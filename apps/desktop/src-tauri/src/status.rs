use serde::Serialize;
use tunbridge_service::{
    protocol::{Capability, ResponseData},
    state::{Phase, WatchdogReason},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatus {
    schema_version: u16,
    service_phase: Phase,
    engine_running: bool,
    caller_is_owner: bool,
    service_version: String,
    read_only: bool,
    capabilities: Vec<Capability>,
    stop_reason: Option<WatchdogReason>,
    degraded_reason: Option<WatchdogReason>,
}

impl DesktopStatus {
    pub(crate) fn service_phase(&self) -> Phase {
        self.service_phase
    }

    pub(crate) fn caller_is_owner(&self) -> bool {
        self.caller_is_owner
    }

    pub(crate) fn stop_reason(&self) -> Option<WatchdogReason> {
        self.stop_reason
    }

    pub(crate) fn degraded_reason(&self) -> Option<WatchdogReason> {
        self.degraded_reason
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        service_phase: Phase,
        caller_is_owner: bool,
        stop_reason: Option<WatchdogReason>,
        degraded_reason: Option<WatchdogReason>,
    ) -> Self {
        Self {
            schema_version: 3,
            service_phase,
            engine_running: service_phase == Phase::Running,
            caller_is_owner,
            service_version: "test".into(),
            read_only: false,
            capabilities: Vec::new(),
            stop_reason,
            degraded_reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DesktopErrorCode {
    #[serde(rename = "service_unavailable")]
    Unavailable,
    #[serde(rename = "service_identity_failed")]
    IdentityFailed,
    #[serde(rename = "service_protocol_error")]
    ProtocolError,
    #[allow(dead_code)]
    #[serde(rename = "service_rejected")]
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopError {
    code: DesktopErrorCode,
    safe_message: &'static str,
    retryable: bool,
}

impl DesktopError {
    fn unavailable() -> Self {
        Self {
            code: DesktopErrorCode::Unavailable,
            safe_message: "The TunBridge service is unavailable.",
            retryable: true,
        }
    }

    fn identity() -> Self {
        Self {
            code: DesktopErrorCode::IdentityFailed,
            safe_message: "The TunBridge service identity could not be verified.",
            retryable: false,
        }
    }

    fn protocol() -> Self {
        Self {
            code: DesktopErrorCode::ProtocolError,
            safe_message: "The TunBridge service returned an invalid response.",
            retryable: false,
        }
    }

    #[cfg(any(windows, target_os = "macos", test))]
    fn rejected(retryable: bool) -> Self {
        Self {
            code: DesktopErrorCode::Rejected,
            safe_message: "The TunBridge service rejected the status request.",
            retryable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientFailureClass {
    Unavailable,
    Identity,
    Protocol,
    #[cfg(any(windows, target_os = "macos", test))]
    #[allow(dead_code)]
    Rejected {
        retryable: bool,
    },
}

fn map_failure(class: ClientFailureClass) -> DesktopError {
    match class {
        ClientFailureClass::Unavailable => DesktopError::unavailable(),
        ClientFailureClass::Identity => DesktopError::identity(),
        ClientFailureClass::Protocol => DesktopError::protocol(),
        #[cfg(any(windows, target_os = "macos", test))]
        ClientFailureClass::Rejected { retryable } => DesktopError::rejected(retryable),
    }
}

fn map_status(
    response: ResponseData,
    capabilities: Vec<Capability>,
) -> Result<DesktopStatus, DesktopError> {
    match response {
        ResponseData::Status {
            service_phase,
            caller_is_owner,
            engine_running,
            service_version,
            stop_reason,
            degraded_reason,
        } => Ok(DesktopStatus {
            schema_version: 3,
            service_phase,
            engine_running,
            caller_is_owner,
            service_version,
            read_only: ![
                Capability::Start,
                Capability::Stop,
                Capability::Recover,
                Capability::Lease,
            ]
            .iter()
            .all(|capability| capabilities.contains(capability)),
            capabilities,
            stop_reason,
            degraded_reason,
        }),
        #[allow(unreachable_patterns)]
        _ => Err(DesktopError::protocol()),
    }
}

#[cfg(windows)]
fn map_client_error(error: tunbridge_service::windows::ClientError) -> DesktopError {
    use tunbridge_service::windows::ClientError;

    let class = match error {
        ClientError::ServerIdentity(_) => ClientFailureClass::Identity,
        ClientError::Protocol(_)
        | ClientError::ProtocolMismatch(_)
        | ClientError::MissingStatusCapability
        | ClientError::MissingCapability(_)
        | ClientError::ResponseMismatch => ClientFailureClass::Protocol,
        ClientError::Service { retryable, .. } => ClientFailureClass::Rejected { retryable },
        ClientError::Windows(_) | ClientError::Pipe(_) => ClientFailureClass::Unavailable,
    };
    map_failure(class)
}

#[cfg(windows)]
pub fn get_status() -> Result<DesktopStatus, DesktopError> {
    let mut client =
        tunbridge_service::windows::ServiceClient::connect().map_err(map_client_error)?;
    let capabilities = client.capabilities().to_vec();
    map_status(client.status().map_err(map_client_error)?, capabilities)
}

#[cfg(target_os = "macos")]
fn map_macos_adapter_error(
    error: tunbridge_desktop_contract::adapter::AdapterError,
) -> DesktopError {
    use tunbridge_desktop_contract::adapter::AdapterErrorCode;

    let class = match error.code {
        AdapterErrorCode::IdentityRejected | AdapterErrorCode::PermissionDenied => {
            ClientFailureClass::Identity
        }
        AdapterErrorCode::InvalidData => ClientFailureClass::Protocol,
        AdapterErrorCode::NotReady | AdapterErrorCode::Unavailable => {
            ClientFailureClass::Unavailable
        }
    };
    map_failure(class)
}

#[cfg(target_os = "macos")]
fn map_macos_client_error(
    error: tunbridge_service_macos::client_session::MacosClientError,
) -> DesktopError {
    use tunbridge_service_macos::client_session::MacosClientError;

    match error {
        MacosClientError::Adapter(error) => map_macos_adapter_error(error),
        MacosClientError::Service { retryable, .. } => {
            map_failure(ClientFailureClass::Rejected { retryable })
        }
    }
}

#[cfg(target_os = "macos")]
pub fn get_status() -> Result<DesktopStatus, DesktopError> {
    use std::time::Duration;
    use tunbridge_service::protocol::Command;
    use tunbridge_service_macos::client_session::MacosServiceClient;

    let mut client = MacosServiceClient::connect_system().map_err(map_macos_adapter_error)?;
    let capabilities = client.capabilities().to_vec();
    let response = client
        .send(Command::Status, Duration::from_secs(5))
        .map_err(map_macos_client_error)?;
    map_status(response, capabilities)
}

#[cfg(target_os = "linux")]
fn map_linux_client_error(
    error: tunbridge_desktop_contract::adapter::AdapterError,
) -> DesktopError {
    use tunbridge_desktop_contract::adapter::AdapterErrorCode;

    let class = match error.code {
        AdapterErrorCode::IdentityRejected | AdapterErrorCode::PermissionDenied => {
            ClientFailureClass::Identity
        }
        AdapterErrorCode::InvalidData => ClientFailureClass::Protocol,
        AdapterErrorCode::NotReady | AdapterErrorCode::Unavailable => {
            ClientFailureClass::Unavailable
        }
    };
    map_failure(class)
}

#[cfg(target_os = "linux")]
pub fn get_status() -> Result<DesktopStatus, DesktopError> {
    let mut client = tunbridge_service_linux::LinuxStatusClient::connect_system()
        .map_err(map_linux_client_error)?;
    let capabilities = client.capabilities().to_vec();
    let response = client.status().map_err(map_linux_client_error)?;
    map_status(response, capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_phase_to_fixed_read_only_schema() {
        for phase in [
            Phase::Stopped,
            Phase::Starting,
            Phase::Running,
            Phase::Stopping,
            Phase::Recovering,
            Phase::Faulted,
        ] {
            let mapped = map_status(
                ResponseData::Status {
                    service_phase: phase,
                    caller_is_owner: true,
                    engine_running: phase == Phase::Running,
                    service_version: "0.1.0".into(),
                    stop_reason: None,
                    degraded_reason: None,
                },
                vec![
                    Capability::Status,
                    Capability::Start,
                    Capability::Stop,
                    Capability::Recover,
                    Capability::Lease,
                ],
            )
            .unwrap();
            assert_eq!(mapped.schema_version, 3);
            assert_eq!(mapped.service_phase, phase);
            assert!(!mapped.read_only);
        }
    }

    #[test]
    fn serialized_status_has_only_the_frozen_camel_case_fields() {
        let mapped = map_status(
            ResponseData::Status {
                service_phase: Phase::Stopped,
                caller_is_owner: false,
                engine_running: false,
                service_version: "0.1.0".into(),
                stop_reason: None,
                degraded_reason: None,
            },
            vec![Capability::Status],
        )
        .unwrap();
        let value = serde_json::to_value(mapped).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "callerIsOwner",
                "capabilities",
                "degradedReason",
                "engineRunning",
                "readOnly",
                "schemaVersion",
                "servicePhase",
                "serviceVersion",
                "stopReason",
            ]
        );
        assert!(value["stopReason"].is_null());
        assert!(value["degradedReason"].is_null());
    }

    #[test]
    fn automatic_stop_and_degraded_reasons_reach_the_webview() {
        let stopped = serde_json::to_value(
            map_status(
                ResponseData::Status {
                    service_phase: Phase::Stopped,
                    caller_is_owner: false,
                    engine_running: false,
                    service_version: "0.3.18".into(),
                    stop_reason: Some(WatchdogReason::LeaseExpired),
                    degraded_reason: None,
                },
                vec![Capability::Status],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(stopped["stopReason"], "lease_expired");

        let degraded = serde_json::to_value(
            map_status(
                ResponseData::Status {
                    service_phase: Phase::Running,
                    caller_is_owner: true,
                    engine_running: true,
                    service_version: "0.3.18".into(),
                    stop_reason: None,
                    degraded_reason: Some(WatchdogReason::UpstreamUnavailable),
                },
                vec![Capability::Status],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(degraded["degradedReason"], "upstream_unavailable");
    }

    #[test]
    fn desktop_errors_are_fixed_and_do_not_accept_details() {
        let cases = [
            (ClientFailureClass::Unavailable, true),
            (ClientFailureClass::Identity, false),
            (ClientFailureClass::Protocol, false),
            (ClientFailureClass::Rejected { retryable: false }, false),
            (ClientFailureClass::Rejected { retryable: true }, true),
        ];
        for (class, retryable) in cases {
            let error = map_failure(class);
            assert_eq!(error.retryable, retryable);
            let encoded = serde_json::to_string(&error).unwrap();
            assert!(!encoded.contains("Program Files"));
            assert!(!encoded.contains("pipe"));
            assert!(!encoded.contains("PID"));
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires the fixed product service to be absent"]
    fn real_status_without_service_is_safely_unavailable() {
        let error = get_status().unwrap_err();
        assert_eq!(error.code, DesktopErrorCode::Unavailable);
        assert_eq!(error.safe_message, "The TunBridge service is unavailable.");
        assert!(error.retryable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the fixed Linux system service"]
    fn real_linux_desktop_status_publishes_full_control() {
        let status = get_status().unwrap();
        assert_eq!(status.schema_version, 2);
        assert_eq!(status.service_phase, Phase::Stopped);
        assert!(!status.engine_running);
        assert!(!status.caller_is_owner);
        assert_eq!(status.service_version, env!("CARGO_PKG_VERSION"));
        assert!(!status.read_only);
        for capability in [
            Capability::Status,
            Capability::Start,
            Capability::Stop,
            Capability::Recover,
            Capability::Lease,
            Capability::ObserveLocalTraffic,
        ] {
            assert!(status.capabilities.contains(&capability));
        }
    }
}
