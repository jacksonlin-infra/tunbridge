use crate::protocol::{MacosProtocolSession, ProtocolContractError};
use std::time::Duration;
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ServiceTransport};
use tunbridge_service::protocol::{Capability, Command, ErrorCode, ResponseData};

#[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
fn client_session_debug_log(message: &str) {
    use std::{fs::OpenOptions, io::Write};
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tunbridge-client-m6f.log")
    {
        let _ = writeln!(file, "{message}");
    }
}

#[cfg(target_os = "macos")]
use crate::{
    client_policy::load_bundle_helper_requirement, native::NativeIdentityError,
    xpc_client::NativeXpcClientBackend, MacosXpcTransport,
};

const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub trait RequestIdSource {
    fn next_request_id(&mut self) -> Result<String, AdapterError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRequestIdSource;

impl RequestIdSource for SystemRequestIdSource {
    fn next_request_id(&mut self) -> Result<String, AdapterError> {
        let mut bytes = [0_u8; 16];
        #[cfg(target_os = "macos")]
        if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
            return Err(unavailable());
        }
        #[cfg(not(target_os = "macos"))]
        return Err(unavailable());
        #[cfg(target_os = "macos")]
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

pub struct MacosServiceClient<T, I = SystemRequestIdSource> {
    transport: T,
    protocol: MacosProtocolSession,
    request_ids: I,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacosClientError {
    Adapter(AdapterError),
    Service { code: ErrorCode, retryable: bool },
}

impl<T> MacosServiceClient<T, SystemRequestIdSource>
where
    T: ServiceTransport,
{
    pub fn handshake(transport: T) -> Result<Self, AdapterError> {
        Self::handshake_with_ids(transport, SystemRequestIdSource)
    }
}

#[cfg(target_os = "macos")]
impl MacosServiceClient<MacosXpcTransport<NativeXpcClientBackend>, SystemRequestIdSource> {
    pub fn connect_system() -> Result<Self, AdapterError> {
        let requirement = load_bundle_helper_requirement().map_err(map_native_identity)?;
        let transport = MacosXpcTransport::connect(&requirement)?;
        Self::handshake(transport)
    }
}

impl<T, I> MacosServiceClient<T, I>
where
    T: ServiceTransport,
    I: RequestIdSource,
{
    pub fn handshake_with_ids(mut transport: T, request_ids: I) -> Result<Self, AdapterError> {
        let hello = MacosProtocolSession::hello_frame(SERVICE_VERSION).map_err(map_protocol)?;
        let reply = transport.transact(&hello, HANDSHAKE_TIMEOUT)?;
        let protocol = MacosProtocolSession::accept_hello_frame(&reply).map_err(map_protocol)?;
        Ok(Self {
            transport,
            protocol,
            request_ids,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        self.protocol.capabilities()
    }

    pub fn send(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<ResponseData, MacosClientError> {
        #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
        client_session_debug_log(&format!("send-enter command={}", command_label(&command)));
        let request_id = self
            .request_ids
            .next_request_id()
            .map_err(MacosClientError::Adapter)?;
        #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
        client_session_debug_log("send-request-id-ok");
        let pending = self
            .protocol
            .prepare(command, request_id)
            .map_err(|error| {
                #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
                client_session_debug_log(&format!("protocol-prepare-error={error:?}"));
                MacosClientError::Adapter(map_protocol(error))
            })?;
        #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
        client_session_debug_log(&format!("send-prepared bytes={}", pending.frame().len()));
        let reply = self
            .transport
            .transact(pending.frame(), timeout)
            .map_err(MacosClientError::Adapter)?;
        #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
        client_session_debug_log(&format!("send-transport-ok bytes={}", reply.len()));
        let response = self
            .protocol
            .accept_response(&pending, &reply)
            .map_err(|error| {
                #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
                client_session_debug_log(&format!(
                    "protocol-accept-error={error:?} reply-bytes={}",
                    reply.len()
                ));
                MacosClientError::Adapter(map_protocol(error))
            })?;
        #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
        client_session_debug_log(&format!(
            "protocol-result ok={} has-data={} has-error={}",
            response.result.ok,
            response.result.data.is_some(),
            response.result.error.is_some()
        ));
        if response.result.ok {
            response
                .result
                .data
                .ok_or_else(|| MacosClientError::Adapter(invalid_data()))
        } else {
            let error = response
                .result
                .error
                .ok_or_else(|| MacosClientError::Adapter(invalid_data()))?;
            #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
            client_session_debug_log(&format!(
                "service-error code={:?} retryable={}",
                error.code, error.retryable
            ));
            Err(MacosClientError::Service {
                code: error.code,
                retryable: error.retryable,
            })
        }
    }
}

#[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
fn command_label(command: &Command) -> &'static str {
    match command {
        Command::Status => "status",
        Command::Start { .. } => "start",
        Command::Stop => "stop",
        Command::Recover => "recover",
        Command::ProvisionGeneration { .. } => "provision-generation",
        Command::AcquireLease {} => "acquire-lease",
        Command::RenewLease { .. } => "renew-lease",
        Command::ReleaseLease { .. } => "release-lease",
        Command::ObserveTraffic {} => "observe-traffic",
        Command::ListConnections { .. } => "list-connections",
        Command::CloseConnection { .. } => "close-connection",
        Command::CloseAllConnections {} => "close-all-connections",
        Command::ListMihomoLogs { .. } => "list-mihomo-logs",
    }
}

fn map_protocol(error: ProtocolContractError) -> AdapterError {
    match error {
        ProtocolContractError::IdentityRejected | ProtocolContractError::ResponseRejected => {
            AdapterError {
                code: AdapterErrorCode::IdentityRejected,
                safe_message: "The macOS helper protocol identity was rejected.",
                retryable: false,
            }
        }
        ProtocolContractError::CapabilityUnavailable
        | ProtocolContractError::RequestLimitReached => unavailable(),
        ProtocolContractError::InvalidFrame => AdapterError {
            code: AdapterErrorCode::InvalidData,
            safe_message: "The macOS helper protocol data is invalid.",
            retryable: false,
        },
    }
}

fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "The macOS helper session is unavailable.",
        retryable: true,
    }
}

fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "The macOS helper response is invalid.",
        retryable: false,
    }
}

#[cfg(target_os = "macos")]
fn map_native_identity(error: NativeIdentityError) -> AdapterError {
    match error {
        NativeIdentityError::ProcessUnavailable => unavailable(),
        NativeIdentityError::InvalidRequirement
        | NativeIdentityError::RequirementRejected
        | NativeIdentityError::InvalidConnectionFacts => AdapterError {
            code: AdapterErrorCode::IdentityRejected,
            safe_message: "The macOS helper signing policy was rejected.",
            retryable: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tunbridge_service::{
        frame,
        protocol::{
            Hello, HelloOk, HelloOkKind, Request, Response, MAX_FRAME_BYTES, PROTOCOL_VERSION,
        },
        state::Phase,
    };

    struct MockTransport {
        replies: VecDeque<Vec<u8>>,
        requests: Vec<Vec<u8>>,
    }

    impl ServiceTransport for MockTransport {
        fn transact(
            &mut self,
            request_frame: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, AdapterError> {
            self.requests.push(request_frame.to_vec());
            self.replies.pop_front().ok_or_else(unavailable)
        }
    }

    struct FixedIds(VecDeque<String>);

    impl RequestIdSource for FixedIds {
        fn next_request_id(&mut self) -> Result<String, AdapterError> {
            self.0.pop_front().ok_or_else(unavailable)
        }
    }

    fn hello() -> Vec<u8> {
        frame::encode(&HelloOk::with_capabilities(
            "0.2.3",
            "a".repeat(64),
            vec![
                Capability::Status,
                Capability::Start,
                Capability::Stop,
                Capability::Recover,
                Capability::Lease,
            ],
        ))
        .unwrap()
    }

    fn status_reply(request_id: &str, sequence: u64) -> Vec<u8> {
        let request = Request {
            kind: tunbridge_service::protocol::RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: "a".repeat(64),
            seq: sequence,
            request_id: request_id.into(),
            command: Command::Status,
        };
        frame::encode(&Response::success(
            &request,
            ResponseData::Status {
                service_phase: Phase::Stopped,
                caller_is_owner: false,
                engine_running: false,
                service_version: "0.2.3".into(),
                stop_reason: None,
                degraded_reason: None,
            },
        ))
        .unwrap()
    }

    #[test]
    fn handshake_and_status_use_one_session_and_exact_sequence() {
        let transport = MockTransport {
            replies: [hello(), status_reply(&"b".repeat(32), 1)]
                .into_iter()
                .collect(),
            requests: Vec::new(),
        };
        let ids = FixedIds(["b".repeat(32)].into_iter().collect());
        let mut client = MacosServiceClient::handshake_with_ids(transport, ids).unwrap();
        assert!(matches!(
            client
                .send(Command::Status, Duration::from_secs(1))
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                ..
            }
        ));
        let hello_request: Hello = frame::decode(&client.transport.requests[0]).unwrap();
        assert_eq!(hello_request.protocol, PROTOCOL_VERSION);
        let status_request: Request = frame::decode(&client.transport.requests[1]).unwrap();
        assert_eq!(status_request.seq, 1);
        assert_eq!(status_request.request_id, "b".repeat(32));
    }

    #[test]
    fn malformed_handshake_and_unpublished_capability_fail_closed() {
        let malformed = MockTransport {
            replies: [frame::encode(&Hello::new("0.2.3")).unwrap()]
                .into_iter()
                .collect(),
            requests: Vec::new(),
        };
        assert!(
            MacosServiceClient::handshake_with_ids(malformed, FixedIds(VecDeque::new())).is_err()
        );

        let status_only = frame::encode(&HelloOk {
            kind: HelloOkKind::HelloOk,
            protocol: PROTOCOL_VERSION,
            service_version: "0.2.3".into(),
            session_nonce: "a".repeat(64),
            max_frame_bytes: MAX_FRAME_BYTES,
            capabilities: vec![Capability::Status],
        })
        .unwrap();
        let transport = MockTransport {
            replies: [status_only].into_iter().collect(),
            requests: Vec::new(),
        };
        let ids = FixedIds(["b".repeat(32)].into_iter().collect());
        let mut client = MacosServiceClient::handshake_with_ids(transport, ids).unwrap();
        assert_eq!(
            client
                .send(Command::Stop, Duration::from_secs(1))
                .unwrap_err(),
            MacosClientError::Adapter(unavailable())
        );
        assert_eq!(client.transport.requests.len(), 1);
    }

    #[test]
    fn service_error_preserves_only_code_and_retryability() {
        let request = Request {
            kind: tunbridge_service::protocol::RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: "a".repeat(64),
            seq: 1,
            request_id: "b".repeat(32),
            command: Command::Stop,
        };
        let rejected = frame::encode(&Response::error(
            &request,
            ErrorCode::NotOwner,
            "fixture detail must not escape",
            false,
        ))
        .unwrap();
        let transport = MockTransport {
            replies: [hello(), rejected].into_iter().collect(),
            requests: Vec::new(),
        };
        let ids = FixedIds(["b".repeat(32)].into_iter().collect());
        let mut client = MacosServiceClient::handshake_with_ids(transport, ids).unwrap();
        assert_eq!(
            client
                .send(Command::Stop, Duration::from_secs(1))
                .unwrap_err(),
            MacosClientError::Service {
                code: ErrorCode::NotOwner,
                retryable: false
            }
        );
    }
}
