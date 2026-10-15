use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use tunbridge_core::{
    probe,
    profile::{Protocol, Upstream},
    remote::{preflight_pinned_tcp, resolve_endpoint_system},
    upstream::{Endpoint, RemoteProtocolConfig, SecretMaterialV2, StandardProtocol},
};
use zeroize::Zeroize;

pub const DISCOVERY_SCHEMA_VERSION: u16 = 1;
pub const TEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_DISCOVERY_PORTS: usize = 64;
pub const MAX_DISCOVERY_RESULTS: usize = 16;
pub const MAX_PROCESS_HINT_BYTES: usize = 128;
pub const MAX_USERNAME_BYTES: usize = 128;
pub const MAX_PASSWORD_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesktopProxyProtocol {
    Socks5,
    Http,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct SecretText(String);

impl SecretText {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    pub(crate) fn from_owned(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestInput {
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    #[serde(default)]
    pub username: Option<SecretText>,
    #[serde(default)]
    pub password: Option<SecretText>,
}

impl fmt::Debug for TestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestInput")
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopProbeErrorCode {
    InvalidInput,
    Busy,
    ConnectFailed,
    AuthenticationFailed,
    ProtocolMismatch,
    UpstreamTimeout,
    TestTargetUnavailable,
    InvalidResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopProbeError {
    pub code: DesktopProbeErrorCode,
    pub safe_message: &'static str,
}

impl From<DesktopProbeErrorCode> for DesktopProbeError {
    fn from(code: DesktopProbeErrorCode) -> Self {
        let safe_message = match code {
            DesktopProbeErrorCode::InvalidInput => "The local proxy input is invalid.",
            DesktopProbeErrorCode::Busy => "Another local proxy operation is already active.",
            DesktopProbeErrorCode::ConnectFailed => "The local proxy connection failed.",
            DesktopProbeErrorCode::AuthenticationFailed => {
                "The local proxy rejected the supplied credentials."
            }
            DesktopProbeErrorCode::ProtocolMismatch => {
                "The local endpoint did not match the selected proxy protocol."
            }
            DesktopProbeErrorCode::UpstreamTimeout => "The local proxy test timed out.",
            DesktopProbeErrorCode::TestTargetUnavailable => {
                "The fixed connectivity test target was unavailable."
            }
            DesktopProbeErrorCode::InvalidResponse => {
                "The local proxy returned an invalid test response."
            }
        };
        Self { code, safe_message }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    InvalidInput,
    Busy,
    ConnectFailed,
    AuthenticationFailed,
    ProtocolMismatch,
    UpstreamTimeout,
    TestTargetUnavailable,
    InvalidResponse,
}

impl From<ProbeFailure> for DesktopProbeErrorCode {
    fn from(value: ProbeFailure) -> Self {
        match value {
            ProbeFailure::InvalidInput => Self::InvalidInput,
            ProbeFailure::Busy => Self::Busy,
            ProbeFailure::ConnectFailed => Self::ConnectFailed,
            ProbeFailure::AuthenticationFailed => Self::AuthenticationFailed,
            ProbeFailure::ProtocolMismatch => Self::ProtocolMismatch,
            ProbeFailure::UpstreamTimeout => Self::UpstreamTimeout,
            ProbeFailure::TestTargetUnavailable => Self::TestTargetUnavailable,
            ProbeFailure::InvalidResponse => Self::InvalidResponse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResponse {
    pub schema_version: u16,
    pub ok: bool,
    pub http_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub udp_supported: bool,
    pub error_code: Option<DesktopProbeErrorCode>,
}

pub fn successful_test_response(
    http_code: u16,
    latency_ms: u128,
    udp_supported: bool,
) -> TestResponse {
    TestResponse {
        schema_version: TEST_SCHEMA_VERSION,
        ok: true,
        http_code: Some(http_code),
        latency_ms: Some(u64::try_from(latency_ms).unwrap_or(u64::MAX)),
        udp_supported,
        error_code: None,
    }
}

pub fn failed_test_response(failure: ProbeFailure) -> TestResponse {
    TestResponse {
        schema_version: TEST_SCHEMA_VERSION,
        ok: false,
        http_code: None,
        latency_ms: None,
        udp_supported: false,
        error_code: Some(failure.into()),
    }
}

/// Test a saved remote endpoint without allowing the WebView to choose a test
/// target. Plain HTTP/SOCKS5 profiles complete an end-to-end request through
/// the proxy. TLS-wrapped proxy profiles currently prove the validated saved
/// endpoint is reachable before the lifecycle performs its own engine setup.
pub fn test_remote_profile(
    endpoint: &Endpoint,
    protocol_config: &RemoteProtocolConfig,
    secret_material: Option<&SecretMaterialV2>,
) -> Result<TestResponse, DesktopProbeError> {
    endpoint
        .validate()
        .map_err(|_| DesktopProbeError::from(DesktopProbeErrorCode::InvalidInput))?;
    protocol_config
        .validate()
        .map_err(|_| DesktopProbeError::from(DesktopProbeErrorCode::InvalidInput))?;
    if let Some(material) = secret_material {
        material
            .validate()
            .map_err(|_| DesktopProbeError::from(DesktopProbeErrorCode::InvalidInput))?;
    }

    let addresses = resolve_endpoint_system(endpoint)
        .map_err(|_| DesktopProbeError::from(DesktopProbeErrorCode::ConnectFailed))?;
    let started = Instant::now();
    if protocol_config.tls_enabled() {
        let reachable = addresses.into_iter().any(|address| {
            preflight_pinned_tcp(address, endpoint.port, Duration::from_secs(4)).is_ok()
        });
        return Ok(if reachable {
            TestResponse {
                schema_version: TEST_SCHEMA_VERSION,
                ok: true,
                http_code: None,
                latency_ms: Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
                udp_supported: false,
                error_code: None,
            }
        } else {
            failed_test_response(ProbeFailure::ConnectFailed)
        });
    }

    let (username, password) = secret_material
        .map(|material| material.material.basic_auth())
        .map_or((None, None), |(username, password)| {
            (Some(username.to_owned()), Some(password.to_owned()))
        });
    for address in addresses {
        let upstream = Upstream {
            host: address.to_string(),
            port: endpoint.port,
            protocol: match protocol_config.standard_protocol() {
                StandardProtocol::Socks5 => Protocol::Socks5,
                StandardProtocol::Http => Protocol::Http,
            },
            username: username.clone(),
            password: password.clone(),
            udp: protocol_config.udp_enabled(),
        };
        let result = probe::test_upstream(
            &upstream,
            probe::DEFAULT_TEST_HOST,
            probe::DEFAULT_TEST_PORT,
            probe::DEFAULT_TEST_PATH,
            Duration::from_secs(4),
        );
        if result.ok {
            return Ok(match (result.http_code, result.latency_ms) {
                (Some(http_code), Some(latency_ms)) => {
                    successful_test_response(http_code, latency_ms, result.udp_supported)
                }
                _ => failed_test_response(ProbeFailure::InvalidResponse),
            });
        }
    }
    Ok(failed_test_response(ProbeFailure::ConnectFailed))
}

#[derive(Debug)]
pub struct ValidatedCredentials {
    pub username: SecretText,
    pub password: SecretText,
}

#[derive(Debug)]
pub struct ValidatedTestInput {
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    pub credentials: Option<ValidatedCredentials>,
}

pub fn validate_test_input(input: TestInput) -> Result<ValidatedTestInput, DesktopProbeErrorCode> {
    if input.port == 0 {
        return Err(DesktopProbeErrorCode::InvalidInput);
    }

    let credentials = match (input.username, input.password) {
        (None, None) => None,
        (Some(username), Some(password)) if username.is_empty() && password.is_empty() => None,
        (Some(username), Some(password)) => {
            if username.is_empty()
                || password.is_empty()
                || !valid_secret(&username, MAX_USERNAME_BYTES)
                || !valid_secret(&password, MAX_PASSWORD_BYTES)
            {
                return Err(DesktopProbeErrorCode::InvalidInput);
            }
            Some(ValidatedCredentials { username, password })
        }
        _ => return Err(DesktopProbeErrorCode::InvalidInput),
    };

    Ok(ValidatedTestInput {
        port: input.port,
        protocol: input.protocol,
        credentials,
    })
}

fn valid_secret(secret: &SecretText, max_bytes: usize) -> bool {
    !secret.expose().is_empty()
        && secret.expose().len() <= max_bytes
        && !secret.expose().chars().any(char::is_control)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOwner {
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCandidate {
    pub port: u16,
    pub protocol: Option<DesktopProxyProtocol>,
    pub owners: Vec<RawOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopCandidate {
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryWarningCode {
    ListenerEnumerationUnavailable,
    ListenerLimitReached,
    DiscoveryDeadlineReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryResponse {
    pub schema_version: u16,
    pub candidates: Vec<DesktopCandidate>,
    pub warning_codes: Vec<DiscoveryWarningCode>,
}

pub fn project_candidates(
    raw: impl IntoIterator<Item = RawCandidate>,
    warning_codes: Vec<DiscoveryWarningCode>,
) -> DiscoveryResponse {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    for candidate in raw {
        let Some(protocol) = candidate.protocol else {
            continue;
        };
        let Some(process_hint) = unambiguous_process_hint(&candidate.owners) else {
            // A local profile cannot pass the lifecycle ownership gate without
            // one exact listener process. Do not publish a candidate that the
            // service will necessarily reject later.
            continue;
        };
        if candidate.port == 0 || !seen.insert((candidate.port, protocol)) {
            continue;
        }

        candidates.push(DesktopCandidate {
            port: candidate.port,
            protocol,
            process_hint: Some(process_hint),
        });
        if candidates.len() == MAX_DISCOVERY_RESULTS {
            break;
        }
    }

    DiscoveryResponse {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        candidates,
        warning_codes,
    }
}

fn unambiguous_process_hint(owners: &[RawOwner]) -> Option<String> {
    let owner_pids: BTreeSet<u32> = owners.iter().map(|owner| owner.pid).collect();
    if owner_pids.len() != 1 {
        return None;
    }

    let names: BTreeSet<String> = owners
        .iter()
        .filter_map(|owner| sanitize_process_hint(&owner.process_name))
        .collect();
    if names.len() == 1 {
        names.into_iter().next()
    } else {
        None
    }
}

pub fn sanitize_process_hint(value: &str) -> Option<String> {
    let leaf = value.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let mut result = String::new();
    for character in leaf.chars().filter(|character| !character.is_control()) {
        if result.len() + character.len_utf8() > MAX_PROCESS_HINT_BYTES {
            break;
        }
        result.push(character);
    }
    let result = result.trim();
    (!result.is_empty()).then(|| result.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSelection {
    pub ports: Vec<u16>,
    pub limit_reached: bool,
}

pub fn select_discovery_ports(defaults: &[u16], listeners: &[u16]) -> PortSelection {
    let mut seen = BTreeSet::new();
    let mut ports = Vec::new();

    for port in defaults.iter().copied().filter(|port| *port != 0) {
        if seen.insert(port) && ports.len() < MAX_DISCOVERY_PORTS {
            ports.push(port);
        }
    }

    let sorted_listeners: BTreeSet<u16> = listeners
        .iter()
        .copied()
        .filter(|port| *port != 0)
        .collect();
    let total_distinct = seen.union(&sorted_listeners).count();
    for port in sorted_listeners {
        if seen.insert(port) && ports.len() < MAX_DISCOVERY_PORTS {
            ports.push(port);
        }
    }

    PortSelection {
        ports,
        limit_reached: total_distinct > MAX_DISCOVERY_PORTS,
    }
}

#[derive(Debug, Default)]
pub struct OperationSlot {
    active: AtomicBool,
}

impl OperationSlot {
    pub fn try_acquire(&self) -> Result<OperationPermit<'_>, DesktopProbeErrorCode> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| OperationPermit { slot: self })
            .map_err(|_| DesktopProbeErrorCode::Busy)
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn try_acquire_owned(
        self: &Arc<Self>,
    ) -> Result<OwnedOperationPermit, DesktopProbeErrorCode> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| OwnedOperationPermit {
                slot: Arc::clone(self),
            })
            .map_err(|_| DesktopProbeErrorCode::Busy)
    }

    pub fn acquire_owned_until(
        self: &Arc<Self>,
        timeout: Duration,
    ) -> Result<OwnedOperationPermit, DesktopProbeErrorCode> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_acquire_owned() {
                Ok(permit) => return Ok(permit),
                Err(DesktopProbeErrorCode::Busy) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Debug)]
pub struct OperationPermit<'a> {
    slot: &'a OperationSlot,
}

impl Drop for OperationPermit<'_> {
    fn drop(&mut self) {
        self.slot.active.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
pub struct OwnedOperationPermit {
    slot: Arc<OperationSlot>,
}

impl Drop for OwnedOperationPermit {
    fn drop(&mut self) {
        self.slot.active.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_input(json: &str) -> Result<TestInput, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn strict_test_schema_accepts_only_closed_fields_and_protocols() {
        let input =
            parse_input(r#"{"port":7078,"protocol":"socks5","username":"u","password":"p"}"#)
                .unwrap();
        assert_eq!(input.port, 7078);
        assert_eq!(input.protocol, DesktopProxyProtocol::Socks5);

        assert!(parse_input(r#"{"port":7078,"protocol":"ftp"}"#).is_err());
        assert!(parse_input(r#"{"port":7078,"protocol":"http","host":"example.com"}"#).is_err());
    }

    #[test]
    fn validation_rejects_zero_port_and_unpaired_credentials() {
        for json in [
            r#"{"port":0,"protocol":"socks5"}"#,
            r#"{"port":7078,"protocol":"socks5","username":"u"}"#,
            r#"{"port":7078,"protocol":"socks5","password":"p"}"#,
            r#"{"port":7078,"protocol":"socks5","username":"","password":"p"}"#,
        ] {
            assert_eq!(
                validate_test_input(parse_input(json).unwrap()).unwrap_err(),
                DesktopProbeErrorCode::InvalidInput
            );
        }
    }

    #[test]
    fn validation_normalizes_empty_pair_and_accepts_bounded_credentials() {
        let empty = validate_test_input(
            parse_input(r#"{"port":7078,"protocol":"http","username":"","password":""}"#).unwrap(),
        )
        .unwrap();
        assert!(empty.credentials.is_none());

        let valid = validate_test_input(
            parse_input(
                r#"{"port":7078,"protocol":"socks5","username":"user","password":"secret"}"#,
            )
            .unwrap(),
        )
        .unwrap();
        let credentials = valid.credentials.unwrap();
        assert_eq!(credentials.username.expose(), "user");
        assert_eq!(credentials.password.expose(), "secret");
    }

    #[test]
    fn validation_rejects_oversize_and_control_credentials() {
        let long_username = "u".repeat(MAX_USERNAME_BYTES + 1);
        let long_password = "p".repeat(MAX_PASSWORD_BYTES + 1);
        for (username, password) in [
            (long_username.as_str(), "p"),
            ("u", long_password.as_str()),
            ("user\nname", "p"),
            ("u", "pass\0word"),
        ] {
            let json = serde_json::json!({
                "port": 7078,
                "protocol": "socks5",
                "username": username,
                "password": password,
            });
            let error = validate_test_input(serde_json::from_value(json).unwrap()).unwrap_err();
            assert_eq!(error, DesktopProbeErrorCode::InvalidInput);
        }
    }

    #[test]
    fn secret_and_input_debug_are_redacted() {
        let input = parse_input(
            r#"{"port":7078,"protocol":"socks5","username":"private-user","password":"private-password"}"#,
        )
        .unwrap();
        let debug = format!("{input:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
    }

    #[test]
    fn process_hint_uses_only_sanitized_leaf() {
        assert_eq!(
            sanitize_process_hint("C:\\private\\proxy\u{0}.exe").as_deref(),
            Some("proxy.exe")
        );
        let long = format!("{}é", "a".repeat(MAX_PROCESS_HINT_BYTES - 1));
        let hint = sanitize_process_hint(&long).unwrap();
        assert_eq!(hint.len(), MAX_PROCESS_HINT_BYTES - 1);
        assert!(hint.is_char_boundary(hint.len()));
    }

    #[test]
    fn projection_discards_candidates_without_one_exact_owner() {
        let response = project_candidates(
            [RawCandidate {
                port: 7078,
                protocol: Some(DesktopProxyProtocol::Socks5),
                owners: vec![
                    RawOwner {
                        pid: 10,
                        process_name: "one.exe".into(),
                        process_path: Some("C:\\private\\one.exe".into()),
                    },
                    RawOwner {
                        pid: 11,
                        process_name: "two.exe".into(),
                        process_path: Some("D:\\secret\\two.exe".into()),
                    },
                ],
            }],
            vec![],
        );

        assert!(response.candidates.is_empty());
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("pid"));
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn projection_emits_one_non_authoritative_hint_for_one_owner() {
        let response = project_candidates(
            [RawCandidate {
                port: 7078,
                protocol: Some(DesktopProxyProtocol::Socks5),
                owners: vec![RawOwner {
                    pid: 10,
                    process_name: "C:\\apps\\proxy.exe".into(),
                    process_path: Some("C:\\apps\\proxy.exe".into()),
                }],
            }],
            vec![],
        );
        assert_eq!(
            response.candidates[0].process_hint.as_deref(),
            Some("proxy.exe")
        );
    }

    #[test]
    fn projection_filters_invalid_duplicate_and_unfingerprinted_rows() {
        let rows = [
            RawCandidate {
                port: 0,
                protocol: Some(DesktopProxyProtocol::Http),
                owners: vec![],
            },
            RawCandidate {
                port: 7078,
                protocol: None,
                owners: vec![],
            },
            RawCandidate {
                port: 7078,
                protocol: Some(DesktopProxyProtocol::Socks5),
                owners: vec![RawOwner {
                    pid: 10,
                    process_name: "proxy.exe".into(),
                    process_path: None,
                }],
            },
            RawCandidate {
                port: 7078,
                protocol: Some(DesktopProxyProtocol::Socks5),
                owners: vec![RawOwner {
                    pid: 10,
                    process_name: "proxy.exe".into(),
                    process_path: None,
                }],
            },
        ];
        let response = project_candidates(rows, vec![]);
        assert_eq!(response.candidates.len(), 1);
    }

    #[test]
    fn projection_caps_results() {
        let rows = (1..=MAX_DISCOVERY_RESULTS + 2).map(|index| RawCandidate {
            port: u16::try_from(index).unwrap(),
            protocol: Some(DesktopProxyProtocol::Http),
            owners: vec![RawOwner {
                pid: u32::try_from(index).unwrap(),
                process_name: format!("proxy-{index}"),
                process_path: None,
            }],
        });
        assert_eq!(
            project_candidates(rows, vec![]).candidates.len(),
            MAX_DISCOVERY_RESULTS
        );
    }

    #[test]
    fn port_selection_prioritizes_defaults_and_caps_distinct_ports() {
        let listeners: Vec<u16> = (1..=100).collect();
        let selection = select_discovery_ports(&[7078, 1080, 7078, 0], &listeners);
        assert_eq!(&selection.ports[..2], &[7078, 1080]);
        assert_eq!(selection.ports.len(), MAX_DISCOVERY_PORTS);
        assert!(selection.limit_reached);
    }

    #[test]
    fn port_selection_does_not_report_limit_for_duplicates() {
        let selection = select_discovery_ports(&[7078], &[7078, 7078]);
        assert_eq!(selection.ports, vec![7078]);
        assert!(!selection.limit_reached);
    }

    #[test]
    fn typed_failures_map_without_text_matching() {
        let pairs = [
            (
                ProbeFailure::InvalidInput,
                DesktopProbeErrorCode::InvalidInput,
            ),
            (ProbeFailure::Busy, DesktopProbeErrorCode::Busy),
            (
                ProbeFailure::ConnectFailed,
                DesktopProbeErrorCode::ConnectFailed,
            ),
            (
                ProbeFailure::AuthenticationFailed,
                DesktopProbeErrorCode::AuthenticationFailed,
            ),
            (
                ProbeFailure::ProtocolMismatch,
                DesktopProbeErrorCode::ProtocolMismatch,
            ),
            (
                ProbeFailure::UpstreamTimeout,
                DesktopProbeErrorCode::UpstreamTimeout,
            ),
            (
                ProbeFailure::TestTargetUnavailable,
                DesktopProbeErrorCode::TestTargetUnavailable,
            ),
            (
                ProbeFailure::InvalidResponse,
                DesktopProbeErrorCode::InvalidResponse,
            ),
        ];
        for (source, expected) in pairs {
            assert_eq!(DesktopProbeErrorCode::from(source), expected);
        }
    }

    #[test]
    fn test_response_is_fixed_and_clamps_latency() {
        let success = successful_test_response(204, u128::MAX, true);
        assert_eq!(success.schema_version, TEST_SCHEMA_VERSION);
        assert_eq!(success.latency_ms, Some(u64::MAX));
        assert_eq!(success.error_code, None);

        let failure = failed_test_response(ProbeFailure::AuthenticationFailed);
        let json = serde_json::to_value(failure).unwrap();
        assert_eq!(json["schemaVersion"], TEST_SCHEMA_VERSION);
        assert_eq!(json["ok"], false);
        assert_eq!(json["httpCode"], serde_json::Value::Null);
        assert_eq!(json["latencyMs"], serde_json::Value::Null);
        assert_eq!(json["udpSupported"], false);
        assert_eq!(json["errorCode"], "authentication_failed");
    }

    #[test]
    fn operation_slot_is_non_queuing_and_releases_on_drop() {
        let slot = OperationSlot::default();
        let permit = slot.try_acquire().unwrap();
        assert!(slot.is_active());
        assert_eq!(slot.try_acquire().unwrap_err(), DesktopProbeErrorCode::Busy);
        drop(permit);
        assert!(!slot.is_active());
        assert!(slot.try_acquire().is_ok());
    }

    #[test]
    fn owned_operation_permit_blocks_before_worker_dispatch() {
        let slot = Arc::new(OperationSlot::default());
        let permit = slot.try_acquire_owned().unwrap();
        assert_eq!(
            slot.try_acquire_owned().unwrap_err(),
            DesktopProbeErrorCode::Busy
        );
        drop(permit);
        assert!(slot.try_acquire_owned().is_ok());
    }

    #[test]
    fn bounded_acquire_waits_for_a_short_startup_operation() {
        let slot = Arc::new(OperationSlot::default());
        let permit = slot.try_acquire_owned().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            drop(permit);
        });
        let acquired = slot.acquire_owned_until(Duration::from_secs(1)).unwrap();
        release.join().unwrap();
        drop(acquired);
        assert!(!slot.is_active());
    }

    #[test]
    fn bounded_acquire_still_rejects_a_stuck_operation() {
        let slot = Arc::new(OperationSlot::default());
        let _permit = slot.try_acquire_owned().unwrap();
        assert_eq!(
            slot.acquire_owned_until(Duration::from_millis(30))
                .unwrap_err(),
            DesktopProbeErrorCode::Busy
        );
    }

    #[test]
    fn schema_and_warning_codes_are_fixed() {
        let response = project_candidates(
            [],
            vec![
                DiscoveryWarningCode::ListenerEnumerationUnavailable,
                DiscoveryWarningCode::ListenerLimitReached,
                DiscoveryWarningCode::DiscoveryDeadlineReached,
            ],
        );
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["schemaVersion"], DISCOVERY_SCHEMA_VERSION);
        assert_eq!(
            json["warningCodes"],
            serde_json::json!([
                "listener_enumeration_unavailable",
                "listener_limit_reached",
                "discovery_deadline_reached"
            ])
        );
    }

    #[test]
    fn command_errors_have_only_fixed_safe_messages() {
        let error = DesktopProbeError::from(DesktopProbeErrorCode::ConnectFailed);
        assert_eq!(error.safe_message, "The local proxy connection failed.");
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "code": "connect_failed",
                "safeMessage": "The local proxy connection failed."
            })
        );
    }
}
