use std::{fmt, net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(feature = "production-mihomo-logs-v4")]
pub const PROTOCOL_VERSION: u16 = 4;
#[cfg(all(
    feature = "remote-upstream-v3",
    not(feature = "production-mihomo-logs-v4")
))]
pub const PROTOCOL_VERSION: u16 = 3;
#[cfg(all(
    not(feature = "remote-upstream-v3"),
    not(any(feature = "production-app-lease", feature = "acceptance-m2b5"))
))]
pub const PROTOCOL_VERSION: u16 = 1;
#[cfg(all(
    not(feature = "remote-upstream-v3"),
    any(feature = "production-app-lease", feature = "acceptance-m2b5")
))]
pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_REQUESTS_PER_CONNECTION: u64 = 32;
pub const MAX_RULE_ITEMS: usize = 128;
#[cfg(feature = "macos-development-bootstrap")]
pub const MAX_BOOTSTRAP_POLICY_BYTES: usize = 4096;
#[cfg(feature = "production-local-observability")]
pub const MAX_CONNECTION_PAGE_SIZE: u16 = 25;
#[cfg(feature = "production-local-observability")]
pub const MAX_CONNECTION_PAGE_OFFSET: u32 = 10_000;
#[cfg(feature = "production-mihomo-logs-v4")]
pub const MAX_MIHOMO_LOG_PAGE_SIZE: u16 = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub kind: HelloKind,
    pub protocol: u16,
    pub client_version: String,
}

impl Hello {
    pub fn new(client_version: impl Into<String>) -> Self {
        Self {
            kind: HelloKind::Hello,
            protocol: PROTOCOL_VERSION,
            client_version: client_version.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedProtocol(self.protocol));
        }
        validate_printable("client_version", &self.client_version, 64, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloKind {
    Hello,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloOk {
    pub kind: HelloOkKind,
    pub protocol: u16,
    pub service_version: String,
    pub session_nonce: String,
    pub max_frame_bytes: usize,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelloOkKind {
    HelloOk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Status,
    Start,
    Stop,
    Recover,
    #[cfg(feature = "macos-development-bootstrap")]
    Provision,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    Lease,
    #[cfg(feature = "production-local-observability")]
    ObserveLocalTraffic,
    #[cfg(feature = "production-local-observability")]
    CloseOwnedConnections,
    #[cfg(feature = "remote-upstream-v3")]
    RemoteUpstream,
    #[cfg(feature = "production-mihomo-logs-v4")]
    ObserveMihomoLogs,
}

impl HelloOk {
    pub fn new(service_version: impl Into<String>, session_nonce: String) -> Self {
        Self::with_capabilities(service_version, session_nonce, vec![Capability::Status])
    }

    pub fn with_capabilities(
        service_version: impl Into<String>,
        session_nonce: String,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            kind: HelloOkKind::HelloOk,
            protocol: PROTOCOL_VERSION,
            service_version: service_version.into(),
            session_nonce,
            max_frame_bytes: MAX_FRAME_BYTES,
            capabilities,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub kind: RequestKind,
    pub protocol: u16,
    pub session_nonce: String,
    pub seq: u64,
    pub request_id: String,
    pub command: Command,
}

impl Request {
    pub fn validate_envelope(&self) -> Result<(), ProtocolError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedProtocol(self.protocol));
        }
        validate_hex("session_nonce", &self.session_nonce, 64)?;
        validate_hex("request_id", &self.request_id, 32)?;
        self.command.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Request,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status,
    Start {
        profile: ActiveStartProfile,
    },
    Stop,
    Recover,
    #[cfg(feature = "macos-development-bootstrap")]
    ProvisionGeneration {
        transaction_id: String,
        caller_cdhash: String,
        policy_json: Vec<u8>,
        engine_manifest_sha256: String,
        engine_sha256: String,
        engine_size: u64,
        target_triple: String,
    },
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    AcquireLease {},
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    RenewLease {
        lease_id: String,
        lease_nonce: String,
        lease_seq: u64,
    },
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    ReleaseLease {
        lease_id: String,
        lease_nonce: String,
        lease_seq: u64,
    },
    #[cfg(feature = "production-local-observability")]
    ObserveTraffic {},
    #[cfg(feature = "production-local-observability")]
    ListConnections {
        state: ConnectionState,
        offset: u32,
        limit: u16,
    },
    #[cfg(feature = "production-local-observability")]
    CloseConnection {
        connection_id: String,
    },
    #[cfg(feature = "production-local-observability")]
    CloseAllConnections {},
    #[cfg(feature = "production-mihomo-logs-v4")]
    ListMihomoLogs {
        after_sequence: u64,
        limit: u16,
    },
}

#[cfg(feature = "remote-upstream-v3")]
pub type ActiveStartProfile = StartProfileV3;
#[cfg(not(feature = "remote-upstream-v3"))]
pub type ActiveStartProfile = StartProfile;

impl Command {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Start { profile } => profile.validate(),
            Self::Status | Self::Stop | Self::Recover => Ok(()),
            #[cfg(feature = "macos-development-bootstrap")]
            Self::ProvisionGeneration {
                transaction_id,
                caller_cdhash,
                policy_json,
                engine_manifest_sha256,
                engine_sha256,
                engine_size,
                target_triple,
            } => {
                validate_lower_hex("transaction_id", transaction_id, 32)?;
                validate_lower_hex("caller_cdhash", caller_cdhash, 40)?;
                if policy_json.is_empty() || policy_json.len() > MAX_BOOTSTRAP_POLICY_BYTES {
                    return Err(ProtocolError::InvalidRequest(
                        "policy_json exceeds the bounded bootstrap limit".into(),
                    ));
                }
                validate_lower_hex("engine_manifest_sha256", engine_manifest_sha256, 64)?;
                validate_lower_hex("engine_sha256", engine_sha256, 64)?;
                if *engine_size == 0 || *engine_size > 128 * 1024 * 1024 {
                    return Err(ProtocolError::InvalidRequest(
                        "engine_size is outside the bounded bootstrap limit".into(),
                    ));
                }
                if !matches!(
                    target_triple.as_str(),
                    "aarch64-apple-darwin" | "x86_64-apple-darwin"
                ) {
                    return Err(ProtocolError::InvalidRequest(
                        "target_triple is not a supported Monterey target".into(),
                    ));
                }
                Ok(())
            }
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            Self::AcquireLease {} => Ok(()),
            #[cfg(feature = "production-local-observability")]
            Self::ObserveTraffic {} => Ok(()),
            #[cfg(feature = "production-local-observability")]
            Self::ListConnections { offset, limit, .. } => {
                if *limit == 0 || *limit > MAX_CONNECTION_PAGE_SIZE {
                    return Err(ProtocolError::InvalidRequest(format!(
                        "connection page limit must be between 1 and {MAX_CONNECTION_PAGE_SIZE}"
                    )));
                }
                if *offset > MAX_CONNECTION_PAGE_OFFSET {
                    return Err(ProtocolError::InvalidRequest(format!(
                        "connection page offset exceeds {MAX_CONNECTION_PAGE_OFFSET}"
                    )));
                }
                Ok(())
            }
            #[cfg(feature = "production-local-observability")]
            Self::CloseConnection { connection_id } => {
                if connection_id.is_empty()
                    || connection_id.len() > 128
                    || !connection_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(ProtocolError::InvalidRequest(
                        "connection_id must be a bounded opaque identifier".into(),
                    ));
                }
                Ok(())
            }
            #[cfg(feature = "production-local-observability")]
            Self::CloseAllConnections {} => Ok(()),
            #[cfg(feature = "production-mihomo-logs-v4")]
            Self::ListMihomoLogs { limit, .. } => {
                if *limit == 0 || *limit > MAX_MIHOMO_LOG_PAGE_SIZE {
                    return Err(ProtocolError::InvalidRequest(format!(
                        "mihomo log page limit must be between 1 and {MAX_MIHOMO_LOG_PAGE_SIZE}"
                    )));
                }
                Ok(())
            }
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            Self::RenewLease {
                lease_id,
                lease_nonce,
                lease_seq,
            }
            | Self::ReleaseLease {
                lease_id,
                lease_nonce,
                lease_seq,
            } => {
                validate_lower_hex("lease_id", lease_id, 64)?;
                validate_lower_hex("lease_nonce", lease_nonce, 64)?;
                if *lease_seq == 0 {
                    return Err(ProtocolError::InvalidRequest(
                        "lease_seq must be non-zero".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        match self {
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            Self::RenewLease {
                lease_id,
                lease_nonce,
                ..
            }
            | Self::ReleaseLease {
                lease_id,
                lease_nonce,
                ..
            } => {
                lease_id.zeroize();
                lease_nonce.zeroize();
            }
            Self::Status | Self::Start { .. } | Self::Stop | Self::Recover => {}
            #[cfg(feature = "macos-development-bootstrap")]
            Self::ProvisionGeneration { policy_json, .. } => {
                // Policy material is not secret, but clear the owned vector
                // with the same bounded lifetime as other request payloads.
                policy_json.fill(0);
            }
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            Self::AcquireLease {} => {}
            #[cfg(feature = "production-local-observability")]
            Self::ObserveTraffic {}
            | Self::ListConnections { .. }
            | Self::CloseConnection { .. }
            | Self::CloseAllConnections {} => {}
            #[cfg(feature = "production-mihomo-logs-v4")]
            Self::ListMihomoLogs { .. } => {}
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartProfile {
    pub upstream_host: String,
    pub upstream_port: u16,
    pub protocol: UpstreamProtocol,
    pub username: Option<String>,
    pub password: Option<String>,
    pub upstream_process_id: u32,
    #[serde(default)]
    pub bypass_domains: Vec<String>,
    #[serde(default)]
    pub bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub bypass_process_names: Vec<String>,
}

impl fmt::Debug for StartProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartProfile")
            .field("upstream_host", &self.upstream_host)
            .field("upstream_port", &self.upstream_port)
            .field("protocol", &self.protocol)
            .field("username", &self.username.as_ref().map(|_| "[REDACTED]"))
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("upstream_process_id", &self.upstream_process_id)
            .field("bypass_domains", &self.bypass_domains)
            .field("bypass_cidrs", &self.bypass_cidrs)
            .field("bypass_process_names", &self.bypass_process_names)
            .finish()
    }
}

impl Drop for StartProfile {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl StartProfile {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.upstream_host.as_str(),
            "127.0.0.1" | "::1" | "localhost"
        ) {
            return invalid_profile("upstream_host must be loopback");
        }
        if self.upstream_port == 0 {
            return invalid_profile("upstream_port must be non-zero");
        }
        if self.upstream_process_id == 0 {
            return invalid_profile("upstream_process_id must be non-zero");
        }

        validate_optional_credential("username", &self.username)?;
        validate_optional_credential("password", &self.password)?;
        validate_list("bypass_domains", &self.bypass_domains, validate_domain)?;
        validate_list("bypass_cidrs", &self.bypass_cidrs, validate_cidr)?;
        validate_list(
            "bypass_process_names",
            &self.bypass_process_names,
            validate_process_name,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Socks5,
    Http,
}

#[cfg(feature = "remote-upstream-v3")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartProfileV3 {
    pub upstream: StartUpstreamV3,
    #[serde(default)]
    pub traffic_bypass_domains: Vec<String>,
    #[serde(default)]
    pub traffic_bypass_cidrs: Vec<String>,
    #[serde(default)]
    pub traffic_bypass_process_names: Vec<String>,
}

#[cfg(feature = "remote-upstream-v3")]
impl StartProfileV3 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.upstream.validate()?;
        validate_list(
            "traffic_bypass_domains",
            &self.traffic_bypass_domains,
            validate_domain,
        )?;
        validate_list(
            "traffic_bypass_cidrs",
            &self.traffic_bypass_cidrs,
            validate_cidr,
        )?;
        validate_list(
            "traffic_bypass_process_names",
            &self.traffic_bypass_process_names,
            validate_process_name,
        )
    }

    /// Preserve the established local-listener ownership path while protocol
    /// v3 introduces an explicit remote variant. Remote input can never be
    /// downgraded into the legacy loopback shape.
    pub fn legacy_local_profile(&self) -> Option<StartProfile> {
        let StartUpstreamV3::LocalListener {
            port,
            protocol,
            credentials,
            expected_process_id,
        } = &self.upstream
        else {
            return None;
        };
        let (username, password) = credentials
            .as_ref()
            .map(|material| material.material.basic_auth())
            .map_or((None, None), |(username, password)| {
                (Some(username.to_owned()), Some(password.to_owned()))
            });
        Some(StartProfile {
            upstream_host: "127.0.0.1".into(),
            upstream_port: *port,
            protocol: match protocol {
                tunbridge_core::upstream::StandardProtocol::Socks5 => UpstreamProtocol::Socks5,
                tunbridge_core::upstream::StandardProtocol::Http => UpstreamProtocol::Http,
            },
            username,
            password,
            upstream_process_id: *expected_process_id,
            bypass_domains: self.traffic_bypass_domains.clone(),
            bypass_cidrs: self.traffic_bypass_cidrs.clone(),
            bypass_process_names: self.traffic_bypass_process_names.clone(),
        })
    }
}

#[cfg(feature = "remote-upstream-v3")]
impl fmt::Debug for StartProfileV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartProfileV3")
            .field("upstream", &self.upstream)
            .field("traffic_bypass_domains", &self.traffic_bypass_domains)
            .field("traffic_bypass_cidrs", &self.traffic_bypass_cidrs)
            .field(
                "traffic_bypass_process_names",
                &self.traffic_bypass_process_names,
            )
            .finish()
    }
}

#[cfg(feature = "remote-upstream-v3")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StartUpstreamV3 {
    LocalListener {
        port: u16,
        protocol: tunbridge_core::upstream::StandardProtocol,
        credentials: Option<tunbridge_core::upstream::SecretMaterialV2>,
        expected_process_id: u32,
    },
    RemoteServer {
        endpoint: tunbridge_core::upstream::Endpoint,
        protocol_config: tunbridge_core::upstream::RemoteProtocolConfig,
        secret_material: Option<tunbridge_core::upstream::SecretMaterialV2>,
    },
}

#[cfg(feature = "remote-upstream-v3")]
impl StartUpstreamV3 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::LocalListener {
                port,
                credentials,
                expected_process_id,
                ..
            } => {
                if *port == 0 {
                    return invalid_profile("local listener port must be non-zero");
                }
                if *expected_process_id == 0 {
                    return invalid_profile("local listener process identity must be non-zero");
                }
                validate_secret_material(credentials.as_ref())
            }
            Self::RemoteServer {
                endpoint,
                protocol_config,
                secret_material,
            } => {
                endpoint.validate().map_err(|_| {
                    ProtocolError::InvalidProfile("remote endpoint is invalid".into())
                })?;
                if matches!(
                    endpoint.ip_preference,
                    tunbridge_core::upstream::IpPreference::Ipv6
                        | tunbridge_core::upstream::IpPreference::Ipv6Prefer
                ) {
                    return invalid_profile(
                        "IPv6 remote upstream is unavailable until the three-platform gate passes",
                    );
                }
                protocol_config.validate().map_err(|_| {
                    ProtocolError::InvalidProfile("remote protocol configuration is invalid".into())
                })?;
                validate_secret_material(secret_material.as_ref())
            }
        }
    }

    pub const fn is_remote(&self) -> bool {
        matches!(self, Self::RemoteServer { .. })
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::LocalListener { port, .. } => *port,
            Self::RemoteServer { endpoint, .. } => endpoint.port,
        }
    }

    pub const fn expected_process_id(&self) -> Option<u32> {
        match self {
            Self::LocalListener {
                expected_process_id,
                ..
            } => Some(*expected_process_id),
            Self::RemoteServer { .. } => None,
        }
    }
}

#[cfg(feature = "remote-upstream-v3")]
impl fmt::Debug for StartUpstreamV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalListener {
                port,
                protocol,
                credentials,
                expected_process_id,
            } => formatter
                .debug_struct("LocalListener")
                .field("port", port)
                .field("protocol", protocol)
                .field("has_credentials", &credentials.is_some())
                .field("expected_process_id", expected_process_id)
                .finish(),
            Self::RemoteServer {
                endpoint,
                protocol_config,
                secret_material,
            } => formatter
                .debug_struct("RemoteServer")
                .field("endpoint", endpoint)
                .field("protocol_config", protocol_config)
                .field("has_secret_material", &secret_material.is_some())
                .finish(),
        }
    }
}

#[cfg(feature = "remote-upstream-v3")]
fn validate_secret_material(
    material: Option<&tunbridge_core::upstream::SecretMaterialV2>,
) -> Result<(), ProtocolError> {
    material.map_or(Ok(()), |material| {
        material
            .validate()
            .map_err(|_| ProtocolError::InvalidProfile("secret material is invalid".into()))
    })
}

/// Per-connection replay and ordering guard. The nonce is generated by the
/// Windows transport using a CSPRNG and is never accepted from client identity
/// claims or persisted across connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGuard {
    nonce: String,
    next_seq: u64,
}

impl SessionGuard {
    pub fn new(nonce: String) -> Result<Self, ProtocolError> {
        validate_hex("session_nonce", &nonce, 64)?;
        Ok(Self { nonce, next_seq: 1 })
    }

    pub fn accept(&mut self, request: &Request) -> Result<(), ProtocolError> {
        request.validate_envelope()?;
        if request.session_nonce != self.nonce {
            return Err(ProtocolError::ReplayDetected(
                "session nonce does not belong to this connection".into(),
            ));
        }
        if request.seq != self.next_seq {
            return Err(ProtocolError::ReplayDetected(format!(
                "expected sequence {}, got {}",
                self.next_seq, request.seq
            )));
        }
        if request.seq > MAX_REQUESTS_PER_CONNECTION {
            return Err(ProtocolError::ReplayDetected(
                "connection request limit exceeded".into(),
            ));
        }
        self.next_seq += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AccessDenied,
    LowIntegrityDenied,
    UnsupportedProtocol,
    InvalidFrame,
    FrameTooLarge,
    InvalidRequest,
    ReplayDetected,
    Timeout,
    OperationInProgress,
    AlreadyRunning,
    NotRunning,
    NotOwner,
    InvalidProfile,
    EngineIntegrityFailed,
    ConfigValidationFailed,
    OwnedProcessMismatch,
    RecoveryRequired,
    CapabilityUnavailable,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    LeaseInvalid,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    LeaseExpired,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    LeaseAlreadyActive,
    #[cfg(feature = "production-local-observability")]
    ObservabilityUnavailable,
    #[cfg(feature = "production-local-observability")]
    ConnectionNotFound,
    InternalError,
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
impl ErrorCode {
    /// A lease renewal rejected with this code can never succeed again: the
    /// session ended or the lease is gone. The App stops renewing and forgets
    /// the session it started; any other rejection is retried.
    pub fn ends_lease(&self) -> bool {
        matches!(
            self,
            Self::NotRunning
                | Self::NotOwner
                | Self::RecoveryRequired
                | Self::LeaseInvalid
                | Self::LeaseExpired
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub kind: ResponseKind,
    pub protocol: u16,
    pub seq: u64,
    pub request_id: String,
    pub result: ResponseResult,
}

impl Response {
    pub fn success(request: &Request, data: ResponseData) -> Self {
        Self {
            kind: ResponseKind::Response,
            protocol: PROTOCOL_VERSION,
            seq: request.seq,
            request_id: request.request_id.clone(),
            result: ResponseResult {
                ok: true,
                data: Some(data),
                error: None,
            },
        }
    }

    pub fn error(
        request: &Request,
        code: ErrorCode,
        safe_message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            kind: ResponseKind::Response,
            protocol: PROTOCOL_VERSION,
            seq: request.seq,
            request_id: request.request_id.clone(),
            result: ResponseResult {
                ok: false,
                data: None,
                error: Some(ErrorBody {
                    code,
                    safe_message: safe_message.into(),
                    retryable,
                }),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseResult {
    pub ok: bool,
    pub data: Option<ResponseData>,
    pub error: Option<ErrorBody>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseData {
    Status {
        service_phase: crate::state::Phase,
        caller_is_owner: bool,
        engine_running: bool,
        service_version: String,
        /// Why the service stopped or faulted the session on its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stop_reason: Option<crate::state::WatchdogReason>,
        /// Why a running session is degraded while it keeps failing closed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        degraded_reason: Option<crate::state::WatchdogReason>,
    },
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    Lease {
        lease_id: String,
        lease_nonce: String,
        next_seq: u64,
        ttl_ticks: u64,
        renew_after_ticks: u64,
    },
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    LeaseReleased { released: bool },
    #[cfg(feature = "production-local-observability")]
    TrafficSnapshot { snapshot: TrafficSnapshot },
    #[cfg(feature = "production-local-observability")]
    ConnectionPage { page: ConnectionPage },
    #[cfg(feature = "production-local-observability")]
    ConnectionsClosed { closed: u32 },
    #[cfg(feature = "production-mihomo-logs-v4")]
    MihomoLogPage { page: MihomoLogPage },
}

#[cfg(feature = "production-mihomo-logs-v4")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MihomoLogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[cfg(feature = "production-mihomo-logs-v4")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MihomoLogEntry {
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub level: MihomoLogLevel,
    pub message: String,
    pub truncated: bool,
}

#[cfg(feature = "production-mihomo-logs-v4")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MihomoLogPage {
    pub schema_version: u16,
    pub engine_generation: String,
    pub oldest_sequence: u64,
    pub next_sequence: u64,
    pub items: Vec<MihomoLogEntry>,
}

#[cfg(feature = "production-local-observability")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSnapshot {
    pub schema_version: u16,
    pub engine_generation: String,
    pub sequence: u64,
    pub sampled_at_unix_ms: u64,
    pub interval_ms: u32,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: u32,
    pub memory_bytes: u64,
    pub stale: bool,
}

#[cfg(feature = "production-local-observability")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Active,
    Closed,
}

#[cfg(feature = "production-local-observability")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionView {
    pub id: String,
    pub host: String,
    pub network: String,
    pub connection_type: String,
    pub source: String,
    pub destination: String,
    pub process_name: Option<String>,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: Option<String>,
    pub upload_total: u64,
    pub download_total: u64,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub started_at: String,
    pub closed_at_unix_ms: Option<u64>,
}

#[cfg(feature = "production-local-observability")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPage {
    pub schema_version: u16,
    pub engine_generation: String,
    pub sequence: u64,
    pub state: ConnectionState,
    pub offset: u32,
    pub limit: u16,
    pub total: u32,
    pub items: Vec<ConnectionView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub safe_message: String,
    pub retryable: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid profile: {0}")]
    InvalidProfile(String),
    #[error("replay detected: {0}")]
    ReplayDetected(String),
}

impl ProtocolError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedProtocol(_) => ErrorCode::UnsupportedProtocol,
            Self::InvalidFrame(_) => ErrorCode::InvalidFrame,
            Self::FrameTooLarge(_) => ErrorCode::FrameTooLarge,
            Self::InvalidRequest(_) => ErrorCode::InvalidRequest,
            Self::InvalidProfile(_) => ErrorCode::InvalidProfile,
            Self::ReplayDetected(_) => ErrorCode::ReplayDetected,
        }
    }
}

fn validate_optional_credential(field: &str, value: &Option<String>) -> Result<(), ProtocolError> {
    if let Some(value) = value {
        validate_printable(field, value, 256, true).map_err(|error| match error {
            ProtocolError::InvalidRequest(message) => ProtocolError::InvalidProfile(message),
            other => other,
        })?;
    }
    Ok(())
}

fn validate_list(
    field: &str,
    values: &[String],
    validator: fn(&str) -> bool,
) -> Result<(), ProtocolError> {
    if values.len() > MAX_RULE_ITEMS {
        return invalid_profile(format!("{field} exceeds {MAX_RULE_ITEMS} items"));
    }
    for value in values {
        if value.len() > 253 || !validator(value) {
            return invalid_profile(format!("{field} contains an invalid item"));
        }
    }
    Ok(())
}

fn validate_domain(domain: &str) -> bool {
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    !domain.is_empty()
        && !domain.contains(',')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_cidr(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    if cidr.matches('/').count() != 1 {
        return false;
    }
    let Ok(address) = IpAddr::from_str(address) else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn validate_process_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':' | ','))
}

fn validate_hex(field: &str, value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must contain exactly {length} hexadecimal characters"
        )));
    }
    Ok(())
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
fn validate_lower_hex(field: &str, value: &str, length: usize) -> Result<(), ProtocolError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} must contain exactly {length} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_printable(
    field: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidRequest(format!(
            "{field} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}

fn invalid_profile<T>(message: impl Into<String>) -> Result<T, ProtocolError> {
    Err(ProtocolError::InvalidProfile(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reasons_are_optional_and_omitted_when_absent() {
        let legacy = serde_json::json!({
            "type": "status",
            "service_phase": "running",
            "caller_is_owner": true,
            "engine_running": true,
            "service_version": "0.3.17"
        });
        let decoded: ResponseData = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(
            decoded,
            ResponseData::Status {
                service_phase: crate::state::Phase::Running,
                caller_is_owner: true,
                engine_running: true,
                service_version: "0.3.17".into(),
                stop_reason: None,
                degraded_reason: None,
            }
        );
        assert_eq!(serde_json::to_value(&decoded).unwrap(), legacy);

        let degraded = ResponseData::Status {
            service_phase: crate::state::Phase::Running,
            caller_is_owner: true,
            engine_running: true,
            service_version: "0.3.18".into(),
            stop_reason: None,
            degraded_reason: Some(crate::state::WatchdogReason::UpstreamUnavailable),
        };
        let encoded = serde_json::to_value(&degraded).unwrap();
        assert_eq!(encoded["degraded_reason"], "upstream_unavailable");
        assert!(encoded.get("stop_reason").is_none());
        assert_eq!(
            serde_json::from_value::<ResponseData>(encoded).unwrap(),
            degraded
        );
    }

    fn valid_profile() -> StartProfile {
        StartProfile {
            upstream_host: "127.0.0.1".into(),
            upstream_port: 7078,
            protocol: UpstreamProtocol::Socks5,
            username: Some("alice".into()),
            password: Some("secret".into()),
            upstream_process_id: 42,
            bypass_domains: vec!["example.com".into(), ".internal.example".into()],
            bypass_cidrs: vec!["10.0.0.0/8".into(), "fd00::/8".into()],
            bypass_process_names: vec!["client.exe".into()],
        }
    }

    fn request(nonce: &str, seq: u64) -> Request {
        Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: nonce.into(),
            seq,
            request_id: format!("{seq:032x}"),
            command: Command::Status,
        }
    }

    #[test]
    fn valid_profile_is_accepted_and_debug_redacts_credentials() {
        let profile = valid_profile();
        profile.validate().unwrap();
        let debug = format!("{profile:?}");
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn profile_rejects_non_loopback_and_zero_process() {
        let mut profile = valid_profile();
        profile.upstream_host = "192.0.2.1".into();
        assert!(matches!(
            profile.validate(),
            Err(ProtocolError::InvalidProfile(_))
        ));

        profile = valid_profile();
        profile.upstream_process_id = 0;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn profile_rejects_injection_and_invalid_rules() {
        let mut profile = valid_profile();
        profile.password = Some("secret\nmode: direct".into());
        assert!(profile.validate().is_err());

        profile = valid_profile();
        profile.bypass_domains = vec!["example.com,MATCH".into()];
        assert!(profile.validate().is_err());

        profile = valid_profile();
        profile.bypass_cidrs = vec!["10.0.0.0/99".into()];
        assert!(profile.validate().is_err());

        profile = valid_profile();
        profile.bypass_process_names = vec![r"C:\client.exe".into()];
        assert!(profile.validate().is_err());
    }

    #[test]
    fn profile_rejects_unbounded_lists() {
        let mut profile = valid_profile();
        profile.bypass_domains = vec!["example.com".into(); MAX_RULE_ITEMS + 1];
        assert!(profile.validate().is_err());
    }

    #[test]
    fn command_schema_rejects_arbitrary_paths_and_unknown_commands() {
        let arbitrary_path = r#"{"name":"start","profile":{"upstream_host":"127.0.0.1","upstream_port":7078,"protocol":"socks5","username":null,"password":null,"upstream_process_id":42,"bypass_domains":[],"bypass_cidrs":[],"bypass_process_names":[],"engine_path":"C:\\evil.exe"}}"#;
        assert!(serde_json::from_str::<Command>(arbitrary_path).is_err());
        assert!(serde_json::from_str::<Command>(r#"{"name":"exec","argv":["cmd"]}"#).is_err());
    }

    #[cfg(feature = "production-local-observability")]
    #[test]
    fn connection_pages_are_strict_and_bounded() {
        Command::ListConnections {
            state: ConnectionState::Active,
            offset: MAX_CONNECTION_PAGE_OFFSET,
            limit: MAX_CONNECTION_PAGE_SIZE,
        }
        .validate()
        .unwrap();
        assert!(Command::ListConnections {
            state: ConnectionState::Closed,
            offset: 0,
            limit: 0,
        }
        .validate()
        .is_err());
        assert!(Command::ListConnections {
            state: ConnectionState::Active,
            offset: MAX_CONNECTION_PAGE_OFFSET + 1,
            limit: 1,
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<Command>(
            r#"{"name":"list_connections","state":"active","offset":0,"limit":25,"process_path":"C:\\secret"}"#
        )
        .is_err());
        Command::CloseConnection {
            connection_id: "opaque-id_123".into(),
        }
        .validate()
        .unwrap();
        for connection_id in ["", "../all", "id/other", "id\r\nheader"] {
            assert!(Command::CloseConnection {
                connection_id: connection_id.into(),
            }
            .validate()
            .is_err());
        }
    }

    #[test]
    fn session_guard_rejects_wrong_nonce_duplicates_and_gaps() {
        let nonce = "a".repeat(64);
        let mut guard = SessionGuard::new(nonce.clone()).unwrap();

        let wrong = request(&"b".repeat(64), 1);
        assert!(matches!(
            guard.accept(&wrong),
            Err(ProtocolError::ReplayDetected(_))
        ));

        guard.accept(&request(&nonce, 1)).unwrap();
        assert!(guard.accept(&request(&nonce, 1)).is_err());
        assert!(guard.accept(&request(&nonce, 3)).is_err());
    }

    #[test]
    fn unsupported_protocol_has_stable_error_code() {
        let hello = Hello {
            kind: HelloKind::Hello,
            protocol: 99,
            client_version: "0.1.0".into(),
        };
        let error = hello.validate().unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsupportedProtocol);
    }

    #[cfg(not(any(feature = "production-app-lease", feature = "acceptance-m2b5")))]
    #[test]
    fn default_protocol_remains_v1_without_lease_commands() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert!(serde_json::from_str::<Command>(r#"{"name":"acquire_lease"}"#).is_err());
    }

    #[cfg(all(
        not(feature = "remote-upstream-v3"),
        any(feature = "production-app-lease", feature = "acceptance-m2b5")
    ))]
    #[test]
    fn isolated_v2_lease_schema_is_strict_and_lowercase() {
        assert_eq!(PROTOCOL_VERSION, 2);
        Command::AcquireLease {}.validate().unwrap();
        let valid = Command::RenewLease {
            lease_id: "ab".repeat(32),
            lease_nonce: "cd".repeat(32),
            lease_seq: 1,
        };
        valid.validate().unwrap();
        let uppercase = Command::RenewLease {
            lease_id: "AB".repeat(32),
            lease_nonce: "cd".repeat(32),
            lease_seq: 1,
        };
        assert!(uppercase.validate().is_err());
        assert!(serde_json::from_str::<Command>(r#"{"name":"acquire_lease","pid":42}"#).is_err());
        assert!(serde_json::from_str::<Command>(
            r#"{"name":"renew_lease","lease_id":"aa","lease_nonce":"bb","lease_seq":1,"path":"C:\\evil"}"#
        )
        .is_err());
    }

    #[cfg(feature = "remote-upstream-v3")]
    #[test]
    fn v3_local_and_remote_upstreams_are_explicit_and_strict() {
        use tunbridge_core::upstream::{
            CertificatePolicy, Endpoint, IpPreference, RemoteProtocolConfig, SecretMaterialV2,
            StandardProtocol,
        };

        #[cfg(not(feature = "production-mihomo-logs-v4"))]
        assert_eq!(PROTOCOL_VERSION, 3);
        #[cfg(feature = "production-mihomo-logs-v4")]
        assert_eq!(PROTOCOL_VERSION, 4);
        let local = StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: 7078,
                protocol: StandardProtocol::Socks5,
                credentials: Some(SecretMaterialV2::basic_auth("alice", "secret")),
                expected_process_id: 42,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: Vec::new(),
        };
        local.validate().unwrap();
        assert!(!local.upstream.is_remote());

        let remote = StartProfileV3 {
            upstream: StartUpstreamV3::RemoteServer {
                endpoint: Endpoint::new("proxy.example.com", 443, IpPreference::Ipv4Prefer)
                    .unwrap(),
                protocol_config: RemoteProtocolConfig::Http {
                    tls: true,
                    sni: Some("proxy.example.com".into()),
                    certificate_policy: CertificatePolicy::Strict,
                },
                secret_material: None,
            },
            traffic_bypass_domains: vec!["internal.example".into()],
            traffic_bypass_cidrs: vec!["10.0.0.0/8".into()],
            traffic_bypass_process_names: Vec::new(),
        };
        remote.validate().unwrap();
        assert!(remote.upstream.is_remote());
        assert_eq!(remote.upstream.expected_process_id(), None);

        let mut value = serde_json::to_value(remote).unwrap();
        value["upstream"]["interface"] = serde_json::json!("en0");
        assert!(serde_json::from_value::<StartProfileV3>(value).is_err());
    }

    #[cfg(feature = "remote-upstream-v3")]
    #[test]
    fn v3_remote_rejects_loopback_ipv6_gate_and_secret_leaks() {
        use tunbridge_core::upstream::{
            CertificatePolicy, Endpoint, IpPreference, RemoteProtocolConfig, SecretMaterialV2,
        };

        let invalid_loopback = serde_json::json!({
            "upstream": {
                "kind": "remote_server",
                "endpoint": {
                    "host": "127.0.0.1",
                    "port": 1080,
                    "ipPreference": "ipv4_prefer"
                },
                "protocol_config": {
                    "protocol": "socks5",
                    "tls": false,
                    "sni": null,
                    "udp": true,
                    "certificatePolicy": "strict"
                },
                "secret_material": null
            },
            "traffic_bypass_domains": [],
            "traffic_bypass_cidrs": [],
            "traffic_bypass_process_names": []
        });
        let profile: StartProfileV3 = serde_json::from_value(invalid_loopback).unwrap();
        assert!(profile.validate().is_err());

        let ipv6 = StartProfileV3 {
            upstream: StartUpstreamV3::RemoteServer {
                endpoint: Endpoint::new("2001:4860:4860::8888", 443, IpPreference::Ipv6).unwrap(),
                protocol_config: RemoteProtocolConfig::Http {
                    tls: true,
                    sni: Some("proxy.example.com".into()),
                    certificate_policy: CertificatePolicy::Strict,
                },
                secret_material: Some(SecretMaterialV2::basic_auth(
                    "private-user",
                    "private-password",
                )),
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: Vec::new(),
        };
        assert!(ipv6.validate().is_err());
        let debug = format!("{ipv6:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
        assert!(!debug.contains("2001:4860"));
    }

    #[cfg(feature = "production-mihomo-logs-v4")]
    #[test]
    fn v4_mihomo_log_pages_are_strict_and_bounded() {
        assert_eq!(PROTOCOL_VERSION, 4);
        Command::ListMihomoLogs {
            after_sequence: u64::MAX,
            limit: MAX_MIHOMO_LOG_PAGE_SIZE,
        }
        .validate()
        .unwrap();
        assert!(Command::ListMihomoLogs {
            after_sequence: 0,
            limit: 0,
        }
        .validate()
        .is_err());
        assert!(serde_json::from_str::<Command>(
            r#"{"name":"list_mihomo_logs","after_sequence":0,"limit":25,"controller":"127.0.0.1:9090"}"#,
        )
        .is_err());
    }
}
