use serde::{Deserialize, Serialize};
use std::time::Duration;
use tunbridge_service::protocol::{
    Command, ConnectionState, ConnectionView, ErrorCode, MihomoLogEntry, MihomoLogLevel,
    ResponseData,
};
#[cfg(target_os = "linux")]
use tunbridge_service_linux::{LinuxClientError, LinuxServiceClient};
#[cfg(target_os = "macos")]
use tunbridge_service_macos::{
    client_session::{MacosClientError, MacosServiceClient},
    xpc_client::NativeXpcClientBackend,
    MacosXpcTransport,
};

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopTrafficSnapshot {
    schema_version: u16,
    engine_generation: String,
    sequence: u64,
    sampled_at_unix_ms: u64,
    interval_ms: u32,
    upload_bps: u64,
    download_bps: u64,
    upload_total: u64,
    download_total: u64,
    active_connections: u32,
    memory_bytes: u64,
    stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopConnectionPageInput {
    state: ConnectionState,
    offset: u32,
    limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopConnectionView {
    id: String,
    host: String,
    network: String,
    connection_type: String,
    source: String,
    destination: String,
    process_name: Option<String>,
    chains: Vec<String>,
    rule: String,
    rule_payload: Option<String>,
    upload_total: u64,
    download_total: u64,
    upload_bps: u64,
    download_bps: u64,
    started_at: String,
    closed_at_unix_ms: Option<u64>,
}

impl From<ConnectionView> for DesktopConnectionView {
    fn from(value: ConnectionView) -> Self {
        Self {
            id: value.id,
            host: value.host,
            network: value.network,
            connection_type: value.connection_type,
            source: value.source,
            destination: value.destination,
            process_name: value.process_name,
            chains: value.chains,
            rule: value.rule,
            rule_payload: value.rule_payload,
            upload_total: value.upload_total,
            download_total: value.download_total,
            upload_bps: value.upload_bps,
            download_bps: value.download_bps,
            started_at: value.started_at,
            closed_at_unix_ms: value.closed_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopConnectionPage {
    schema_version: u16,
    engine_generation: String,
    sequence: u64,
    state: ConnectionState,
    offset: u32,
    limit: u16,
    total: u32,
    items: Vec<DesktopConnectionView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopMihomoLogPageInput {
    after_sequence: u64,
    limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopMihomoLogEntry {
    sequence: u64,
    observed_at_unix_ms: u64,
    level: MihomoLogLevel,
    message: String,
    truncated: bool,
}

impl From<MihomoLogEntry> for DesktopMihomoLogEntry {
    fn from(entry: MihomoLogEntry) -> Self {
        Self {
            sequence: entry.sequence,
            observed_at_unix_ms: entry.observed_at_unix_ms,
            level: entry.level,
            message: entry.message,
            truncated: entry.truncated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopMihomoLogPage {
    schema_version: u16,
    engine_generation: String,
    oldest_sequence: u64,
    next_sequence: u64,
    items: Vec<DesktopMihomoLogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloseConnectionInput {
    connection_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseConnectionsResult {
    schema_version: u16,
    closed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficCommandErrorCode {
    ServiceUnavailable,
    ServiceIdentityFailed,
    ServiceProtocolError,
    NotRunning,
    NotOwner,
    TrafficUnavailable,
    ConnectionNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficCommandError {
    code: TrafficCommandErrorCode,
    safe_message: &'static str,
    retryable: bool,
}

impl From<TrafficCommandErrorCode> for TrafficCommandError {
    fn from(code: TrafficCommandErrorCode) -> Self {
        let (safe_message, retryable) = match code {
            TrafficCommandErrorCode::ServiceUnavailable => {
                ("The TunBridge service is unavailable.", true)
            }
            TrafficCommandErrorCode::ServiceIdentityFailed => (
                "The TunBridge service identity could not be verified.",
                false,
            ),
            TrafficCommandErrorCode::ServiceProtocolError => (
                "The TunBridge service returned an invalid traffic response.",
                false,
            ),
            TrafficCommandErrorCode::NotRunning => ("TunBridge is not running.", true),
            TrafficCommandErrorCode::NotOwner => (
                "Traffic details are available only to the session that started TunBridge.",
                false,
            ),
            TrafficCommandErrorCode::TrafficUnavailable => {
                ("Local traffic data is temporarily unavailable.", true)
            }
            TrafficCommandErrorCode::ConnectionNotFound => {
                ("The connection is no longer active.", true)
            }
        };
        Self {
            code,
            safe_message,
            retryable,
        }
    }
}

pub fn get_traffic_snapshot() -> Result<DesktopTrafficSnapshot, TrafficCommandError> {
    match send(Command::ObserveTraffic {})? {
        ResponseData::TrafficSnapshot { snapshot } => Ok(DesktopTrafficSnapshot {
            schema_version: snapshot.schema_version,
            engine_generation: snapshot.engine_generation,
            sequence: snapshot.sequence,
            sampled_at_unix_ms: snapshot.sampled_at_unix_ms,
            interval_ms: snapshot.interval_ms,
            upload_bps: snapshot.upload_bps,
            download_bps: snapshot.download_bps,
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
            active_connections: snapshot.active_connections,
            memory_bytes: snapshot.memory_bytes,
            stale: snapshot.stale,
        }),
        _ => Err(TrafficCommandErrorCode::ServiceProtocolError.into()),
    }
}

pub fn get_connections_page(
    input: DesktopConnectionPageInput,
) -> Result<DesktopConnectionPage, TrafficCommandError> {
    match send(Command::ListConnections {
        state: input.state,
        offset: input.offset,
        limit: input.limit,
    })? {
        ResponseData::ConnectionPage { page } => Ok(DesktopConnectionPage {
            schema_version: page.schema_version,
            engine_generation: page.engine_generation,
            sequence: page.sequence,
            state: page.state,
            offset: page.offset,
            limit: page.limit,
            total: page.total,
            items: page.items.into_iter().map(Into::into).collect(),
        }),
        _ => Err(TrafficCommandErrorCode::ServiceProtocolError.into()),
    }
}

pub fn get_mihomo_logs_page(
    input: DesktopMihomoLogPageInput,
) -> Result<DesktopMihomoLogPage, TrafficCommandError> {
    match send(Command::ListMihomoLogs {
        after_sequence: input.after_sequence,
        limit: input.limit,
    })? {
        ResponseData::MihomoLogPage { page } => Ok(DesktopMihomoLogPage {
            schema_version: page.schema_version,
            engine_generation: page.engine_generation,
            oldest_sequence: page.oldest_sequence,
            next_sequence: page.next_sequence,
            items: page.items.into_iter().map(Into::into).collect(),
        }),
        _ => Err(TrafficCommandErrorCode::ServiceProtocolError.into()),
    }
}

pub fn close_connection(
    input: CloseConnectionInput,
) -> Result<CloseConnectionsResult, TrafficCommandError> {
    close_result(send(Command::CloseConnection {
        connection_id: input.connection_id,
    })?)
}

pub fn close_all_connections() -> Result<CloseConnectionsResult, TrafficCommandError> {
    close_result(send(Command::CloseAllConnections {})?)
}

fn close_result(response: ResponseData) -> Result<CloseConnectionsResult, TrafficCommandError> {
    match response {
        ResponseData::ConnectionsClosed { closed } => Ok(CloseConnectionsResult {
            schema_version: 1,
            closed,
        }),
        _ => Err(TrafficCommandErrorCode::ServiceProtocolError.into()),
    }
}

fn send(command: Command) -> Result<ResponseData, TrafficCommandError> {
    #[cfg(target_os = "linux")]
    {
        let mut client = LinuxServiceClient::connect_system()
            .map_err(|_| TrafficCommandErrorCode::ServiceUnavailable)?;
        client
            .send_detailed(command, TIMEOUT)
            .map_err(map_linux_client_error)
    }
    #[cfg(target_os = "macos")]
    {
        let mut client =
            MacosServiceClient::<MacosXpcTransport<NativeXpcClientBackend>>::connect_system()
                .map_err(|_| TrafficCommandErrorCode::ServiceUnavailable)?;
        client
            .send(command, TIMEOUT)
            .map_err(map_macos_client_error)
    }
}

#[cfg(target_os = "linux")]
fn map_linux_client_error(error: LinuxClientError) -> TrafficCommandError {
    match error {
        LinuxClientError::Adapter(error) => match error.code {
            tunbridge_desktop_contract::adapter::AdapterErrorCode::IdentityRejected => {
                TrafficCommandErrorCode::ServiceIdentityFailed.into()
            }
            tunbridge_desktop_contract::adapter::AdapterErrorCode::InvalidData => {
                TrafficCommandErrorCode::ServiceProtocolError.into()
            }
            _ => TrafficCommandErrorCode::ServiceUnavailable.into(),
        },
        LinuxClientError::Service { code, .. } => map_service_error(code),
    }
}

#[cfg(target_os = "macos")]
fn map_macos_client_error(error: MacosClientError) -> TrafficCommandError {
    match error {
        MacosClientError::Adapter(error) => match error.code {
            tunbridge_desktop_contract::adapter::AdapterErrorCode::IdentityRejected => {
                TrafficCommandErrorCode::ServiceIdentityFailed.into()
            }
            tunbridge_desktop_contract::adapter::AdapterErrorCode::InvalidData => {
                TrafficCommandErrorCode::ServiceProtocolError.into()
            }
            _ => TrafficCommandErrorCode::ServiceUnavailable.into(),
        },
        MacosClientError::Service { code, .. } => map_service_error(code),
    }
}

fn map_service_error(code: ErrorCode) -> TrafficCommandError {
    match code {
        ErrorCode::NotRunning => TrafficCommandErrorCode::NotRunning.into(),
        ErrorCode::NotOwner => TrafficCommandErrorCode::NotOwner.into(),
        ErrorCode::ConnectionNotFound => TrafficCommandErrorCode::ConnectionNotFound.into(),
        ErrorCode::ObservabilityUnavailable => TrafficCommandErrorCode::TrafficUnavailable.into(),
        _ => TrafficCommandErrorCode::ServiceProtocolError.into(),
    }
}
