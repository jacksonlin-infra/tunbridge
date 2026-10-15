use serde::{Deserialize, Serialize};
use tunbridge_service::{
    protocol::{ConnectionState, ConnectionView, MihomoLogEntry, MihomoLogLevel, ResponseData},
    windows::{ClientError, ServiceClient},
};

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
    fn from(connection: ConnectionView) -> Self {
        Self {
            id: connection.id,
            host: connection.host,
            network: connection.network,
            connection_type: connection.connection_type,
            source: connection.source,
            destination: connection.destination,
            process_name: connection.process_name,
            chains: connection.chains,
            rule: connection.rule,
            rule_payload: connection.rule_payload,
            upload_total: connection.upload_total,
            download_total: connection.download_total,
            upload_bps: connection.upload_bps,
            download_bps: connection.download_bps,
            started_at: connection.started_at,
            closed_at_unix_ms: connection.closed_at_unix_ms,
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
        error_for(code)
    }
}

pub fn get_traffic_snapshot() -> Result<DesktopTrafficSnapshot, TrafficCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    match client.observe_traffic().map_err(map_client_error)? {
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
        _ => Err(error(
            TrafficCommandErrorCode::ServiceProtocolError,
            "The TunBridge service returned an invalid traffic response.",
            false,
        )),
    }
}

pub fn get_connections_page(
    input: DesktopConnectionPageInput,
) -> Result<DesktopConnectionPage, TrafficCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    match client
        .list_connections(input.state, input.offset, input.limit)
        .map_err(map_client_error)?
    {
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
        _ => Err(error(
            TrafficCommandErrorCode::ServiceProtocolError,
            "The TunBridge service returned an invalid connection response.",
            false,
        )),
    }
}

pub fn get_mihomo_logs_page(
    input: DesktopMihomoLogPageInput,
) -> Result<DesktopMihomoLogPage, TrafficCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    match client
        .list_mihomo_logs(input.after_sequence, input.limit)
        .map_err(map_client_error)?
    {
        ResponseData::MihomoLogPage { page } => Ok(DesktopMihomoLogPage {
            schema_version: page.schema_version,
            engine_generation: page.engine_generation,
            oldest_sequence: page.oldest_sequence,
            next_sequence: page.next_sequence,
            items: page.items.into_iter().map(Into::into).collect(),
        }),
        _ => Err(error(
            TrafficCommandErrorCode::ServiceProtocolError,
            "The TunBridge service returned an invalid Mihomo log response.",
            false,
        )),
    }
}

pub fn close_connection(
    input: CloseConnectionInput,
) -> Result<CloseConnectionsResult, TrafficCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    close_result(
        client
            .close_connection(input.connection_id)
            .map_err(map_client_error)?,
    )
}

pub fn close_all_connections() -> Result<CloseConnectionsResult, TrafficCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    close_result(client.close_all_connections().map_err(map_client_error)?)
}

fn close_result(response: ResponseData) -> Result<CloseConnectionsResult, TrafficCommandError> {
    match response {
        ResponseData::ConnectionsClosed { closed } => Ok(CloseConnectionsResult {
            schema_version: 1,
            closed,
        }),
        _ => Err(error(
            TrafficCommandErrorCode::ServiceProtocolError,
            "The TunBridge service returned an invalid close response.",
            false,
        )),
    }
}

fn map_client_error(client_error: ClientError) -> TrafficCommandError {
    match client_error {
        ClientError::ServerIdentity(_) => error_for(TrafficCommandErrorCode::ServiceIdentityFailed),
        ClientError::Protocol(_)
        | ClientError::ProtocolMismatch(_)
        | ClientError::MissingStatusCapability
        | ClientError::MissingCapability(_)
        | ClientError::ResponseMismatch => error_for(TrafficCommandErrorCode::ServiceProtocolError),
        ClientError::Service {
            code, retryable, ..
        } => match code {
            tunbridge_service::protocol::ErrorCode::NotRunning => {
                error_for(TrafficCommandErrorCode::NotRunning)
            }
            tunbridge_service::protocol::ErrorCode::NotOwner => {
                error_for(TrafficCommandErrorCode::NotOwner)
            }
            tunbridge_service::protocol::ErrorCode::ObservabilityUnavailable => error(
                TrafficCommandErrorCode::TrafficUnavailable,
                "Local traffic data is temporarily unavailable.",
                retryable,
            ),
            tunbridge_service::protocol::ErrorCode::ConnectionNotFound => {
                error_for(TrafficCommandErrorCode::ConnectionNotFound)
            }
            _ => error(
                TrafficCommandErrorCode::ServiceProtocolError,
                "The TunBridge service rejected the traffic request.",
                retryable,
            ),
        },
        ClientError::Windows(_) | ClientError::Pipe(_) => {
            error_for(TrafficCommandErrorCode::ServiceUnavailable)
        }
    }
}

fn error_for(code: TrafficCommandErrorCode) -> TrafficCommandError {
    let (message, retryable) = match code {
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
    error(code, message, retryable)
}

fn error(
    code: TrafficCommandErrorCode,
    safe_message: &'static str,
    retryable: bool,
) -> TrafficCommandError {
    TrafficCommandError {
        code,
        safe_message,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_errors_are_mapped_without_raw_details() {
        let mapped = map_client_error(ClientError::Service {
            code: tunbridge_service::protocol::ErrorCode::ObservabilityUnavailable,
            message: r"C:\ProgramData\secret".into(),
            retryable: true,
        });
        let encoded = serde_json::to_string(&mapped).unwrap();
        assert!(encoded.contains("traffic_unavailable"));
        assert!(!encoded.contains("ProgramData"));
        assert!(!encoded.contains("secret"));
    }
}
