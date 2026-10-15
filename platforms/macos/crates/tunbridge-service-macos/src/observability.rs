use serde_json::Value;
use std::{
    collections::VecDeque,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tunbridge_service::protocol::{
    ConnectionPage, ConnectionState, ConnectionView, ErrorCode, TrafficSnapshot,
};

const MAX_CONNECTIONS: usize = 4096;
const MAX_CLOSED: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservabilityFailure {
    pub code: ErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
}

pub trait OwnedControllerSource {
    fn engine_generation(&self) -> Result<String, ObservabilityFailure>;
    fn connections(&mut self) -> Result<Vec<u8>, ObservabilityFailure>;
    fn close(&mut self, connection_id: Option<&str>) -> Result<(), ObservabilityFailure>;
}

#[derive(Default)]
pub struct MacosObservability {
    previous: Option<PreviousSample>,
    sequence: u64,
    closed: VecDeque<ConnectionView>,
}

struct PreviousSample {
    at: Instant,
    upload_total: u64,
    download_total: u64,
}

impl MacosObservability {
    pub fn sample<S: OwnedControllerSource>(
        &mut self,
        source: &mut S,
    ) -> Result<TrafficSnapshot, ObservabilityFailure> {
        let generation = valid_generation(source.engine_generation()?)?;
        let document = connections_document(source)?;
        let upload_total = number(&document, "uploadTotal")?;
        let download_total = number(&document, "downloadTotal")?;
        let active_connections = document
            .get("connections")
            .and_then(|value| {
                value
                    .as_array()
                    .map(|items| items.len().min(u32::MAX as usize) as u32)
                    .or_else(|| value.is_null().then_some(0))
            })
            .ok_or_else(observability_error)?;
        let memory_bytes = number(&document, "memory")?;
        let now = Instant::now();
        let (interval_ms, upload_bps, download_bps, stale) = match self.previous.take() {
            Some(previous) => {
                let elapsed = now.duration_since(previous.at);
                let milliseconds = elapsed.as_millis().clamp(1, u32::MAX as u128) as u32;
                (
                    milliseconds,
                    upload_total
                        .saturating_sub(previous.upload_total)
                        .saturating_mul(1000)
                        / milliseconds as u64,
                    download_total
                        .saturating_sub(previous.download_total)
                        .saturating_mul(1000)
                        / milliseconds as u64,
                    elapsed > Duration::from_secs(5),
                )
            }
            None => (1000, 0, 0, true),
        };
        self.previous = Some(PreviousSample {
            at: now,
            upload_total,
            download_total,
        });
        self.sequence = self.sequence.saturating_add(1);
        Ok(TrafficSnapshot {
            schema_version: 1,
            engine_generation: generation,
            sequence: self.sequence,
            sampled_at_unix_ms: unix_ms(),
            interval_ms,
            upload_bps,
            download_bps,
            upload_total,
            download_total,
            active_connections,
            memory_bytes,
            stale,
        })
    }

    pub fn page<S: OwnedControllerSource>(
        &mut self,
        source: &mut S,
        state: ConnectionState,
        offset: u32,
        limit: u16,
    ) -> Result<ConnectionPage, ObservabilityFailure> {
        if limit == 0 || limit > 25 || offset > 10_000 {
            return Err(observability_error());
        }
        let generation = valid_generation(source.engine_generation()?)?;
        let items = match state {
            ConnectionState::Active => active_connections(source)?,
            ConnectionState::Closed => self.closed.iter().cloned().collect(),
        };
        let total = items.len().min(u32::MAX as usize) as u32;
        let items = items
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        self.sequence = self.sequence.saturating_add(1);
        Ok(ConnectionPage {
            schema_version: 1,
            engine_generation: generation,
            sequence: self.sequence,
            state,
            offset,
            limit,
            total,
            items,
        })
    }

    pub fn close<S: OwnedControllerSource>(
        &mut self,
        source: &mut S,
        connection_id: Option<&str>,
    ) -> Result<u32, ObservabilityFailure> {
        valid_generation(source.engine_generation()?)?;
        if connection_id.is_some_and(|value| !valid_connection_id(value)) {
            return Err(observability_error());
        }
        let active = active_connections(source)?;
        let selected = match connection_id {
            Some(id) => active
                .into_iter()
                .filter(|connection| connection.id == id)
                .collect::<Vec<_>>(),
            None => active,
        };
        if connection_id.is_some() && selected.is_empty() {
            return Err(ObservabilityFailure {
                code: ErrorCode::ConnectionNotFound,
                safe_message: "The connection is no longer active.",
                retryable: true,
            });
        }
        source.close(connection_id)?;
        let closed = selected.len().min(u32::MAX as usize) as u32;
        for mut connection in selected {
            connection.closed_at_unix_ms = Some(unix_ms());
            self.closed.push_front(connection);
        }
        self.closed.truncate(MAX_CLOSED);
        Ok(closed)
    }

    pub fn reset(&mut self) {
        self.previous = None;
        self.closed.clear();
    }
}

fn connections_document<S: OwnedControllerSource>(
    source: &mut S,
) -> Result<Value, ObservabilityFailure> {
    serde_json::from_slice(&source.connections()?).map_err(|_| observability_error())
}

fn active_connections<S: OwnedControllerSource>(
    source: &mut S,
) -> Result<Vec<ConnectionView>, ObservabilityFailure> {
    let document = connections_document(source)?;
    let value = document
        .get("connections")
        .ok_or_else(observability_error)?;
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value.as_array().ok_or_else(observability_error)?;
    if values.len() > MAX_CONNECTIONS {
        return Err(observability_error());
    }
    values.iter().map(parse_connection).collect()
}

fn parse_connection(value: &Value) -> Result<ConnectionView, ObservabilityFailure> {
    let metadata = value
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(observability_error)?;
    let id = text(value, "id", 128)?;
    if !valid_connection_id(&id) {
        return Err(observability_error());
    }
    let host = metadata
        .get("host")
        .and_then(Value::as_str)
        .or_else(|| metadata.get("destinationIP").and_then(Value::as_str))
        .unwrap_or("")
        .chars()
        .take(255)
        .collect();
    let destination_ip = metadata
        .get("destinationIP")
        .and_then(Value::as_str)
        .unwrap_or("");
    let destination_port = metadata
        .get("destinationPort")
        .and_then(Value::as_str)
        .unwrap_or("");
    let source_ip = metadata
        .get("sourceIP")
        .and_then(Value::as_str)
        .unwrap_or("");
    let source_port = metadata
        .get("sourcePort")
        .and_then(Value::as_str)
        .unwrap_or("");
    Ok(ConnectionView {
        id,
        host,
        network: bounded_optional(metadata.get("network"), 32),
        connection_type: bounded_optional(metadata.get("type"), 32),
        source: format!("{source_ip}:{source_port}"),
        destination: format!("{destination_ip}:{destination_port}"),
        process_name: metadata
            .get("process")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(128).collect()),
        chains: value
            .get("chains")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .take(16)
                    .map(|value| value.chars().take(128).collect())
                    .collect()
            })
            .unwrap_or_default(),
        rule: bounded_optional(value.get("rule"), 128),
        rule_payload: value
            .get("rulePayload")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(256).collect()),
        upload_total: number(value, "upload")?,
        download_total: number(value, "download")?,
        upload_bps: 0,
        download_bps: 0,
        started_at: text(value, "start", 64)?,
        closed_at_unix_ms: None,
    })
}

fn valid_generation(value: String) -> Result<String, ObservabilityFailure> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(value)
    } else {
        Err(observability_error())
    }
}

fn valid_connection_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn bounded_optional(value: Option<&Value>, max: usize) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(max)
        .collect()
}

fn text(value: &Value, field: &str, max: usize) -> Result<String, ObservabilityFailure> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(observability_error)?;
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        Err(observability_error())
    } else {
        Ok(text.into())
    }
}

fn number(value: &Value, field: &str) -> Result<u64, ObservabilityFailure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(observability_error)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

const fn observability_error() -> ObservabilityFailure {
    ObservabilityFailure {
        code: ErrorCode::ObservabilityUnavailable,
        safe_message: "macOS owned-engine observability is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSource {
        generation: String,
        document: Vec<u8>,
        closed: Vec<Option<String>>,
    }

    impl OwnedControllerSource for MockSource {
        fn engine_generation(&self) -> Result<String, ObservabilityFailure> {
            Ok(self.generation.clone())
        }

        fn connections(&mut self) -> Result<Vec<u8>, ObservabilityFailure> {
            Ok(self.document.clone())
        }

        fn close(&mut self, connection_id: Option<&str>) -> Result<(), ObservabilityFailure> {
            self.closed.push(connection_id.map(str::to_owned));
            Ok(())
        }
    }

    fn document() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "uploadTotal": 12,
            "downloadTotal": 34,
            "memory": 56,
            "connections": [{
                "id": "abc-123",
                "metadata": {
                    "host": "example.com",
                    "network": "tcp",
                    "type": "HTTP",
                    "sourceIP": "198.18.0.1",
                    "sourcePort": "12345",
                    "destinationIP": "93.184.216.34",
                    "destinationPort": "443",
                    "process": "curl"
                },
                "chains": ["upstream"],
                "rule": "Match",
                "rulePayload": "",
                "upload": 12,
                "download": 34,
                "start": "2026-07-31T00:00:00.000Z"
            }]
        }))
        .unwrap()
    }

    fn source() -> MockSource {
        MockSource {
            generation: "a".repeat(32),
            document: document(),
            closed: Vec::new(),
        }
    }

    #[test]
    fn traffic_page_close_and_closed_history_share_one_generation() {
        let mut source = source();
        let mut observer = MacosObservability::default();
        let sample = observer.sample(&mut source).unwrap();
        assert_eq!(sample.active_connections, 1);
        assert_eq!(sample.upload_total, 12);
        assert!(sample.stale);

        let active = observer
            .page(&mut source, ConnectionState::Active, 0, 25)
            .unwrap();
        assert_eq!(active.items[0].id, "abc-123");
        assert_eq!(observer.close(&mut source, Some("abc-123")).unwrap(), 1);
        assert_eq!(source.closed, [Some("abc-123".into())]);
        let closed = observer
            .page(&mut source, ConnectionState::Closed, 0, 25)
            .unwrap();
        assert_eq!(closed.items.len(), 1);
        assert!(closed.items[0].closed_at_unix_ms.is_some());
    }

    #[test]
    fn malformed_generation_document_page_and_id_fail_before_close() {
        let mut observer = MacosObservability::default();
        let mut invalid_generation = source();
        invalid_generation.generation = "A".repeat(32);
        assert_eq!(
            observer.sample(&mut invalid_generation).unwrap_err().code,
            ErrorCode::ObservabilityUnavailable
        );

        let mut malformed = source();
        malformed.document = br#"{"connections":"not-an-array"}"#.to_vec();
        assert!(observer
            .page(&mut malformed, ConnectionState::Active, 0, 25)
            .is_err());
        let mut valid = source();
        assert!(observer
            .page(&mut valid, ConnectionState::Active, 0, 26)
            .is_err());
        assert!(observer.close(&mut valid, Some("../escape")).is_err());
        assert!(valid.closed.is_empty());
    }

    #[test]
    fn missing_connection_is_typed_and_does_not_call_controller_delete() {
        let mut source = source();
        let mut observer = MacosObservability::default();
        let error = observer.close(&mut source, Some("missing")).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConnectionNotFound);
        assert!(source.closed.is_empty());
    }
}
