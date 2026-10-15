use crate::{LifecycleFailure, LinuxLifecycle};
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

#[derive(Default)]
pub struct LinuxObservability {
    previous: Option<PreviousSample>,
    sequence: u64,
    closed: VecDeque<ConnectionView>,
}

struct PreviousSample {
    at: Instant,
    upload_total: u64,
    download_total: u64,
}

impl LinuxObservability {
    pub fn sample(
        &mut self,
        lifecycle: &LinuxLifecycle,
    ) -> Result<TrafficSnapshot, LifecycleFailure> {
        let generation = lifecycle.engine_generation()?;
        let document = connections_document(lifecycle)?;
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
                let upload = upload_total
                    .saturating_sub(previous.upload_total)
                    .saturating_mul(1000)
                    / milliseconds as u64;
                let download = download_total
                    .saturating_sub(previous.download_total)
                    .saturating_mul(1000)
                    / milliseconds as u64;
                (
                    milliseconds,
                    upload,
                    download,
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

    pub fn page(
        &mut self,
        lifecycle: &LinuxLifecycle,
        state: ConnectionState,
        offset: u32,
        limit: u16,
    ) -> Result<ConnectionPage, LifecycleFailure> {
        let generation = lifecycle.engine_generation()?;
        let items = match state {
            ConnectionState::Active => active_connections(lifecycle)?,
            ConnectionState::Closed => self.closed.iter().cloned().collect(),
        };
        let total = items.len().min(u32::MAX as usize) as u32;
        let page = items
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
            items: page,
        })
    }

    pub fn close(
        &mut self,
        lifecycle: &LinuxLifecycle,
        connection_id: Option<&str>,
    ) -> Result<u32, LifecycleFailure> {
        let active = active_connections(lifecycle)?;
        let selected: Vec<_> = match connection_id {
            Some(id) => active.into_iter().filter(|item| item.id == id).collect(),
            None => active,
        };
        if connection_id.is_some() && selected.is_empty() {
            return Err(LifecycleFailure {
                code: ErrorCode::ConnectionNotFound,
                safe_message: "The connection is no longer active.",
                retryable: true,
            });
        }
        let closed_count = selected.len().min(u32::MAX as usize) as u32;
        let path = connection_id
            .map(|id| format!("/connections/{id}"))
            .unwrap_or_else(|| "/connections".into());
        lifecycle.controller_request("DELETE", &path)?;
        for mut item in selected {
            item.closed_at_unix_ms = Some(unix_ms());
            self.closed.push_front(item);
        }
        self.closed.truncate(MAX_CLOSED);
        Ok(closed_count)
    }

    pub fn reset(&mut self) {
        self.previous = None;
        self.closed.clear();
    }
}

fn connections_document(lifecycle: &LinuxLifecycle) -> Result<Value, LifecycleFailure> {
    serde_json::from_slice(&lifecycle.controller_request("GET", "/connections")?)
        .map_err(|_| observability_error())
}

fn active_connections(lifecycle: &LinuxLifecycle) -> Result<Vec<ConnectionView>, LifecycleFailure> {
    let document = connections_document(lifecycle)?;
    let Some(value) = document.get("connections") else {
        return Err(observability_error());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value.as_array().ok_or_else(observability_error)?;
    if values.len() > MAX_CONNECTIONS {
        return Err(observability_error());
    }
    values.iter().map(parse_connection).collect()
}

fn parse_connection(value: &Value) -> Result<ConnectionView, LifecycleFailure> {
    let metadata = value
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(observability_error)?;
    let id = text(value, "id", 128)?;
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
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
        network: metadata
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(32)
            .collect(),
        connection_type: metadata
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(32)
            .collect(),
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
        rule: value
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(128)
            .collect(),
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

fn text(value: &Value, field: &str, max: usize) -> Result<String, LifecycleFailure> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(observability_error)?;
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(observability_error());
    }
    Ok(text.into())
}

fn number(value: &Value, field: &str) -> Result<u64, LifecycleFailure> {
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

const fn observability_error() -> LifecycleFailure {
    LifecycleFailure {
        code: ErrorCode::ObservabilityUnavailable,
        safe_message: "Linux owned-engine observability is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_parser_accepts_bounded_mihomo_shape() {
        let value = serde_json::json!({
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
            "start": "2026-07-27T00:00:00.000Z"
        });
        let parsed = parse_connection(&value).unwrap();
        assert_eq!(parsed.id, "abc-123");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.upload_total, 12);
    }
}
