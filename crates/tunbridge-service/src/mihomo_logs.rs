use std::{
    collections::VecDeque,
    io,
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use thiserror::Error;
use tungstenite::{
    client::{client_with_config, IntoClientRequest},
    http::header::AUTHORIZATION,
    protocol::WebSocketConfig,
    Error as WebSocketError, Message,
};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{MihomoLogEntry, MihomoLogLevel, MihomoLogPage};

pub const LOG_SCHEMA_VERSION: u16 = 1;
pub const MAX_LOG_ENTRIES: usize = 1_000;
pub const MAX_LOG_MESSAGE_BYTES: usize = 1_024;
pub const MAX_LOG_FRAME_BYTES: usize = 16 * 1_024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogRecordError {
    #[error("mihomo log frame is empty or exceeds the bounded limit")]
    InvalidFrameSize,
    #[error("mihomo log frame is malformed")]
    Malformed,
    #[error("mihomo log frame has an unsupported level")]
    UnsupportedLevel,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogMonitorError {
    #[error("mihomo log session is invalid")]
    InvalidSession,
    #[error("mihomo log monitor state is unavailable")]
    StateUnavailable,
    #[error("mihomo log monitor worker could not be started")]
    WorkerStart,
    #[error("mihomo log monitor worker did not stop cleanly")]
    WorkerJoin,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MihomoLogSession {
    pub engine_generation: String,
    pub controller: SocketAddr,
    pub controller_secret: Zeroizing<String>,
}

impl MihomoLogSession {
    pub fn new(
        engine_generation: String,
        controller: SocketAddr,
        controller_secret: Zeroizing<String>,
    ) -> Result<Self, LogMonitorError> {
        if engine_generation.is_empty()
            || engine_generation.len() > 64
            || engine_generation.chars().any(char::is_control)
            || !controller.ip().is_loopback()
            || controller.port() == 0
            || controller_secret.len() != 64
            || !controller_secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(LogMonitorError::InvalidSession);
        }
        Ok(Self {
            engine_generation,
            controller,
            controller_secret,
        })
    }
}

impl std::fmt::Debug for MihomoLogSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MihomoLogSession")
            .field("engine_generation", &self.engine_generation)
            .field("controller", &self.controller)
            .field("controller_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredLogFrame {
    #[allow(dead_code)]
    time: String,
    level: String,
    message: String,
    #[serde(default)]
    fields: serde_json::Value,
}

#[derive(Default)]
pub struct MihomoLogStore {
    engine_generation: String,
    next_sequence: u64,
    entries: VecDeque<MihomoLogEntry>,
}

#[derive(Default)]
pub struct MihomoLogMonitor {
    store: Arc<Mutex<MihomoLogStore>>,
    worker: Mutex<Option<LogWorker>>,
}

struct LogWorker {
    engine_generation: String,
    controller: SocketAddr,
    cancelled: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl MihomoLogMonitor {
    pub fn sync(&self, session: Option<MihomoLogSession>) -> Result<(), LogMonitorError> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| LogMonitorError::StateUnavailable)?;
        let unchanged = match (&*worker, &session) {
            (Some(current), Some(next)) => {
                current.engine_generation == next.engine_generation
                    && current.controller == next.controller
            }
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return Ok(());
        }
        if let Some(current) = worker.take() {
            stop_worker(current)?;
        }
        let Some(session) = session else {
            self.store
                .lock()
                .map_err(|_| LogMonitorError::StateUnavailable)?
                .reset("");
            return Ok(());
        };
        self.store
            .lock()
            .map_err(|_| LogMonitorError::StateUnavailable)?
            .reset(session.engine_generation.clone());
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let store = Arc::clone(&self.store);
        let engine_generation = session.engine_generation.clone();
        let controller = session.controller;
        let handle = std::thread::Builder::new()
            .name("tunbridge-mihomo-logs".into())
            .spawn(move || run_monitor(session, store, worker_cancelled))
            .map_err(|_| LogMonitorError::WorkerStart)?;
        *worker = Some(LogWorker {
            engine_generation,
            controller,
            cancelled,
            handle,
        });
        Ok(())
    }

    pub fn page(&self, after_sequence: u64, limit: u16) -> Result<MihomoLogPage, LogMonitorError> {
        self.store
            .lock()
            .map(|store| store.page(after_sequence, limit))
            .map_err(|_| LogMonitorError::StateUnavailable)
    }

    pub fn stop(&self) -> Result<(), LogMonitorError> {
        self.sync(None)
    }
}

impl Drop for MihomoLogMonitor {
    fn drop(&mut self) {
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = stop_worker(worker);
            }
        }
    }
}

fn stop_worker(worker: LogWorker) -> Result<(), LogMonitorError> {
    worker.cancelled.store(true, Ordering::SeqCst);
    worker
        .handle
        .join()
        .map_err(|_| LogMonitorError::WorkerJoin)
}

fn run_monitor(
    mut session: MihomoLogSession,
    store: Arc<Mutex<MihomoLogStore>>,
    cancelled: Arc<AtomicBool>,
) {
    let mut reconnect_delay = MIN_RECONNECT_DELAY;
    while !cancelled.load(Ordering::SeqCst) {
        let observed = collect_stream_once(&session, &store, &cancelled).unwrap_or(0);
        reconnect_delay = if observed > 0 {
            MIN_RECONNECT_DELAY
        } else {
            reconnect_delay.saturating_mul(2).min(MAX_RECONNECT_DELAY)
        };
        wait_until_cancelled(&cancelled, reconnect_delay);
    }
    session.controller_secret.zeroize();
}

fn collect_stream_once(
    session: &MihomoLogSession,
    store: &Arc<Mutex<MihomoLogStore>>,
    cancelled: &AtomicBool,
) -> Result<usize, ()> {
    let stream =
        TcpStream::connect_timeout(&session.controller, CONNECT_TIMEOUT).map_err(|_| ())?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let controller = match session.controller {
        SocketAddr::V4(address) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    };
    let mut request = format!("ws://{controller}/logs?level=info&format=structured")
        .into_client_request()
        .map_err(|_| ())?;
    let authorization = format!("Bearer {}", session.controller_secret.as_str())
        .parse()
        .map_err(|_| ())?;
    request.headers_mut().insert(AUTHORIZATION, authorization);
    let config = WebSocketConfig::default()
        .read_buffer_size(4 * 1_024)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * MAX_LOG_FRAME_BYTES)
        .max_message_size(Some(MAX_LOG_FRAME_BYTES))
        .max_frame_size(Some(MAX_LOG_FRAME_BYTES));
    let (mut socket, _) = client_with_config(request, stream, Some(config)).map_err(|_| ())?;
    let mut observed = 0;
    while !cancelled.load(Ordering::SeqCst) {
        match socket.read() {
            Ok(Message::Text(text)) => {
                let observed_at = unix_time_ms().map_err(|_| ())?;
                if let Ok(mut store) = store.lock() {
                    if store
                        .record_json(
                            text.as_bytes(),
                            observed_at,
                            session.controller_secret.as_str(),
                        )
                        .is_ok()
                    {
                        observed += 1;
                    }
                } else {
                    return Err(());
                }
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {
                let _ = socket.flush();
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Binary(_) | Message::Frame(_)) => {}
            Err(WebSocketError::Io(error)) if is_retryable_read_timeout(&error) => continue,
            Err(_) => break,
        }
    }
    let _ = socket.close(None);
    Ok(observed)
}

fn is_retryable_read_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn unix_time_ms() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .map_err(|_| ())
}

fn wait_until_cancelled(cancelled: &AtomicBool, duration: Duration) {
    let mut remaining = duration;
    while !cancelled.load(Ordering::SeqCst) && !remaining.is_zero() {
        let slice = remaining.min(Duration::from_millis(50));
        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

impl MihomoLogStore {
    pub fn reset(&mut self, engine_generation: impl Into<String>) {
        self.engine_generation = engine_generation.into();
        self.next_sequence = 1;
        self.entries.clear();
    }

    pub fn engine_generation(&self) -> &str {
        &self.engine_generation
    }

    pub fn record_json(
        &mut self,
        frame: &[u8],
        observed_at_unix_ms: u64,
        controller_secret: &str,
    ) -> Result<(), LogRecordError> {
        if frame.is_empty() || frame.len() > MAX_LOG_FRAME_BYTES {
            return Err(LogRecordError::InvalidFrameSize);
        }
        let parsed: StructuredLogFrame =
            serde_json::from_slice(frame).map_err(|_| LogRecordError::Malformed)?;
        let _ = parsed.fields;
        let level = parse_level(&parsed.level)?;
        let (message, truncated) = normalize_message(&parsed.message, controller_secret);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.entries.push_back(MihomoLogEntry {
            sequence,
            observed_at_unix_ms,
            level,
            message,
            truncated,
        });
        while self.entries.len() > MAX_LOG_ENTRIES {
            self.entries.pop_front();
        }
        Ok(())
    }

    pub fn page(&self, after_sequence: u64, limit: u16) -> MihomoLogPage {
        let oldest_sequence = self
            .entries
            .front()
            .map_or(self.next_sequence.max(1), |entry| entry.sequence);
        let items = self
            .entries
            .iter()
            .filter(|entry| entry.sequence > after_sequence)
            .take(usize::from(limit))
            .cloned()
            .collect();
        MihomoLogPage {
            schema_version: LOG_SCHEMA_VERSION,
            engine_generation: self.engine_generation.clone(),
            oldest_sequence,
            next_sequence: self.next_sequence.max(1),
            items,
        }
    }
}

fn parse_level(value: &str) -> Result<MihomoLogLevel, LogRecordError> {
    match value.to_ascii_lowercase().as_str() {
        "debug" => Ok(MihomoLogLevel::Debug),
        "info" => Ok(MihomoLogLevel::Info),
        "warn" | "warning" => Ok(MihomoLogLevel::Warning),
        "error" => Ok(MihomoLogLevel::Error),
        _ => Err(LogRecordError::UnsupportedLevel),
    }
}

fn normalize_message(value: &str, controller_secret: &str) -> (String, bool) {
    let mut normalized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if !controller_secret.is_empty() {
        normalized = normalized.replace(controller_secret, "[REDACTED]");
    }
    for marker in ["authorization:", "proxy-authorization:"] {
        redact_after_marker(&mut normalized, marker, false);
    }
    for marker in ["bearer ", "password=", "passwd=", "token=", "secret="] {
        redact_after_marker(&mut normalized, marker, true);
    }
    truncate_utf8(normalized, MAX_LOG_MESSAGE_BYTES)
}

fn redact_after_marker(value: &mut String, marker: &str, stop_on_whitespace: bool) {
    let mut search_from = 0;
    loop {
        let lowercase = value[search_from..].to_ascii_lowercase();
        let Some(relative_start) = lowercase.find(marker) else {
            break;
        };
        let value_start = search_from + relative_start + marker.len();
        let value_end = value[value_start..]
            .char_indices()
            .find_map(|(offset, character)| {
                ((stop_on_whitespace && character.is_whitespace())
                    || matches!(character, ',' | ';' | '&' | ']' | '}'))
                .then_some(value_start + offset)
            })
            .unwrap_or(value.len());
        value.replace_range(value_start..value_end, "[REDACTED]");
        search_from = value_start + "[REDACTED]".len();
        if search_from >= value.len() {
            break;
        }
    }
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    (value, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(level: &str, message: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "time": "2026-08-29T10:00:00.000Z",
            "level": level,
            "message": message,
            "fields": { "ignored": "value" }
        }))
        .unwrap()
    }

    #[test]
    fn structured_frames_are_normalized_and_secrets_are_redacted() {
        let mut store = MihomoLogStore::default();
        store.reset("generation-a");
        store
            .record_json(
                &frame(
                    "warning",
                    "dial example.com\nAuthorization: abc token=private; ok",
                ),
                42,
                "abc",
            )
            .unwrap();
        let page = store.page(0, 25);
        assert_eq!(page.engine_generation, "generation-a");
        assert_eq!(page.items[0].level, MihomoLogLevel::Warning);
        assert_eq!(page.items[0].observed_at_unix_ms, 42);
        assert!(!page.items[0].message.contains("abc"));
        assert!(!page.items[0].message.contains("private"));
        assert!(!page.items[0].message.contains('\n'));

        let (authorization, _) = normalize_message(
            "Authorization: Bearer unrelated-secret, route=direct",
            "not-the-secret",
        );
        assert!(!authorization.contains("unrelated-secret"));
    }

    #[test]
    fn ring_and_cursor_are_bounded_and_generation_reset_is_exact() {
        let mut store = MihomoLogStore::default();
        store.reset("generation-a");
        for index in 0..(MAX_LOG_ENTRIES + 5) {
            store
                .record_json(
                    &frame("info", &format!("message-{index}")),
                    index as u64,
                    "",
                )
                .unwrap();
        }
        let page = store.page(0, 25);
        assert_eq!(page.oldest_sequence, 6);
        assert_eq!(page.next_sequence, 1_006);
        assert_eq!(page.items.len(), 25);
        assert_eq!(page.items[0].sequence, 6);

        store.reset("generation-b");
        let page = store.page(0, 25);
        assert_eq!(page.engine_generation, "generation-b");
        assert_eq!(page.oldest_sequence, 1);
        assert_eq!(page.next_sequence, 1);
        assert!(page.items.is_empty());
    }

    #[test]
    fn malformed_unknown_and_oversize_frames_are_rejected() {
        let mut store = MihomoLogStore::default();
        store.reset("generation-a");
        assert_eq!(
            store.record_json(b"{}", 1, ""),
            Err(LogRecordError::Malformed)
        );
        assert_eq!(
            store.record_json(&frame("trace", "message"), 1, ""),
            Err(LogRecordError::UnsupportedLevel)
        );
        assert_eq!(
            store.record_json(&vec![b'x'; MAX_LOG_FRAME_BYTES + 1], 1, ""),
            Err(LogRecordError::InvalidFrameSize)
        );
    }

    #[test]
    fn messages_are_truncated_on_utf8_boundaries() {
        let mut store = MihomoLogStore::default();
        store.reset("generation-a");
        store
            .record_json(&frame("debug", &"界".repeat(500)), 1, "")
            .unwrap();
        let item = &store.page(0, 1).items[0];
        assert!(item.truncated);
        assert!(item.message.len() <= MAX_LOG_MESSAGE_BYTES);
        assert!(std::str::from_utf8(item.message.as_bytes()).is_ok());
    }

    #[test]
    fn maximum_page_remains_within_the_protocol_frame_limit() {
        let mut store = MihomoLogStore::default();
        store.reset("generation-a");
        for index in 0..crate::protocol::MAX_MIHOMO_LOG_PAGE_SIZE {
            store
                .record_json(
                    &frame("info", &"\\\"".repeat(MAX_LOG_MESSAGE_BYTES)),
                    u64::from(index),
                    "",
                )
                .unwrap();
        }
        let encoded =
            serde_json::to_vec(&store.page(0, crate::protocol::MAX_MIHOMO_LOG_PAGE_SIZE)).unwrap();
        assert!(encoded.len() < crate::protocol::MAX_FRAME_BYTES);
    }
}
