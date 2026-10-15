use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::protocol::{
    ConnectionPage, ConnectionState, ConnectionView, TrafficSnapshot, MAX_CONNECTION_PAGE_SIZE,
};
use tunbridge_core::engine::{self, EngineConnection, EngineSnapshot};
use zeroize::Zeroizing;

use super::{
    load_owned_engine, process::query_process_working_set, random::random_hex_32,
    OwnedEngineRecord, OwnedEngineStage, ProtectedDataDirectory,
};

const TRAFFIC_SCHEMA_VERSION: u16 = 1;
const CONTROLLER_TIMEOUT: Duration = Duration::from_millis(500);
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
const MAX_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const CONNECTION_SCHEMA_VERSION: u16 = 1;
const MAX_CLOSED_CONNECTIONS: usize = 500;
const MAX_EXPOSED_CHAINS: usize = 8;
const CONNECTION_CACHE_MAX_AGE: Duration = Duration::from_millis(1_250);

#[derive(Default)]
pub(super) struct LocalObservabilityState {
    generation_key: Option<(u32, u64)>,
    generation: String,
    sequence: u64,
    previous: Option<PreviousSample>,
    last_observed_at: Option<Instant>,
    active: Vec<ConnectionView>,
    closed: VecDeque<ConnectionView>,
}

struct PreviousSample {
    sampled_at: Instant,
    upload_total: u64,
    download_total: u64,
    connection_totals: HashMap<String, (u64, u64)>,
}

impl LocalObservabilityState {
    pub(super) fn sample(&mut self) -> Result<TrafficSnapshot, ObservabilityError> {
        self.fetch_and_observe()
    }

    pub(super) fn connections_page(
        &mut self,
        state: ConnectionState,
        offset: u32,
        limit: u16,
    ) -> Result<ConnectionPage, ObservabilityError> {
        debug_assert!((1..=MAX_CONNECTION_PAGE_SIZE).contains(&limit));
        let cache_is_fresh = self
            .last_observed_at
            .is_some_and(|sampled_at| sampled_at.elapsed() <= CONNECTION_CACHE_MAX_AGE);
        if !cache_is_fresh {
            self.fetch_and_observe()?;
        }
        let offset_usize = offset as usize;
        let limit_usize = limit as usize;
        let (total, items) = match state {
            ConnectionState::Active => (
                self.active.len(),
                self.active
                    .iter()
                    .skip(offset_usize)
                    .take(limit_usize)
                    .cloned()
                    .collect(),
            ),
            ConnectionState::Closed => (
                self.closed.len(),
                self.closed
                    .iter()
                    .skip(offset_usize)
                    .take(limit_usize)
                    .cloned()
                    .collect(),
            ),
        };
        Ok(ConnectionPage {
            schema_version: CONNECTION_SCHEMA_VERSION,
            engine_generation: self.generation.clone(),
            sequence: self.sequence,
            state,
            offset,
            limit,
            total: total.min(u32::MAX as usize) as u32,
            items,
        })
    }

    fn fetch_and_observe(&mut self) -> Result<TrafficSnapshot, ObservabilityError> {
        let (record, controller, secret) = owned_controller()?;
        let mut snapshot = engine::rest_engine_snapshot(&controller, &secret, CONTROLLER_TIMEOUT)
            .map_err(ObservabilityError::Controller)?;
        snapshot.memory_bytes = query_process_working_set(record.pid, record.creation_time)
            .map_err(ObservabilityError::Process)?;
        self.observe(&record, snapshot, Instant::now(), SystemTime::now(), || {
            random_hex_32().map_err(ObservabilityError::Random)
        })
    }

    pub(super) fn close_connection(
        &mut self,
        connection_id: &str,
    ) -> Result<u32, ObservabilityError> {
        self.fetch_and_observe()?;
        if !self
            .active
            .iter()
            .any(|connection| connection.id == connection_id)
        {
            return Err(ObservabilityError::ConnectionNotFound);
        }
        let (_, controller, secret) = owned_controller()?;
        engine::close_engine_connection(&controller, &secret, connection_id, CONTROLLER_TIMEOUT)
            .map_err(ObservabilityError::Controller)?;
        Ok(1)
    }

    pub(super) fn close_all_connections(&mut self) -> Result<u32, ObservabilityError> {
        self.fetch_and_observe()?;
        let count = self.active.len().min(u32::MAX as usize) as u32;
        let (_, controller, secret) = owned_controller()?;
        engine::close_all_engine_connections(&controller, &secret, CONTROLLER_TIMEOUT)
            .map_err(ObservabilityError::Controller)?;
        Ok(count)
    }

    fn observe(
        &mut self,
        record: &OwnedEngineRecord,
        snapshot: EngineSnapshot,
        sampled_at: Instant,
        wall_clock: SystemTime,
        generation_factory: impl FnOnce() -> Result<String, ObservabilityError>,
    ) -> Result<TrafficSnapshot, ObservabilityError> {
        let key = (record.pid, record.creation_time);
        if self.generation_key != Some(key) {
            self.generation_key = Some(key);
            self.generation = generation_factory()?;
            self.sequence = 0;
            self.previous = None;
            self.last_observed_at = None;
            self.active.clear();
            self.closed.clear();
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ObservabilityError::SequenceOverflow)?;

        let mut upload_bps = 0;
        let mut download_bps = 0;
        let mut interval_ms = 0;
        let sampled_at_unix_ms = wall_clock
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ObservabilityError::Clock)?
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let mut connection_rates = HashMap::new();
        if let Some(previous) = &self.previous {
            let elapsed = sampled_at.saturating_duration_since(previous.sampled_at);
            if (MIN_SAMPLE_INTERVAL..=MAX_SAMPLE_INTERVAL).contains(&elapsed)
                && snapshot.upload_total >= previous.upload_total
                && snapshot.download_total >= previous.download_total
            {
                interval_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;
                upload_bps =
                    bytes_per_second(snapshot.upload_total - previous.upload_total, elapsed);
                download_bps =
                    bytes_per_second(snapshot.download_total - previous.download_total, elapsed);
                for connection in &snapshot.connections {
                    if let Some((previous_upload, previous_download)) =
                        previous.connection_totals.get(&connection.id)
                    {
                        if connection.upload_total >= *previous_upload
                            && connection.download_total >= *previous_download
                        {
                            connection_rates.insert(
                                connection.id.as_str(),
                                (
                                    bytes_per_second(
                                        connection.upload_total - previous_upload,
                                        elapsed,
                                    ),
                                    bytes_per_second(
                                        connection.download_total - previous_download,
                                        elapsed,
                                    ),
                                ),
                            );
                        }
                    }
                }
            }
        }
        let current_ids = snapshot
            .connections
            .iter()
            .map(|connection| connection.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        for mut connection in std::mem::take(&mut self.active) {
            if !current_ids.contains(connection.id.as_str()) {
                connection.upload_bps = 0;
                connection.download_bps = 0;
                connection.closed_at_unix_ms = Some(sampled_at_unix_ms);
                self.closed.push_front(connection);
            }
        }
        self.closed.truncate(MAX_CLOSED_CONNECTIONS);
        self.active = snapshot
            .connections
            .iter()
            .map(|connection| {
                let (connection_upload_bps, connection_download_bps) = connection_rates
                    .get(connection.id.as_str())
                    .copied()
                    .unwrap_or_default();
                connection_view(connection, connection_upload_bps, connection_download_bps)
            })
            .collect();
        self.active.sort_by(|left, right| {
            (right.download_bps + right.upload_bps)
                .cmp(&(left.download_bps + left.upload_bps))
                .then_with(|| left.host.cmp(&right.host))
        });
        self.previous = Some(PreviousSample {
            sampled_at,
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
            connection_totals: snapshot
                .connections
                .iter()
                .map(|connection| {
                    (
                        connection.id.clone(),
                        (connection.upload_total, connection.download_total),
                    )
                })
                .collect(),
        });
        self.last_observed_at = Some(sampled_at);
        Ok(TrafficSnapshot {
            schema_version: TRAFFIC_SCHEMA_VERSION,
            engine_generation: self.generation.clone(),
            sequence: self.sequence,
            sampled_at_unix_ms,
            interval_ms,
            upload_bps,
            download_bps,
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
            active_connections: snapshot.connections.len() as u32,
            memory_bytes: snapshot.memory_bytes,
            stale: false,
        })
    }
}

fn owned_controller() -> Result<(OwnedEngineRecord, String, Zeroizing<String>), ObservabilityError>
{
    let record = load_owned_engine()
        .map_err(ObservabilityError::Owned)?
        .filter(|record| record.stage == OwnedEngineStage::Running)
        .ok_or(ObservabilityError::NotRunning)?;
    let config = ProtectedDataDirectory::prepare()
        .map_err(ObservabilityError::Storage)?
        .read_active_config()
        .map_err(ObservabilityError::Storage)?;
    let secret = controller_secret(&config)?;
    let controller = format!("{}:{}", record.controller_host, record.controller_port);
    Ok((record, controller, secret))
}

#[cfg(feature = "production-mihomo-logs-v4")]
type OwnedLogSessionParts = ((u32, u64), SocketAddr, Zeroizing<String>);

#[cfg(feature = "production-mihomo-logs-v4")]
pub(super) fn owned_log_session_parts() -> Result<OwnedLogSessionParts, ObservabilityError> {
    let (record, controller, secret) = owned_controller()?;
    super::verify_owned_engine(&record).map_err(ObservabilityError::Owned)?;
    super::verify_loopback_listener_owner(
        &record.controller_host,
        record.controller_port,
        record.pid,
    )
    .map_err(|error| {
        ObservabilityError::Owned(super::OwnedEngineError::ControllerIdentity(error))
    })?;
    let controller = controller
        .parse()
        .map_err(|_| ObservabilityError::MissingSecret)?;
    Ok(((record.pid, record.creation_time), controller, secret))
}

fn connection_view(
    connection: &EngineConnection,
    upload_bps: u64,
    download_bps: u64,
) -> ConnectionView {
    ConnectionView {
        id: connection.id.clone(),
        host: connection.host.clone(),
        network: connection.network.clone(),
        connection_type: connection.connection_type.clone(),
        source: connection.source.clone(),
        destination: connection.destination.clone(),
        process_name: connection.process_name.clone(),
        chains: connection
            .chains
            .iter()
            .take(MAX_EXPOSED_CHAINS)
            .cloned()
            .collect(),
        rule: connection.rule.clone(),
        rule_payload: connection.rule_payload.clone(),
        upload_total: connection.upload_total,
        download_total: connection.download_total,
        upload_bps,
        download_bps,
        started_at: connection.started_at.clone(),
        closed_at_unix_ms: None,
    }
}

fn controller_secret(config: &str) -> Result<Zeroizing<String>, ObservabilityError> {
    let config: serde_yaml::Value =
        serde_yaml::from_str(config).map_err(ObservabilityError::Config)?;
    let secret = config
        .get("secret")
        .and_then(serde_yaml::Value::as_str)
        .ok_or(ObservabilityError::MissingSecret)?;
    if secret.len() != 64
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ObservabilityError::MissingSecret);
    }
    Ok(Zeroizing::new(secret.to_string()))
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let millis = elapsed.as_millis().max(1);
    ((bytes as u128).saturating_mul(1_000) / millis).min(u64::MAX as u128) as u64
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ObservabilityError {
    #[error("TunBridge is not running")]
    NotRunning,
    #[error("owned engine identity is unavailable: {0}")]
    Owned(#[source] super::OwnedEngineError),
    #[error("protected runtime storage is unavailable: {0}")]
    Storage(#[source] super::StorageError),
    #[error("active config is invalid: {0}")]
    Config(#[source] serde_yaml::Error),
    #[error("active config does not contain a valid controller secret")]
    MissingSecret,
    #[error("engine controller snapshot is unavailable: {0}")]
    Controller(#[source] tunbridge_core::CoreError),
    #[error("owned engine memory observation failed: {0}")]
    Process(#[source] super::process::ProcessIdentityError),
    #[error("connection does not exist in the current owned engine snapshot")]
    ConnectionNotFound,
    #[error("Windows CSPRNG failed: {0}")]
    Random(#[source] std::io::Error),
    #[error("traffic sample sequence overflowed")]
    SequenceOverflow,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UpstreamProtocol;
    use std::path::PathBuf;
    use tunbridge_core::engine::EngineConnection;

    fn record(pid: u32, creation_time: u64) -> OwnedEngineRecord {
        OwnedEngineRecord {
            schema_version: 3,
            product_version: env!("CARGO_PKG_VERSION").into(),
            stage: OwnedEngineStage::Running,
            pid,
            creation_time,
            image_path: PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe"),
            engine_version: "v1.19.28".into(),
            engine_sha256: "a".repeat(64),
            owner_principal_id: "S-1-5-21-test".into(),
            owner_session_id: 1,
            upstream_host: "127.0.0.1".into(),
            upstream_port: 7078,
            upstream_protocol: UpstreamProtocol::Socks5,
            remote_upstream: false,
            upstream_pid: 2,
            upstream_creation_time: 3,
            upstream_image_path: PathBuf::from(r"C:\Proxy\client.exe"),
            controller_host: "127.0.0.1".into(),
            controller_port: 25412,
            adapter_alias: "tunbridge".into(),
            preexisting_wintun_instances: Vec::new(),
            adapter_instance_id: Some(r"SWD\WINTUN\{11111111-1111-1111-1111-111111111111}".into()),
        }
    }

    fn snapshot(upload: u64, download: u64) -> EngineSnapshot {
        EngineSnapshot {
            upload_total: upload,
            download_total: download,
            memory_bytes: 64,
            connections: Vec::new(),
        }
    }

    fn snapshot_with_connection(
        upload: u64,
        download: u64,
        connection_upload: u64,
        connection_download: u64,
    ) -> EngineSnapshot {
        EngineSnapshot {
            upload_total: upload,
            download_total: download,
            memory_bytes: 64,
            connections: vec![EngineConnection {
                id: "connection-a".into(),
                host: "example.com:443".into(),
                network: "tcp".into(),
                connection_type: "TUN".into(),
                source: "198.18.0.1:50000".into(),
                destination: "1.1.1.1:443".into(),
                process_name: Some("browser.exe".into()),
                chains: vec!["Proxy".into()],
                rule: "DomainSuffix".into(),
                rule_payload: Some("example.com".into()),
                upload_total: connection_upload,
                download_total: connection_download,
                started_at: "2026-07-25T12:00:00Z".into(),
            }],
        }
    }

    #[test]
    fn computes_real_rates_and_resets_on_generation_change() {
        let base = Instant::now();
        let wall = UNIX_EPOCH + Duration::from_secs(100);
        let mut state = LocalObservabilityState::default();
        let first = state
            .observe(&record(10, 20), snapshot(100, 200), base, wall, || {
                Ok("generation-a".into())
            })
            .unwrap();
        assert_eq!(first.upload_bps, 0);
        assert_eq!(first.sequence, 1);

        let second = state
            .observe(
                &record(10, 20),
                snapshot(1_100, 2_200),
                base + Duration::from_secs(1),
                wall + Duration::from_secs(1),
                || panic!("same engine must not create a generation"),
            )
            .unwrap();
        assert_eq!(second.upload_bps, 1_000);
        assert_eq!(second.download_bps, 2_000);
        assert_eq!(second.sequence, 2);

        let restarted = state
            .observe(
                &record(11, 21),
                snapshot(5, 7),
                base + Duration::from_secs(2),
                wall + Duration::from_secs(2),
                || Ok("generation-b".into()),
            )
            .unwrap();
        assert_eq!(restarted.engine_generation, "generation-b");
        assert_eq!(restarted.sequence, 1);
        assert_eq!(restarted.upload_bps, 0);
        assert_eq!(restarted.download_bps, 0);
    }

    #[test]
    fn counter_rollback_and_long_gap_do_not_produce_false_rates() {
        let base = Instant::now();
        let wall = UNIX_EPOCH;
        let mut state = LocalObservabilityState::default();
        state
            .observe(&record(1, 1), snapshot(100, 100), base, wall, || {
                Ok("generation".into())
            })
            .unwrap();
        let rollback = state
            .observe(
                &record(1, 1),
                snapshot(10, 10),
                base + Duration::from_secs(1),
                wall + Duration::from_secs(1),
                || unreachable!(),
            )
            .unwrap();
        assert_eq!((rollback.upload_bps, rollback.download_bps), (0, 0));
        let late = state
            .observe(
                &record(1, 1),
                snapshot(1_000, 1_000),
                base + Duration::from_secs(10),
                wall + Duration::from_secs(10),
                || unreachable!(),
            )
            .unwrap();
        assert_eq!((late.upload_bps, late.download_bps), (0, 0));
    }

    #[test]
    fn connection_rates_are_real_and_disappearing_rows_move_to_closed_history() {
        let base = Instant::now();
        let wall = UNIX_EPOCH + Duration::from_secs(100);
        let mut state = LocalObservabilityState::default();
        state
            .observe(
                &record(1, 1),
                snapshot_with_connection(10, 20, 100, 200),
                base,
                wall,
                || Ok("generation".into()),
            )
            .unwrap();
        state
            .observe(
                &record(1, 1),
                snapshot_with_connection(20, 40, 1_100, 2_200),
                base + Duration::from_secs(1),
                wall + Duration::from_secs(1),
                || unreachable!(),
            )
            .unwrap();
        assert_eq!(state.active[0].upload_bps, 1_000);
        assert_eq!(state.active[0].download_bps, 2_000);
        assert!(state.active[0].closed_at_unix_ms.is_none());

        state
            .observe(
                &record(1, 1),
                snapshot(20, 40),
                base + Duration::from_secs(2),
                wall + Duration::from_secs(2),
                || unreachable!(),
            )
            .unwrap();
        assert!(state.active.is_empty());
        assert_eq!(state.closed.len(), 1);
        assert_eq!(state.closed[0].closed_at_unix_ms, Some(102_000));
        assert_eq!(
            (state.closed[0].upload_bps, state.closed[0].download_bps),
            (0, 0)
        );
    }

    #[test]
    fn secret_parser_requires_exact_lower_hex_and_redacts_debug() {
        let secret = "a".repeat(64);
        assert_eq!(
            controller_secret(&format!("secret: {secret}"))
                .unwrap()
                .as_str(),
            secret
        );
        assert!(controller_secret("secret: BAD").is_err());
    }
}
