use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tunbridge_core::{
    config, config_v2,
    net::{httpconnect, socks5},
    probe::{DEFAULT_TEST_HOST, DEFAULT_TEST_PORT},
    profile::{Profile, Protocol, Upstream},
    remote::{preflight_pinned_tcp, resolve_endpoint_system},
    upstream::StandardProtocol,
};
use tunbridge_service::{
    mihomo_logs::MihomoLogSession,
    protocol::{ErrorCode, StartProfile, StartProfileV3, StartUpstreamV3, UpstreamProtocol},
    state::Caller,
    watchdog::{HealthSignal, RuntimeObservation},
};
use zeroize::Zeroizing;

pub const ENGINE_PATH: &str = "/usr/libexec/tunbridge/mihomo";
pub const DATA_ROOT: &str = "/var/lib/tunbridge";
pub const TUN_DEVICE: &str = "tunbridge";
const ENGINE_MANIFEST: &str = "/usr/share/tunbridge/engine-manifest.json";
const ACTIVE_CONFIG: &str = "active-config.yaml";
const OWNED_STATE: &str = "owned-engine.json";
const ROUTE_ESCAPE_STATE: &str = "route-escape.json";
const CONFIG_LIMIT: usize = 256 * 1024;
const STATE_LIMIT: usize = 64 * 1024;
const CONFIG_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const START_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPSTREAM_PROCESS_FAMILY: usize = 64;
const MAX_TRANSPORT_ESCAPE_ADDRESSES: usize = 32;
const LOCAL_TRANSPORT_PROBE_TIMEOUT: Duration = Duration::from_secs(6);
const ROUTE_ESCAPE_MARK: &str = "0x5442";
const ROUTE_ESCAPE_PRIORITY: &str = "8999";
const ROUTE_ESCAPE_TABLE: &str = "tunbridge_route_escape";
/// The traffic lock: while it exists, only the tunnel, the engine and the
/// escaped proxy client may send through a physical interface. It outlives
/// the engine and this service and is removed only by an explicit user stop.
const TRAFFIC_LOCK_TABLE: &str = "tunbridge_lock";
const TRAFFIC_LOCK_CHAIN: &str = "egress";
const TRAFFIC_LOCK_LOCAL_V4: &str =
    "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }";
const TRAFFIC_LOCK_LOCAL_V6: &str = "{ fe80::/10, fc00::/7, ff00::/8 }";
const ROUTE_ESCAPE_CHAIN: &str = "output";
const ROUTE_ESCAPE_NAT_CHAIN: &str = "postrouting";
/// Escaped upstream flows to a fake IP (from the system resolver, which is
/// not escaped) are routed back into Mihomo's auto-route table.
const ROUTE_ESCAPE_FAKE_IP_PRIORITY: &str = "8998";
/// Mihomo's `fake-ip-range` and default `iproute2-table-index`.
const FAKE_IP_RANGE_V4: &str = "198.18.0.0/15";
const MIHOMO_ROUTE_TABLE: &str = "2022";
/// RFC 7600 IPv4 dummy address. Escaped fake-IP flows are rewritten to this
/// source so Mihomo can send exactly them DIRECT without process lookups.
const ESCAPED_FAKE_IP_SOURCE: &str = "192.0.0.8";
/// Mihomo's default TUN addresses (the generated config does not override
/// them). An unbound upstream socket takes one of these as its source on the
/// first route lookup, before the cgroup mark re-routes it to the main table.
const TUN_SOURCE_PREFIX_V4: &str = "198.18.0.0/15";
const TUN_SOURCE_PREFIX_V6: &str = "fdfe:dcba:9876::/48";
const ROUTE_ESCAPE_SCOPE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_UPSTREAM_EXE_PATH_BYTES: usize = 4096;
/// Parent hops searched for the AppImage runtime that launched an upstream.
const MAX_LAUNCHER_HOPS: usize = 8;
/// Descriptors inspected per process when looking for the FUSE session fd.
const MAX_LAUNCHER_FD_SCAN: usize = 4096;
const FUSE_DEVICE: &str = "/dev/fuse";
/// Diagnostic of a recorded local upstream that exited with no listener left.
const UPSTREAM_EXITED: &str = "upstream_exited";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleFailure {
    pub code: ErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
}

impl LifecycleFailure {
    const fn new(code: ErrorCode, safe_message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            safe_message,
            retryable,
        }
    }

    const fn internal() -> Self {
        Self::new(
            ErrorCode::InternalError,
            "The privileged Linux lifecycle operation failed safely.",
            false,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedEngineRecord {
    schema_version: u16,
    stage: OwnedStage,
    owner_uid: u32,
    engine_pid: u32,
    engine_start_time: u64,
    engine_exe_dev: u64,
    engine_exe_ino: u64,
    upstream_pid: u32,
    upstream_port: u16,
    upstream_start_time: u64,
    upstream_exe_dev: u64,
    upstream_exe_ino: u64,
    /// Exact `/proc/<pid>/exe` path of the verified local upstream. It only
    /// authorizes rebinding a restarted client from the same executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_exe_path: Option<String>,
    /// Stable kernel-reported executable that launches the local upstream:
    /// the AppImage runtime for an upstream inside an AppImage mount, else the
    /// upstream executable itself. It survives the random AppImage mount path
    /// of a restart and only authorizes adopting or rebinding that client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_launcher_path: Option<String>,
    /// Set when the active transport scope is named after a restarted client
    /// process (adopted before its listener returned) instead of the recorded
    /// upstream. `local_route_escape` then names exactly this process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adopted_scope_root: Option<ScopeRoot>,
    #[serde(default)]
    remote_upstream: bool,
    #[serde(default)]
    local_transport_escape: Vec<IpAddr>,
    #[serde(default)]
    local_route_escape: Option<LocalRouteEscape>,
    tun_ifindex: Option<u32>,
    controller_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalRouteEscape {
    schema_version: u16,
    stage: RouteEscapeStage,
    owner_uid: u32,
    upstream_pid: u32,
    upstream_start_time: u64,
    scope_unit: String,
    scope_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopeRoot {
    pid: u32,
    start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RouteEscapeStage {
    Planned,
    Installing,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteEscapeCleanupMode {
    AllowAbsent,
    RequirePresent,
}

impl RouteEscapeCleanupMode {
    const fn requires_presence(self) -> bool {
        matches!(self, Self::RequirePresent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedStage {
    Pending,
    Running,
}

#[derive(Debug, Clone)]
struct ProcessIdentity {
    pid: u32,
    uid: u32,
    start_time: u64,
    exe_dev: u64,
    exe_ino: u64,
    exe_path: PathBuf,
}

#[derive(Debug, Clone)]
struct VerifiedRuntimeUpstream {
    identity: ProcessIdentity,
    process_family: Option<ProcessFamily>,
    transport_escape_addresses: Vec<IpAddr>,
    pinned_remote: Option<std::net::IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessFamily {
    pids: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SocketEndpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Debug)]
struct ProcessFamilyEntry {
    pid: u32,
    parent_pid: u32,
    uid: u32,
    process_path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EngineManifest {
    schema_version: u16,
    version: String,
    asset_name: String,
    binary_size: u64,
    binary_sha256: String,
}

pub struct LinuxLifecycle {
    engine: PathBuf,
    data_root: PathBuf,
}

impl LinuxLifecycle {
    pub fn system() -> Self {
        Self {
            engine: ENGINE_PATH.into(),
            data_root: DATA_ROOT.into(),
        }
    }

    pub fn initial_record(&self) -> Result<Option<OwnedEngineRecord>, LifecycleFailure> {
        self.prepare_data_root()?;
        let record = self.read_record()?;
        let route_escape = self.read_route_escape()?;
        match (&record, &route_escape) {
            (None, None) => {}
            (Some(record), Some(route_escape))
                if record.local_route_escape.as_ref() == Some(route_escape) => {}
            (Some(record), Some(route_escape))
                if record.local_route_escape.as_ref().is_some_and(|recorded| {
                    interrupted_upstream_rebind(recorded, route_escape)
                }) =>
            {
                // A crash between the two journal writes of an upstream
                // rebind. Both generations name the same fixed nftables table
                // and policy rules; the owned record is authoritative.
                if let Some(recorded) = &record.local_route_escape {
                    self.write_route_escape(recorded)?;
                }
            }
            (Some(record), None) if record.local_route_escape.is_none() => {}
            (None, Some(route_escape)) => {
                self.remove_local_route_escape(route_escape, RouteEscapeCleanupMode::AllowAbsent)?;
            }
            _ => return Err(LifecycleFailure::internal()),
        }
        Ok(record)
    }

    pub fn start(&self, profile: &StartProfileV3, caller: &Caller) -> Result<(), LifecycleFailure> {
        profile.validate().map_err(|_| invalid_profile())?;
        let caller_uid = caller_uid(caller)?;
        if self.read_record()?.is_some() {
            return Err(LifecycleFailure::new(
                ErrorCode::RecoveryRequired,
                "A previous owned Linux engine record requires recovery.",
                false,
            ));
        }
        self.validate_engine()?;
        self.prepare_data_root()?;
        if interface_index(TUN_DEVICE)?.is_some() {
            return Err(LifecycleFailure::new(
                ErrorCode::OwnedProcessMismatch,
                "A pre-existing TunBridge interface blocks startup.",
                false,
            ));
        }
        let upstream = verify_upstream(profile, caller_uid)?;
        let controller_secret = random_hex_32()?;
        let yaml = render_config(profile, &upstream, &controller_secret)?;
        let candidate = self.write_candidate(&yaml)?;
        if let Err(error) = self.validate_config(&candidate) {
            let _ = fs::remove_file(&candidate);
            return Err(error);
        }
        let active = self.promote_candidate(&candidate)?;
        let local_route_escape = if upstream.pinned_remote.is_none() {
            match self.install_local_route_escape(&upstream, caller_uid) {
                Ok(route_escape) => Some(route_escape),
                Err(error) => {
                    let _ = self.remove_inactive_config();
                    return Err(error);
                }
            }
        } else {
            None
        };
        let mut child = match Command::new(&self.engine)
            .args(["-f"])
            .arg(&active)
            .arg("-d")
            .arg(&self.data_root)
            .current_dir(&self.data_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                if let Some(route_escape) = &local_route_escape {
                    let _ = self.remove_local_route_escape(
                        route_escape,
                        RouteEscapeCleanupMode::AllowAbsent,
                    );
                }
                let _ = self.remove_inactive_config();
                return Err(LifecycleFailure::new(
                    ErrorCode::ConfigValidationFailed,
                    "The controlled Linux engine could not start.",
                    true,
                ));
            }
        };
        let engine = match process_identity(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(route_escape) = &local_route_escape {
                    let _ = self.remove_local_route_escape(
                        route_escape,
                        RouteEscapeCleanupMode::AllowAbsent,
                    );
                }
                let _ = self.remove_inactive_config();
                return Err(error);
            }
        };
        if engine.uid != 0
            || engine.exe_dev
                != fs::metadata(&self.engine)
                    .map_err(|_| engine_integrity())?
                    .dev()
            || engine.exe_ino
                != fs::metadata(&self.engine)
                    .map_err(|_| engine_integrity())?
                    .ino()
        {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(route_escape) = &local_route_escape {
                let _ = self
                    .remove_local_route_escape(route_escape, RouteEscapeCleanupMode::AllowAbsent);
            }
            let _ = self.remove_inactive_config();
            return Err(engine_integrity());
        }
        let mut record = OwnedEngineRecord {
            schema_version: 4,
            stage: OwnedStage::Pending,
            owner_uid: caller_uid,
            engine_pid: engine.pid,
            engine_start_time: engine.start_time,
            engine_exe_dev: engine.exe_dev,
            engine_exe_ino: engine.exe_ino,
            upstream_pid: upstream.identity.pid,
            upstream_port: profile.upstream.port(),
            upstream_start_time: upstream.identity.start_time,
            upstream_exe_dev: upstream.identity.exe_dev,
            upstream_exe_ino: upstream.identity.exe_ino,
            upstream_exe_path: if upstream.pinned_remote.is_none() {
                recordable_exe_path(&upstream.identity.exe_path)
            } else {
                None
            },
            upstream_launcher_path: if upstream.pinned_remote.is_none() {
                upstream_launcher_path(&upstream.identity)
            } else {
                None
            },
            adopted_scope_root: None,
            remote_upstream: upstream.pinned_remote.is_some(),
            local_transport_escape: upstream.transport_escape_addresses.clone(),
            local_route_escape,
            tun_ifindex: None,
            controller_secret,
        };
        if let Err(error) = self.write_record(&record) {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(route_escape) = &record.local_route_escape {
                let _ = self
                    .remove_local_route_escape(route_escape, RouteEscapeCleanupMode::AllowAbsent);
            }
            let _ = self.remove_inactive_config();
            return Err(error);
        }

        let deadline = Instant::now() + START_TIMEOUT;
        let mut saw_tun = false;
        let mut saw_controller = false;
        let tun_ifindex = loop {
            if child
                .try_wait()
                .map_err(|_| LifecycleFailure::internal())?
                .is_some()
            {
                return self.rollback_failed_start(&record);
            }
            if let Some(index) = interface_index(TUN_DEVICE)? {
                saw_tun = true;
                saw_controller = controller_ready(&record.controller_secret);
                if saw_controller {
                    break index;
                }
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "TunBridge Linux readiness timeout (tun={saw_tun}, controller={saw_controller})"
                );
                return self.rollback_failed_start(&record);
            }
            thread::sleep(Duration::from_millis(100));
        };
        record.tun_ifindex = Some(tun_ifindex);
        record.stage = OwnedStage::Running;
        self.write_record(&record)?;
        Ok(())
    }

    pub fn stop(&self) -> Result<(), LifecycleFailure> {
        let Some(record) = self.read_record()? else {
            return Err(LifecycleFailure::new(
                ErrorCode::NotRunning,
                "TunBridge is not running.",
                true,
            ));
        };
        self.stop_record(&record)
    }

    pub fn recover(&self) -> Result<(), LifecycleFailure> {
        match self.read_record()? {
            Some(record) => self.stop_record(&record),
            None => {
                if interface_index(TUN_DEVICE)?.is_some() {
                    Err(LifecycleFailure::new(
                        ErrorCode::OwnedProcessMismatch,
                        "An unowned TunBridge interface was preserved.",
                        false,
                    ))
                } else {
                    if let Some(route_escape) = self.read_route_escape()? {
                        self.remove_local_route_escape(
                            &route_escape,
                            RouteEscapeCleanupMode::AllowAbsent,
                        )?;
                    }
                    self.remove_inactive_config()?;
                    Ok(())
                }
            }
        }
    }

    pub fn record_is_running(&self, record: &OwnedEngineRecord) -> Result<bool, LifecycleFailure> {
        let Ok(actual) = process_identity(record.engine_pid) else {
            eprintln!("TunBridge Linux runtime unhealthy: engine_identity");
            return Ok(false);
        };
        if actual.start_time != record.engine_start_time
            || actual.exe_dev != record.engine_exe_dev
            || actual.exe_ino != record.engine_exe_ino
            || actual.uid != 0
        {
            eprintln!("TunBridge Linux runtime unhealthy: engine_provenance");
            return Ok(false);
        }
        if interface_index(TUN_DEVICE)? != record.tun_ifindex {
            eprintln!("TunBridge Linux runtime unhealthy: tun_identity");
            return Ok(false);
        }
        if record.stage != OwnedStage::Running {
            eprintln!("TunBridge Linux runtime unhealthy: record_stage");
            return Ok(false);
        }
        Ok(true)
    }

    /// Installs (or atomically replaces) the traffic lock. Nothing may leave a
    /// physical interface except the tunnel's own traffic, LAN traffic and
    /// replies to inbound connections, so a socket bound to the physical
    /// interface or its address can no longer bypass the tunnel.
    pub fn install_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        let service_cgroup =
            process_cgroup(std::process::id()).ok_or_else(route_escape_unavailable)?;
        // The proxy client's escape scope is let through by its cgroup too,
        // not only by the mark: an engine restart removes the mark rule with
        // the old session, and the client must still reach its servers while
        // the new session verifies it.
        let escape_scope = self
            .read_record()?
            .and_then(|record| record.local_route_escape)
            .map(|escape| escape.scope_path);
        let arguments = traffic_lock_arguments(&service_cgroup, escape_scope.as_deref())
            .ok_or_else(route_escape_unavailable)?;
        if system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)? {
            Ok(())
        } else {
            Err(route_escape_unavailable())
        }
    }

    /// Removes the traffic lock. Only an explicit user stop, recovery or
    /// package removal calls this; traffic then goes directly again.
    pub fn remove_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        if !self.traffic_lock_present()? {
            return Ok(());
        }
        let arguments = strings(&["delete", "table", "inet", TRAFFIC_LOCK_TABLE]);
        if system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)? {
            Ok(())
        } else {
            Err(route_escape_unavailable())
        }
    }

    pub fn traffic_lock_present(&self) -> Result<bool, LifecycleFailure> {
        let arguments = strings(&["list", "table", "inet", TRAFFIC_LOCK_TABLE]);
        system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)
    }

    pub fn owner_uid(record: &OwnedEngineRecord) -> u32 {
        record.owner_uid
    }

    pub(crate) fn engine_generation(&self) -> Result<String, LifecycleFailure> {
        let record = self.read_record()?.ok_or_else(not_running)?;
        if !self.record_is_running(&record)? {
            return Err(not_running());
        }
        let digest = Sha256::digest(format!(
            "{}:{}:{}:{}",
            record.engine_pid,
            record.engine_start_time,
            record.engine_exe_dev,
            record.engine_exe_ino
        ));
        Ok(format!("{digest:x}"))
    }

    pub(crate) fn mihomo_log_session(&self) -> Result<MihomoLogSession, LifecycleFailure> {
        const CONTROLLER_PORT: u16 = 25_412;
        let record = self.read_record()?.ok_or_else(not_running)?;
        if !self.record_is_running(&record)?
            || !process_owns_listener(record.engine_pid, CONTROLLER_PORT)?
            || !controller_ready(&record.controller_secret)
        {
            return Err(observability_unavailable());
        }
        MihomoLogSession::new(
            self.engine_generation()?,
            "127.0.0.1:25412"
                .parse()
                .map_err(|_| LifecycleFailure::internal())?,
            Zeroizing::new(record.controller_secret.clone()),
        )
        .map_err(|_| observability_unavailable())
    }

    /// Samples the owned runtime as classified watchdog signals. The shared
    /// `WatchdogPolicy` owns hysteresis; this function performs no mutation.
    ///
    /// A procfs or interface read that cannot prove identity is `Unknown`,
    /// never `Unhealthy`, so a transient read error cannot tear the tunnel
    /// down. Only engine, adapter and controller failures can converge; every
    /// upstream-only failure keeps the TUN in place so traffic fails closed.
    pub(crate) fn sample_runtime(&self) -> RuntimeSample {
        let record = match self.read_record() {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => return RuntimeSample::unknown("owned_record"),
        };
        let (engine, engine_detail) = sample_engine(&record);
        let (adapter, adapter_detail) =
            classify_adapter(record.tun_ifindex, interface_index(TUN_DEVICE));
        let (upstream, upstream_detail) = if record.remote_upstream {
            (UpstreamSample::Signal(HealthSignal::Healthy), None)
        } else {
            sample_local_upstream(&record)
        };
        let controller = if controller_ready(&record.controller_secret) {
            HealthSignal::Healthy
        } else {
            HealthSignal::Unhealthy
        };
        let controller_detail = (controller != HealthSignal::Healthy).then_some("controller");
        // Only an exited recorded client with no listener left may have a
        // restarted instance that needs its transport escape before it can
        // reopen the listener (for example, to log in first).
        let probe_restarted_client = !record.remote_upstream
            && record.local_route_escape.is_some()
            && record.upstream_launcher_path.is_some()
            && upstream == UpstreamSample::Signal(HealthSignal::Unhealthy)
            && upstream_detail == Some(UPSTREAM_EXITED);
        let (upstream, restarted_upstream) = match upstream {
            UpstreamSample::Signal(signal) => (signal, None),
            // Healthy only after the caller has persisted the rebind.
            UpstreamSample::Restarted(restarted) => (HealthSignal::NotSampled, Some(restarted)),
        };
        RuntimeSample {
            observation: RuntimeObservation {
                engine,
                upstream,
                controller,
                adapter,
            },
            restarted_upstream,
            probe_restarted_client,
            detail: engine_detail
                .or(adapter_detail)
                .or(controller_detail)
                .or(upstream_detail),
        }
    }

    /// Verifies a restarted local upstream and, in cgroup isolation mode,
    /// attaches its bounded process family to a new deterministic transport
    /// scope. Attaching the user's processes to a scope is the same
    /// non-destructive effect the start path performs; the shared nftables
    /// rule and the owned record are changed only by
    /// [`Self::commit_upstream_rebind`]. A restarted upstream that already
    /// runs inside the active transport scope (adopted while its listener was
    /// down) keeps that scope, so no second move or unmarked window occurs.
    pub(crate) fn prepare_upstream_rebind(
        &self,
        restarted: &RestartedUpstream,
    ) -> Result<PreparedUpstreamRebind, LifecycleFailure> {
        let record = self.read_record()?.ok_or_else(not_running)?;
        rebind_record_matches(&record, restarted)?;
        let (identity, _) = verify_restarted_upstream(&record, restarted)?;
        let scope = match &record.local_route_escape {
            Some(current)
                if process_cgroup(identity.pid).as_deref() == Some(current.scope_path.as_str()) =>
            {
                RebindScope::Reuse(current.clone())
            }
            Some(_) => {
                let family = process_family(&identity)?;
                let mut route_escape = build_local_route_escape(record.owner_uid, &identity)?;
                create_upstream_scope(&route_escape, &family)?;
                route_escape.stage = RouteEscapeStage::Active;
                RebindScope::Replace(route_escape)
            }
            None => RebindScope::Unisolated,
        };
        Ok(PreparedUpstreamRebind {
            restarted: restarted.clone(),
            scope,
        })
    }

    /// Persists a prepared rebind. The caller must hold the service state
    /// lock and have observed `Running` with no operation in progress, so a
    /// Stop, Recover or Start cannot interleave with these writes.
    pub(crate) fn commit_upstream_rebind(
        &self,
        prepared: &PreparedUpstreamRebind,
    ) -> Result<(), LifecycleFailure> {
        let mut record = self.read_record()?.ok_or_else(not_running)?;
        rebind_record_matches(&record, &prepared.restarted)?;
        let (identity, launcher) = verify_restarted_upstream(&record, &prepared.restarted)?;
        match &prepared.scope {
            RebindScope::Unisolated => {
                if record.local_route_escape.is_some() {
                    return Err(owned_mismatch());
                }
            }
            RebindScope::Reuse(expected) => {
                if record.local_route_escape.as_ref() != Some(expected) {
                    return Err(owned_mismatch());
                }
                if process_cgroup(identity.pid).as_deref() != Some(expected.scope_path.as_str()) {
                    return Err(route_escape_unavailable());
                }
                // The marked scope, its journal and nftables stay unchanged;
                // only the record names the new upstream inside it.
                record.adopted_scope_root = scope_root_for(expected, &identity);
            }
            RebindScope::Replace(route_escape) => {
                if record.local_route_escape.is_none() {
                    return Err(owned_mismatch());
                }
                if process_cgroup(identity.pid).as_deref() != Some(route_escape.scope_path.as_str())
                {
                    return Err(route_escape_unavailable());
                }
                replace_route_escape_scope(route_escape)?;
                // Journal first: a crash before the record write leaves the
                // previous record authoritative (see `initial_record`).
                self.write_route_escape(route_escape)?;
                record.local_route_escape = Some(route_escape.clone());
                record.adopted_scope_root = None;
            }
        }
        record.upstream_pid = identity.pid;
        record.upstream_start_time = identity.start_time;
        record.upstream_exe_dev = identity.exe_dev;
        record.upstream_exe_ino = identity.exe_ino;
        record.upstream_exe_path = recordable_exe_path(&identity.exe_path);
        record.upstream_launcher_path = launcher;
        self.write_record(&record)
    }

    /// Finds a restarted client of the recorded launcher while the recorded
    /// upstream is gone and its listener is closed, and attaches that bounded
    /// same-UID family to a new transport scope. A client that must reach
    /// the network (for example, to log in) before it reopens its loopback
    /// listener otherwise loops through the TUN into its own closed listener.
    ///
    /// This never changes upstream health: the session stays degraded and
    /// every other process keeps failing closed until the listener returns.
    /// `Ok(None)` means there is nothing (or nothing unambiguous) to adopt.
    pub(crate) fn prepare_upstream_adoption(
        &self,
    ) -> Result<Option<PreparedUpstreamAdoption>, LifecycleFailure> {
        let record = self.read_record()?.ok_or_else(not_running)?;
        let (Some(current), Some(launcher), Some(recorded_exe)) = (
            record.local_route_escape.as_ref(),
            record.upstream_launcher_path.as_deref(),
            record.upstream_exe_path.as_deref(),
        ) else {
            return Ok(None);
        };
        if record.stage != OwnedStage::Running || record.remote_upstream {
            return Err(owned_mismatch());
        }
        recorded_upstream_exited(&record)?;
        if listener_owner_pids(record.upstream_port)?.is_some() {
            // A returning listener is handled by the verified rebind.
            return Ok(None);
        }
        let app_image = app_image_mount_root(Path::new(recorded_exe)).is_some();
        let entries = same_uid_process_entries(record.owner_uid)?;
        // The user's mount namespace, via the init process.
        let mounts = app_image_mounts_of(1, record.owner_uid);
        let AdoptionCandidate::Family { root_pid, family } = select_adoption_candidate(
            record.owner_uid,
            Path::new(launcher),
            app_image,
            &current.scope_path,
            &entries,
            &mounts,
            process_cgroup,
        ) else {
            return Ok(None);
        };
        let root = verify_adoption_root(&record, root_pid, app_image)?;
        let mut route_escape = build_local_route_escape(record.owner_uid, &root)?;
        create_upstream_scope(&route_escape, &family)?;
        route_escape.stage = RouteEscapeStage::Active;
        Ok(Some(PreparedUpstreamAdoption {
            previous_pid: record.upstream_pid,
            previous_start_time: record.upstream_start_time,
            previous_escape: current.clone(),
            root: ScopeRoot {
                pid: root.pid,
                start_time: root.start_time,
            },
            route_escape,
        }))
    }

    /// Moves the transport mark to a prepared adopted family. The caller must
    /// hold the service state lock and have observed `Running` with no
    /// operation in progress. Write order matches the rebind: nftables, then
    /// the route-escape journal, then the owned record, so a crash between
    /// the writes leaves the previous record authoritative and recoverable.
    pub(crate) fn commit_upstream_adoption(
        &self,
        prepared: &PreparedUpstreamAdoption,
    ) -> Result<(), LifecycleFailure> {
        let mut record = self.read_record()?.ok_or_else(not_running)?;
        if record.stage != OwnedStage::Running
            || record.remote_upstream
            || record.upstream_pid != prepared.previous_pid
            || record.upstream_start_time != prepared.previous_start_time
            || record.local_route_escape.as_ref() != Some(&prepared.previous_escape)
            || prepared.route_escape.owner_uid != record.owner_uid
            || prepared.route_escape.upstream_pid != prepared.root.pid
            || prepared.route_escape.upstream_start_time != prepared.root.start_time
        {
            return Err(owned_mismatch());
        }
        recorded_upstream_exited(&record)?;
        let app_image = record
            .upstream_exe_path
            .as_deref()
            .is_some_and(|path| app_image_mount_root(Path::new(path)).is_some());
        let root = verify_adoption_root(&record, prepared.root.pid, app_image)?;
        if root.start_time != prepared.root.start_time {
            return Err(owned_mismatch());
        }
        if process_cgroup(root.pid).as_deref() != Some(prepared.route_escape.scope_path.as_str()) {
            return Err(route_escape_unavailable());
        }
        replace_route_escape_scope(&prepared.route_escape)?;
        self.write_route_escape(&prepared.route_escape)?;
        record.local_route_escape = Some(prepared.route_escape.clone());
        record.adopted_scope_root = Some(prepared.root);
        self.write_record(&record)
    }

    pub(crate) fn controller_request(
        &self,
        method: &str,
        path: &str,
    ) -> Result<Vec<u8>, LifecycleFailure> {
        if !matches!(method, "GET" | "DELETE")
            || !path.starts_with('/')
            || path.len() > 256
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(LifecycleFailure::internal());
        }
        let record = self.read_record()?.ok_or_else(not_running)?;
        if !self.record_is_running(&record)? {
            return Err(not_running());
        }
        controller_http(method, path, &record.controller_secret)
    }

    fn rollback_failed_start(&self, record: &OwnedEngineRecord) -> Result<(), LifecycleFailure> {
        let _ = self.stop_record(record);
        Err(LifecycleFailure::new(
            ErrorCode::ConfigValidationFailed,
            "The controlled Linux engine did not become ready.",
            true,
        ))
    }

    fn stop_record(&self, record: &OwnedEngineRecord) -> Result<(), LifecycleFailure> {
        let actual = match process_identity(record.engine_pid) {
            Ok(actual) => actual,
            Err(_) if process_is_gone_or_zombie(record.engine_pid) => {
                if !tun_is_safely_absent_after_exit(
                    record.stage,
                    record.tun_ifindex,
                    interface_index(TUN_DEVICE)?,
                ) {
                    return Err(LifecycleFailure::new(
                        ErrorCode::OwnedProcessMismatch,
                        "The recorded engine exited but its TUN identity remains unknown.",
                        false,
                    ));
                }
                reap_owned_child(record.engine_pid)?;
                if let Some(route_escape) = &record.local_route_escape {
                    // nftables and policy-routing state is not persistent across a
                    // reboot. Once the recorded engine is gone and its TUN identity
                    // is safely absent, converge any remaining exact effects without
                    // requiring all three kernel objects to have survived.
                    self.remove_local_route_escape(
                        route_escape,
                        RouteEscapeCleanupMode::AllowAbsent,
                    )?;
                }
                self.clear_record()?;
                return self.remove_inactive_config();
            }
            Err(_) => {
                return Err(LifecycleFailure::new(
                    ErrorCode::OwnedProcessMismatch,
                    "The recorded Linux engine identity could not be verified.",
                    false,
                ))
            }
        };
        if actual.uid != 0
            || actual.start_time != record.engine_start_time
            || actual.exe_dev != record.engine_exe_dev
            || actual.exe_ino != record.engine_exe_ino
        {
            return Err(LifecycleFailure::new(
                ErrorCode::OwnedProcessMismatch,
                "The recorded Linux engine identity does not match.",
                false,
            ));
        }
        signal(record.engine_pid, libc::SIGTERM)?;
        if !wait_for_exit(record.engine_pid, record.engine_start_time, STOP_TIMEOUT)? {
            signal(record.engine_pid, libc::SIGKILL)?;
            if !wait_for_exit(record.engine_pid, record.engine_start_time, STOP_TIMEOUT)? {
                return Err(LifecycleFailure::internal());
            }
        }
        reap_owned_child(record.engine_pid)?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            let actual_ifindex = interface_index(TUN_DEVICE)?;
            if tun_is_safely_absent_after_exit(record.stage, record.tun_ifindex, actual_ifindex) {
                break;
            }
            if record.tun_ifindex.is_none() {
                return Err(LifecycleFailure::new(
                    ErrorCode::OwnedProcessMismatch,
                    "An unrecorded TunBridge interface was preserved.",
                    false,
                ));
            }
            if Instant::now() >= deadline {
                return Err(LifecycleFailure::new(
                    ErrorCode::InternalError,
                    "The owned TunBridge interface did not disappear.",
                    true,
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Some(route_escape) = &record.local_route_escape {
            self.remove_local_route_escape(route_escape, RouteEscapeCleanupMode::RequirePresent)?;
        }
        self.clear_record()?;
        self.remove_inactive_config()
    }

    fn validate_engine(&self) -> Result<(), LifecycleFailure> {
        let manifest = load_engine_manifest()?;
        let metadata = fs::symlink_metadata(&self.engine).map_err(|_| engine_integrity())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o755
            || metadata.nlink() != 1
            || metadata.len() != manifest.binary_size
        {
            return Err(engine_integrity());
        }
        let mut file = File::open(&self.engine).map_err(|_| engine_integrity())?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|_| engine_integrity())?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        if format!("{:x}", digest.finalize()) != manifest.binary_sha256 {
            return Err(engine_integrity());
        }
        Ok(())
    }

    fn prepare_data_root(&self) -> Result<(), LifecycleFailure> {
        match fs::symlink_metadata(&self.data_root) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o777 != 0o700
                {
                    return Err(LifecycleFailure::internal());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&self.data_root).map_err(|_| LifecycleFailure::internal())?;
                fs::set_permissions(&self.data_root, fs::Permissions::from_mode(0o700))
                    .map_err(|_| LifecycleFailure::internal())?;
            }
            Err(_) => return Err(LifecycleFailure::internal()),
        }
        Ok(())
    }

    fn write_candidate(&self, yaml: &str) -> Result<PathBuf, LifecycleFailure> {
        if yaml.len() > CONFIG_LIMIT {
            return Err(invalid_profile());
        }
        let path = self
            .data_root
            .join(format!("candidate-{}.yaml", random_hex_32()?));
        write_new_synced(&path, yaml.as_bytes())?;
        Ok(path)
    }

    fn validate_config(&self, candidate: &Path) -> Result<(), LifecycleFailure> {
        let mut child = Command::new(&self.engine)
            .args(["-t", "-f"])
            .arg(candidate)
            .arg("-d")
            .arg(&self.data_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| LifecycleFailure::internal())?;
        let deadline = Instant::now() + CONFIG_TEST_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().map_err(|_| LifecycleFailure::internal())? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(LifecycleFailure::new(
                        ErrorCode::ConfigValidationFailed,
                        "The controlled Linux engine rejected its generated configuration.",
                        false,
                    ))
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LifecycleFailure::new(
                    ErrorCode::ConfigValidationFailed,
                    "The controlled Linux engine configuration test timed out.",
                    true,
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn promote_candidate(&self, candidate: &Path) -> Result<PathBuf, LifecycleFailure> {
        if candidate.parent() != Some(self.data_root.as_path())
            || !candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("candidate-") && name.ends_with(".yaml"))
        {
            return Err(LifecycleFailure::internal());
        }
        let active = self.data_root.join(ACTIVE_CONFIG);
        fs::rename(candidate, &active).map_err(|_| LifecycleFailure::internal())?;
        sync_directory(&self.data_root)?;
        Ok(active)
    }

    fn install_local_route_escape(
        &self,
        upstream: &VerifiedRuntimeUpstream,
        owner_uid: u32,
    ) -> Result<LocalRouteEscape, LifecycleFailure> {
        let family = upstream
            .process_family
            .as_ref()
            .ok_or_else(LifecycleFailure::internal)?;
        let mut route_escape = build_local_route_escape(owner_uid, &upstream.identity)?;
        self.write_route_escape(&route_escape)?;
        if let Err(error) = create_upstream_scope(&route_escape, family) {
            let _ = self.clear_route_escape();
            return Err(error);
        }
        if let Err(error) = route_escape_effects_available() {
            let _ = self.clear_route_escape();
            return Err(error);
        }
        route_escape.stage = RouteEscapeStage::Installing;
        if let Err(error) = self.write_route_escape(&route_escape) {
            let _ = self.clear_route_escape();
            return Err(error);
        }
        if let Err(error) = install_route_escape_effects(&route_escape) {
            let _ = self.clear_route_escape();
            return Err(error);
        }
        route_escape.stage = RouteEscapeStage::Active;
        if let Err(error) = self.write_route_escape(&route_escape) {
            let _ = remove_route_escape_effects(&route_escape, RouteEscapeCleanupMode::AllowAbsent);
            let _ = self.clear_route_escape();
            return Err(error);
        }
        Ok(route_escape)
    }

    fn remove_local_route_escape(
        &self,
        route_escape: &LocalRouteEscape,
        cleanup_mode: RouteEscapeCleanupMode,
    ) -> Result<(), LifecycleFailure> {
        if !valid_local_route_escape(route_escape) {
            return Err(LifecycleFailure::internal());
        }
        if route_escape.stage != RouteEscapeStage::Planned {
            remove_route_escape_effects(route_escape, cleanup_mode)?;
        }
        self.clear_route_escape()
    }

    fn write_route_escape(&self, route_escape: &LocalRouteEscape) -> Result<(), LifecycleFailure> {
        if !valid_local_route_escape(route_escape) {
            return Err(LifecycleFailure::internal());
        }
        let bytes = serde_json::to_vec(route_escape).map_err(|_| LifecycleFailure::internal())?;
        let candidate = self
            .data_root
            .join(format!("route-state-{}.json", random_hex_32()?));
        write_new_synced(&candidate, &bytes)?;
        fs::rename(candidate, self.data_root.join(ROUTE_ESCAPE_STATE))
            .map_err(|_| LifecycleFailure::internal())?;
        sync_directory(&self.data_root)
    }

    fn read_route_escape(&self) -> Result<Option<LocalRouteEscape>, LifecycleFailure> {
        let path = self.data_root.join(ROUTE_ESCAPE_STATE);
        let metadata = match trusted_file_metadata(&path)? {
            Some(metadata) => metadata,
            None => return Ok(None),
        };
        if metadata.len() > STATE_LIMIT as u64 {
            return Err(LifecycleFailure::internal());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)
            .and_then(|file| file.take((STATE_LIMIT + 1) as u64).read_to_end(&mut bytes))
            .map_err(|_| LifecycleFailure::internal())?;
        let route_escape: LocalRouteEscape =
            serde_json::from_slice(&bytes).map_err(|_| LifecycleFailure::internal())?;
        valid_local_route_escape(&route_escape)
            .then_some(route_escape)
            .ok_or_else(LifecycleFailure::internal)
            .map(Some)
    }

    fn clear_route_escape(&self) -> Result<(), LifecycleFailure> {
        remove_trusted_file(&self.data_root.join(ROUTE_ESCAPE_STATE))
    }

    fn write_record(&self, record: &OwnedEngineRecord) -> Result<(), LifecycleFailure> {
        let bytes = serde_json::to_vec(record).map_err(|_| LifecycleFailure::internal())?;
        if bytes.len() > STATE_LIMIT {
            return Err(LifecycleFailure::internal());
        }
        let candidate = self
            .data_root
            .join(format!("state-{}.json", random_hex_32()?));
        write_new_synced(&candidate, &bytes)?;
        fs::rename(candidate, self.data_root.join(OWNED_STATE))
            .map_err(|_| LifecycleFailure::internal())?;
        sync_directory(&self.data_root)
    }

    fn read_record(&self) -> Result<Option<OwnedEngineRecord>, LifecycleFailure> {
        let path = self.data_root.join(OWNED_STATE);
        let metadata = match trusted_file_metadata(&path)? {
            Some(metadata) => metadata,
            None => return Ok(None),
        };
        if metadata.len() > STATE_LIMIT as u64 {
            return Err(LifecycleFailure::internal());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)
            .and_then(|file| file.take((STATE_LIMIT + 1) as u64).read_to_end(&mut bytes))
            .map_err(|_| LifecycleFailure::internal())?;
        let record: OwnedEngineRecord =
            serde_json::from_slice(&bytes).map_err(|_| LifecycleFailure::internal())?;
        if !matches!(record.schema_version, 1..=4)
            || record.owner_uid == 0
            || record.engine_pid == 0
            || record.upstream_pid == 0
            || record.upstream_port == 0
            || record.controller_secret.len() != 64
            || record.local_transport_escape.len() > MAX_TRANSPORT_ESCAPE_ADDRESSES
            || (record.schema_version >= 3
                && !record.remote_upstream
                && record.local_transport_escape.is_empty())
            || (record.schema_version == 4
                && !record.remote_upstream
                && record.local_route_escape.is_none())
            || (record.remote_upstream && record.local_route_escape.is_some())
            || (record.remote_upstream && record.upstream_exe_path.is_some())
            || record
                .upstream_exe_path
                .as_deref()
                .is_some_and(|path| !valid_recorded_exe_path(path))
            || (record.remote_upstream && record.upstream_launcher_path.is_some())
            || record
                .upstream_launcher_path
                .as_deref()
                .is_some_and(|path| recordable_launcher_path(Path::new(path)).is_none())
            || (record.adopted_scope_root.is_some() && record.local_route_escape.is_none())
            || record
                .local_route_escape
                .as_ref()
                .is_some_and(|route_escape| {
                    !valid_local_route_escape(route_escape)
                        || route_escape.stage != RouteEscapeStage::Active
                        || route_escape.owner_uid != record.owner_uid
                        || !route_escape_names_scope_root(&record, route_escape)
                })
            || record
                .local_transport_escape
                .iter()
                .any(|address| !routable_transport_address(*address))
            || !matches!(
                (record.stage, record.tun_ifindex),
                (OwnedStage::Pending, None) | (OwnedStage::Running, Some(_))
            )
            || !record
                .controller_secret
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LifecycleFailure::internal());
        }
        Ok(Some(record))
    }

    fn clear_record(&self) -> Result<(), LifecycleFailure> {
        remove_trusted_file(&self.data_root.join(OWNED_STATE))
    }

    fn remove_inactive_config(&self) -> Result<(), LifecycleFailure> {
        remove_trusted_file(&self.data_root.join(ACTIVE_CONFIG))
    }
}

/// A recorded local upstream that exited and whose exact loopback listener is
/// now owned by a single new process of the same UID and recorded executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestartedUpstream {
    pub(crate) previous_pid: u32,
    pub(crate) previous_start_time: u64,
    pub(crate) pid: u32,
    pub(crate) start_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedUpstreamRebind {
    restarted: RestartedUpstream,
    scope: RebindScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RebindScope {
    /// Legacy record without cgroup isolation.
    Unisolated,
    /// The restarted upstream already runs in this active, marked scope.
    Reuse(LocalRouteEscape),
    /// The restarted family was attached to this new scope.
    Replace(LocalRouteEscape),
}

/// A restarted client family attached to a new transport scope while the
/// recorded upstream is gone; committed by
/// [`LinuxLifecycle::commit_upstream_adoption`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedUpstreamAdoption {
    previous_pid: u32,
    previous_start_time: u64,
    previous_escape: LocalRouteEscape,
    root: ScopeRoot,
    route_escape: LocalRouteEscape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeSample {
    pub(crate) observation: RuntimeObservation,
    /// Set when the caller may rebind a restarted upstream; the upstream
    /// signal is then `NotSampled` until the rebind is committed.
    pub(crate) restarted_upstream: Option<RestartedUpstream>,
    /// Set when the recorded local upstream exited and nothing listens on its
    /// port, so the caller may pre-adopt a restarted client of the recorded
    /// launcher. This never changes the upstream signal.
    pub(crate) probe_restarted_client: bool,
    /// Fixed, redacted diagnostic for the first non-healthy signal.
    pub(crate) detail: Option<&'static str>,
}

impl RuntimeSample {
    fn unknown(detail: &'static str) -> Self {
        Self {
            observation: RuntimeObservation {
                engine: HealthSignal::Unknown,
                upstream: HealthSignal::Unknown,
                controller: HealthSignal::Unknown,
                adapter: HealthSignal::Unknown,
            },
            restarted_upstream: None,
            probe_restarted_client: false,
            detail: Some(detail),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UpstreamSample {
    Signal(HealthSignal),
    Restarted(RestartedUpstream),
}

type Sampled<T> = (T, Option<&'static str>);

fn sample_engine(record: &OwnedEngineRecord) -> Sampled<HealthSignal> {
    if record.stage != OwnedStage::Running {
        return (HealthSignal::Unknown, Some("record_stage"));
    }
    match process_identity(record.engine_pid) {
        Ok(actual) => classify_engine(record, &actual),
        Err(_) if process_is_gone_or_zombie(record.engine_pid) => {
            (HealthSignal::Unhealthy, Some("engine_exited"))
        }
        Err(_) => (HealthSignal::Unknown, Some("engine_identity")),
    }
}

fn classify_engine(record: &OwnedEngineRecord, actual: &ProcessIdentity) -> Sampled<HealthSignal> {
    if actual.start_time != record.engine_start_time {
        // The recorded PID now names a different process.
        return (HealthSignal::Unhealthy, Some("engine_exited"));
    }
    if actual.uid != 0
        || actual.exe_dev != record.engine_exe_dev
        || actual.exe_ino != record.engine_exe_ino
    {
        return (HealthSignal::Unknown, Some("engine_provenance"));
    }
    (HealthSignal::Healthy, None)
}

fn classify_adapter(
    recorded: Option<u32>,
    actual: Result<Option<u32>, LifecycleFailure>,
) -> Sampled<HealthSignal> {
    match (recorded, actual) {
        (_, Err(_)) => (HealthSignal::Unknown, Some("tun_unreadable")),
        (Some(recorded), Ok(Some(actual))) if recorded == actual => (HealthSignal::Healthy, None),
        (_, Ok(None)) => (HealthSignal::Unhealthy, Some("tun_missing")),
        // An interface with the product name but another identity is never
        // treated as owned, so it must not trigger cleanup.
        (_, Ok(Some(_))) => (HealthSignal::Unknown, Some("tun_identity")),
    }
}

fn sample_local_upstream(record: &OwnedEngineRecord) -> Sampled<UpstreamSample> {
    let unknown = |detail| (UpstreamSample::Signal(HealthSignal::Unknown), Some(detail));
    let identity = match process_identity(record.upstream_pid) {
        Ok(identity) if identity.start_time == record.upstream_start_time => identity,
        Ok(_) => return sample_upstream_replacement(record),
        Err(_) if process_is_gone_or_zombie(record.upstream_pid) => {
            return sample_upstream_replacement(record)
        }
        Err(_) => return unknown("upstream_identity"),
    };
    if identity.uid != record.owner_uid
        || identity.exe_dev != record.upstream_exe_dev
        || identity.exe_ino != record.upstream_exe_ino
    {
        return unknown("upstream_provenance");
    }
    match process_owns_listener(identity.pid, record.upstream_port) {
        Ok(true) => {}
        Ok(false) => {
            return match listener_inodes(record.upstream_port) {
                // The recorded client is alive but its proxy is switched off.
                Ok(inodes) if inodes.is_empty() => (
                    UpstreamSample::Signal(HealthSignal::Unhealthy),
                    Some("upstream_listener"),
                ),
                Ok(_) => unknown("upstream_listener_owner"),
                Err(_) => unknown("upstream_listener_table"),
            };
        }
        Err(_) => return unknown("upstream_listener_identity"),
    }
    let (signal, detail) = sample_transport_isolation(record, &identity);
    (UpstreamSample::Signal(signal), detail)
}

fn sample_transport_isolation(
    record: &OwnedEngineRecord,
    identity: &ProcessIdentity,
) -> Sampled<HealthSignal> {
    if let Some(route_escape) = &record.local_route_escape {
        if !valid_local_route_escape(route_escape) || route_escape.stage != RouteEscapeStage::Active
        {
            return (HealthSignal::Unknown, Some("transport_scope"));
        }
        return match process_cgroup(identity.pid) {
            Some(path) if path == route_escape.scope_path => (HealthSignal::Healthy, None),
            // An unmarked upstream could recurse through TUN. Its isolation
            // cannot be proven, so fail closed without restoring routes.
            Some(_) => (HealthSignal::Unknown, Some("transport_scope")),
            None => (HealthSignal::Unknown, Some("transport_scope_unreadable")),
        };
    }
    if record.local_transport_escape.is_empty() {
        return (HealthSignal::Unknown, Some("transport_escape_missing"));
    }
    let Ok(family) = process_family(identity) else {
        return (HealthSignal::Unknown, Some("transport_family"));
    };
    let Ok(socket_inodes) = process_family_socket_inodes(&family) else {
        return (HealthSignal::Unknown, Some("transport_socket_identity"));
    };
    let Ok(endpoints) = process_family_remote_endpoints(&socket_inodes) else {
        return (HealthSignal::Unknown, Some("transport_socket_table"));
    };
    if transport_escape_drifted(&record.local_transport_escape, &endpoints) {
        // Mihomo's route-exclude set is fixed for the engine generation and
        // cannot be extended without a TUN rebuild. Keep the tunnel failing
        // closed instead of restoring the original routes.
        (HealthSignal::Unhealthy, Some("transport_escape_drift"))
    } else {
        (HealthSignal::Healthy, None)
    }
}

fn transport_escape_drifted(escape: &[IpAddr], endpoints: &BTreeSet<SocketEndpoint>) -> bool {
    endpoints
        .iter()
        .filter(|endpoint| transport_endpoint_allowed(**endpoint, None))
        .any(|endpoint| !escape.contains(&endpoint.address))
}

fn sample_upstream_replacement(record: &OwnedEngineRecord) -> Sampled<UpstreamSample> {
    match listener_owner_pids(record.upstream_port) {
        Ok(owners) => classify_upstream_replacement(
            record,
            owners.as_ref(),
            process_identity,
            upstream_launcher_path,
        ),
        Err(_) => (
            UpstreamSample::Signal(HealthSignal::Unknown),
            Some("upstream_listener_table"),
        ),
    }
}

/// Classifies the recorded upstream listener after the recorded process
/// exited. `owners` is `None` when nothing listens on the recorded loopback
/// port. Any owner that is not provably the same client stays `Unknown`.
fn classify_upstream_replacement(
    record: &OwnedEngineRecord,
    owners: Option<&BTreeSet<u32>>,
    identity_of: impl Fn(u32) -> Result<ProcessIdentity, LifecycleFailure>,
    launcher_of: impl FnOnce(&ProcessIdentity) -> Option<String>,
) -> Sampled<UpstreamSample> {
    let unknown = |detail| (UpstreamSample::Signal(HealthSignal::Unknown), Some(detail));
    let Some(owners) = owners else {
        return (
            UpstreamSample::Signal(HealthSignal::Unhealthy),
            Some(UPSTREAM_EXITED),
        );
    };
    let mut owners = owners.iter().copied();
    let (Some(pid), None) = (owners.next(), owners.next()) else {
        return unknown("upstream_listener_ambiguous");
    };
    if record.upstream_exe_path.is_none() {
        return unknown("upstream_replaced");
    }
    let Ok(identity) = identity_of(pid) else {
        return unknown("upstream_replacement_identity");
    };
    if pid == 0
        || identity.pid != pid
        || (pid == record.upstream_pid && identity.start_time == record.upstream_start_time)
        || identity.uid != record.owner_uid
        || !replacement_executable_matches(record, &identity, launcher_of)
    {
        return unknown("upstream_replaced");
    }
    (
        UpstreamSample::Restarted(RestartedUpstream {
            previous_pid: record.upstream_pid,
            previous_start_time: record.upstream_start_time,
            pid,
            start_time: identity.start_time,
        }),
        Some("upstream_restarted"),
    )
}

fn rebind_record_matches(
    record: &OwnedEngineRecord,
    restarted: &RestartedUpstream,
) -> Result<(), LifecycleFailure> {
    if record.stage != OwnedStage::Running
        || record.remote_upstream
        || restarted.pid == 0
        || record.upstream_pid != restarted.previous_pid
        || record.upstream_start_time != restarted.previous_start_time
    {
        return Err(owned_mismatch());
    }
    // A live recorded process is never replaced.
    recorded_upstream_exited(record)
}

/// Succeeds only when the recorded upstream process provably exited.
fn recorded_upstream_exited(record: &OwnedEngineRecord) -> Result<(), LifecycleFailure> {
    match process_identity(record.upstream_pid) {
        Ok(previous) if previous.start_time == record.upstream_start_time => Err(owned_mismatch()),
        Ok(_) => Ok(()),
        Err(_) if process_is_gone_or_zombie(record.upstream_pid) => Ok(()),
        Err(_) => Err(owned_mismatch()),
    }
}

/// Returns the verified restarted upstream and its freshly derived launcher.
fn verify_restarted_upstream(
    record: &OwnedEngineRecord,
    restarted: &RestartedUpstream,
) -> Result<(ProcessIdentity, Option<String>), LifecycleFailure> {
    let identity = process_identity(restarted.pid)?;
    if identity.start_time != restarted.start_time || identity.uid != record.owner_uid {
        return Err(owned_mismatch());
    }
    let launcher = upstream_launcher_path(&identity);
    if !replacement_executable_matches(record, &identity, |_| launcher.clone()) {
        return Err(owned_mismatch());
    }
    if listener_owner_pids(record.upstream_port)? != Some(BTreeSet::from([restarted.pid])) {
        return Err(owned_mismatch());
    }
    Ok((identity, launcher))
}

/// A restarted upstream is the recorded client when it runs exactly the
/// recorded executable, or, for an AppImage, the same path inside a new
/// AppImage mount that was launched by exactly the recorded runtime. The
/// AppImage runtime picks a random mount directory for every launch.
fn replacement_executable_matches(
    record: &OwnedEngineRecord,
    identity: &ProcessIdentity,
    launcher_of: impl FnOnce(&ProcessIdentity) -> Option<String>,
) -> bool {
    let Some(recorded_exe) = record.upstream_exe_path.as_deref() else {
        return false;
    };
    if identity.exe_path.to_str() == Some(recorded_exe) {
        return true;
    }
    let Some(recorded_launcher) = record.upstream_launcher_path.as_deref() else {
        return false;
    };
    let Some(recorded_relative) = app_image_relative_path(Path::new(recorded_exe)) else {
        return false;
    };
    app_image_relative_path(&identity.exe_path) == Some(recorded_relative)
        && launcher_of(identity).as_deref() == Some(recorded_launcher)
}

/// Executable path below its AppImage mount root, if it is inside one.
fn app_image_relative_path(path: &Path) -> Option<&Path> {
    let mount_root = app_image_mount_root(path)?;
    let relative = path.strip_prefix(&mount_root).ok()?;
    (!relative.as_os_str().is_empty()).then_some(relative)
}

/// `None` when the scope is named after the upstream itself.
fn scope_root_for(
    route_escape: &LocalRouteEscape,
    upstream: &ProcessIdentity,
) -> Option<ScopeRoot> {
    (route_escape.upstream_pid != upstream.pid
        || route_escape.upstream_start_time != upstream.start_time)
        .then_some(ScopeRoot {
            pid: route_escape.upstream_pid,
            start_time: route_escape.upstream_start_time,
        })
}

/// The active scope is named after the adopted root when one is recorded,
/// otherwise after the recorded upstream.
fn route_escape_names_scope_root(
    record: &OwnedEngineRecord,
    route_escape: &LocalRouteEscape,
) -> bool {
    let (pid, start_time) = match record.adopted_scope_root {
        Some(root) => (root.pid, root.start_time),
        None => (record.upstream_pid, record.upstream_start_time),
    };
    route_escape.upstream_pid == pid && route_escape.upstream_start_time == start_time
}

/// Re-reads the adoption root from procfs: owner UID, exactly the recorded
/// launcher, and for a plain executable also the recorded file identity.
fn verify_adoption_root(
    record: &OwnedEngineRecord,
    pid: u32,
    app_image: bool,
) -> Result<ProcessIdentity, LifecycleFailure> {
    let launcher = record
        .upstream_launcher_path
        .as_deref()
        .ok_or_else(owned_mismatch)?;
    let root = process_identity(pid)?;
    if root.pid == 0
        || root.uid != record.owner_uid
        || root.exe_path.to_str() != Some(launcher)
        || (!app_image
            && (root.exe_dev != record.upstream_exe_dev || root.exe_ino != record.upstream_exe_ino))
    {
        return Err(owned_mismatch());
    }
    Ok(root)
}

/// The kernel-reported launcher of a verified local upstream. `None` keeps
/// the previous exact-path behaviour (no adoption, no AppImage rebind).
fn upstream_launcher_path(identity: &ProcessIdentity) -> Option<String> {
    if app_image_mount_root(&identity.exe_path).is_none() {
        return recordable_launcher_path(&identity.exe_path);
    }
    let entries = same_uid_process_entries(identity.uid).ok()?;
    let mounts = app_image_mounts_of(identity.pid, identity.uid);
    derive_launcher_path(
        identity,
        &entries,
        &mounts,
        process_holds_fuse_device,
        |pid| fs::metadata(format!("/proc/{pid}/exe")).is_ok_and(|metadata| metadata.is_file()),
    )
}

/// Finds the AppImage runtime of an upstream that runs inside an AppImage
/// mount: a same-UID process outside that mount which holds the FUSE session
/// (`/dev/fuse`) and is either the nearest ancestor outside the mount
/// (bounded parent walk) or a direct child of a process inside the mount
/// (the type-2 runtime forks its FUSE server after the parent execs AppRun).
/// Exactly one such process must exist.
fn derive_launcher_path(
    root: &ProcessIdentity,
    entries: &[ProcessFamilyEntry],
    mounts: &[AppImageMount],
    holds_fuse: impl Fn(u32) -> bool,
    is_regular_file: impl Fn(u32) -> bool,
) -> Option<String> {
    let Some(mount_root) = app_image_mount_root(&root.exe_path) else {
        return recordable_launcher_path(&root.exe_path);
    };
    let processes: BTreeMap<u32, &ProcessFamilyEntry> = entries
        .iter()
        .filter(|entry| entry.uid == root.uid)
        .map(|entry| (entry.pid, entry))
        .collect();
    let in_mount = |entry: &ProcessFamilyEntry| {
        entry
            .process_path
            .as_ref()
            .is_some_and(|path| path.starts_with(&mount_root))
    };
    let mut candidates = BTreeSet::new();
    let mut pid = processes.get(&root.pid)?.parent_pid;
    for _ in 0..MAX_LAUNCHER_HOPS {
        if pid <= 1 {
            break;
        }
        // A missing parent or one of another UID ends the walk.
        let Some(entry) = processes.get(&pid) else {
            break;
        };
        if in_mount(entry) {
            pid = entry.parent_pid;
            continue;
        }
        if entry.process_path.is_some() && holds_fuse(entry.pid) {
            candidates.insert(entry.pid);
        }
        break;
    }
    for entry in processes.values() {
        if entry.process_path.is_some()
            && !in_mount(entry)
            && processes
                .get(&entry.parent_pid)
                .is_some_and(|parent| in_mount(parent))
            && holds_fuse(entry.pid)
        {
            candidates.insert(entry.pid);
        }
    }
    // The runtime may also be a sibling reparented to the user manager. The
    // kernel mount table names the FUSE source after the AppImage file and
    // records the mounting user, which links the runtime to this mount.
    if let Some(source) = mount_source(mounts, &mount_root) {
        for entry in processes.values() {
            if !in_mount(entry)
                && entry
                    .process_path
                    .as_deref()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    == Some(source)
                && holds_fuse(entry.pid)
            {
                candidates.insert(entry.pid);
            }
        }
    }
    let mut candidates = candidates.into_iter();
    let (Some(pid), None) = (candidates.next(), candidates.next()) else {
        return None;
    };
    if !is_regular_file(pid) {
        return None;
    }
    recordable_launcher_path(processes.get(&pid)?.process_path.as_deref()?)
}

/// A launcher must be an absolute, bounded path outside any AppImage mount.
fn recordable_launcher_path(path: &Path) -> Option<String> {
    path.to_str()
        .filter(|path| {
            valid_recorded_exe_path(path)
                && !path.ends_with(" (deleted)")
                && app_image_mount_root(Path::new(path)).is_none()
        })
        .map(str::to_owned)
}

#[derive(Debug, PartialEq, Eq)]
enum AdoptionCandidate {
    /// No restarted client (or its AppImage mount is not ready yet).
    None,
    /// More than one family, or a family beyond the process bound.
    Ambiguous,
    /// The single family root already runs in the active transport scope.
    AlreadyAdopted,
    Family {
        root_pid: u32,
        family: ProcessFamily,
    },
}

/// Selects exactly one restarted client family of the recorded launcher.
/// Only processes of `owner_uid` are considered. A launcher process nested
/// below another launcher process belongs to that one's family. For an
/// AppImage the family is the runtime, every process inside the single mount
/// the runtime serves (its parent's or its children's mount), and all of
/// their descendants; for a plain executable it is the root and its
/// descendants. Every family is bounded by `MAX_UPSTREAM_PROCESS_FAMILY`.
fn select_adoption_candidate(
    owner_uid: u32,
    launcher: &Path,
    app_image: bool,
    current_scope: &str,
    entries: &[ProcessFamilyEntry],
    mounts: &[AppImageMount],
    cgroup_of: impl Fn(u32) -> Option<String>,
) -> AdoptionCandidate {
    let processes: BTreeMap<u32, &ProcessFamilyEntry> = entries
        .iter()
        .filter(|entry| entry.uid == owner_uid)
        .map(|entry| (entry.pid, entry))
        .collect();
    let matches: BTreeSet<u32> = processes
        .values()
        .filter(|entry| entry.process_path.as_deref() == Some(launcher))
        .map(|entry| entry.pid)
        .collect();
    if matches.len() > MAX_UPSTREAM_PROCESS_FAMILY {
        return AdoptionCandidate::Ambiguous;
    }
    let roots: Vec<u32> = matches
        .iter()
        .copied()
        .filter(|pid| !has_ancestor_in(*pid, &matches, &processes))
        .collect();
    let root = match roots.as_slice() {
        [] => return AdoptionCandidate::None,
        [root] => *root,
        _ => return AdoptionCandidate::Ambiguous,
    };
    if cgroup_of(root).as_deref() == Some(current_scope) {
        return AdoptionCandidate::AlreadyAdopted;
    }
    let mut seed = BTreeSet::from([root]);
    if app_image {
        let Some(mount_root) = runtime_mount_root(root, &processes, mounts) else {
            return AdoptionCandidate::None;
        };
        seed.extend(
            processes
                .values()
                .filter(|entry| {
                    entry
                        .process_path
                        .as_ref()
                        .is_some_and(|path| path.starts_with(&mount_root))
                })
                .map(|entry| entry.pid),
        );
    }
    match bounded_process_family(seed, &processes) {
        Some(family) => AdoptionCandidate::Family {
            root_pid: root,
            family,
        },
        None => AdoptionCandidate::Ambiguous,
    }
}

fn has_ancestor_in(
    pid: u32,
    set: &BTreeSet<u32>,
    processes: &BTreeMap<u32, &ProcessFamilyEntry>,
) -> bool {
    let mut current = pid;
    for _ in 0..processes.len() {
        let Some(entry) = processes.get(&current) else {
            return false;
        };
        if entry.parent_pid <= 1 || entry.parent_pid == current {
            return false;
        }
        if set.contains(&entry.parent_pid) {
            return true;
        }
        current = entry.parent_pid;
    }
    false
}

/// The single AppImage mount served by a runtime process: the mount of its
/// parent (type-2 FUSE server child) or of its direct children.
fn runtime_mount_root(
    runtime: u32,
    processes: &BTreeMap<u32, &ProcessFamilyEntry>,
    mounts: &[AppImageMount],
) -> Option<PathBuf> {
    let entry = processes.get(&runtime)?;
    let mount_of =
        |entry: &ProcessFamilyEntry| entry.process_path.as_deref().and_then(app_image_mount_root);
    let mut roots: BTreeSet<PathBuf> = processes
        .values()
        .filter(|child| child.parent_pid == runtime && child.pid != runtime)
        .filter_map(|child| mount_of(child))
        .collect();
    if let Some(parent) = processes.get(&entry.parent_pid) {
        roots.extend(mount_of(parent));
    }
    // A sibling runtime: the kernel mount whose FUSE source is its file.
    if let Some(name) = entry
        .process_path
        .as_deref()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
    {
        roots.extend(
            mounts
                .iter()
                .filter(|mount| mount.source == name)
                .map(|mount| mount.root.clone()),
        );
    }
    let mut roots = roots.into_iter();
    match (roots.next(), roots.next()) {
        (Some(root), None) => Some(root),
        _ => None,
    }
}

fn recordable_exe_path(path: &Path) -> Option<String> {
    path.to_str()
        .filter(|path| valid_recorded_exe_path(path))
        .map(str::to_owned)
}

fn valid_recorded_exe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_UPSTREAM_EXE_PATH_BYTES
        && !path.bytes().any(|byte| byte.is_ascii_control())
}

/// Both journals describe an active transport scope of the same owner, so
/// they share the fixed nftables table and policy rules.
fn interrupted_upstream_rebind(recorded: &LocalRouteEscape, journal: &LocalRouteEscape) -> bool {
    recorded != journal
        && valid_local_route_escape(recorded)
        && valid_local_route_escape(journal)
        && recorded.stage == RouteEscapeStage::Active
        && journal.stage == RouteEscapeStage::Active
        && recorded.owner_uid == journal.owner_uid
}

fn load_engine_manifest() -> Result<EngineManifest, LifecycleFailure> {
    let path = Path::new(ENGINE_MANIFEST);
    let metadata = fs::symlink_metadata(path).map_err(|_| engine_integrity())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o644
        || metadata.nlink() != 1
        || metadata.len() > 4096
    {
        return Err(engine_integrity());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(4097).read_to_end(&mut bytes))
        .map_err(|_| engine_integrity())?;
    let manifest: EngineManifest =
        serde_json::from_slice(&bytes).map_err(|_| engine_integrity())?;
    if manifest.schema_version != 1
        || manifest.version.is_empty()
        || manifest.version.len() > 64
        || !manifest.version.starts_with('v')
        || manifest.asset_name != format!("mihomo-linux-amd64-compatible-{}.gz", manifest.version)
        || manifest.binary_size == 0
        || manifest.binary_size > 128 * 1024 * 1024
        || manifest.binary_sha256.len() != 64
        || !manifest
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(engine_integrity());
    }
    Ok(manifest)
}

fn render_config(
    request: &StartProfileV3,
    upstream: &VerifiedRuntimeUpstream,
    secret: &str,
) -> Result<String, LifecycleFailure> {
    if let Some(legacy) = request.legacy_local_profile() {
        let protocol = match legacy.protocol {
            UpstreamProtocol::Socks5 => Protocol::Socks5,
            UpstreamProtocol::Http => Protocol::Http,
        };
        let mut profile = Profile::with_upstream(Upstream {
            host: if legacy.upstream_host == "localhost" {
                "127.0.0.1".into()
            } else {
                legacy.upstream_host.clone()
            },
            port: legacy.upstream_port,
            protocol,
            username: legacy.username.clone(),
            password: legacy.password.clone(),
            udp: protocol == Protocol::Socks5,
        });
        profile.secret = secret.into();
        if upstream.transport_escape_addresses.is_empty() {
            return Err(invalid_profile());
        }
        // Linux process rules require an expensive, racy /proc lookup for each
        // new flow. The verified proxy transport is instead excluded before
        // TUN routing, so its packets cannot recurse through Mihomo.
        profile.exclude_processes = Vec::new();
        profile.direct_source_cidrs = vec![format!("{ESCAPED_FAKE_IP_SOURCE}/32")];
        profile.route_exclude_addresses = upstream.transport_escape_addresses.clone();
        profile.bypass_domains = deduplicate(legacy.bypass_domains.iter().cloned());
        profile.bypass_cidrs = deduplicate(
            profile
                .bypass_cidrs
                .into_iter()
                .chain(legacy.bypass_cidrs.iter().cloned()),
        );
        return config::render(&profile).map_err(|_| {
            LifecycleFailure::new(
                ErrorCode::ConfigValidationFailed,
                "The controlled Linux engine configuration could not be rendered.",
                false,
            )
        });
    }
    let StartUpstreamV3::RemoteServer {
        endpoint,
        protocol_config,
        secret_material,
    } = &request.upstream
    else {
        return Err(invalid_profile());
    };
    let pinned_server = upstream.pinned_remote.ok_or_else(invalid_profile)?;
    let mut profile = Profile::with_upstream(Upstream {
        host: pinned_server.to_string(),
        port: endpoint.port,
        protocol: match protocol_config.standard_protocol() {
            StandardProtocol::Socks5 => Protocol::Socks5,
            StandardProtocol::Http => Protocol::Http,
        },
        username: None,
        password: None,
        udp: protocol_config.udp_enabled(),
    });
    profile.secret = secret.into();
    // Linux never emits process rules. Route-level escape owns recursion
    // prevention, and procfs matching can amplify short-flow storms.
    profile.exclude_processes = Vec::new();
    profile.bypass_domains = deduplicate(request.traffic_bypass_domains.iter().cloned());
    profile.bypass_cidrs = deduplicate(
        profile
            .bypass_cidrs
            .into_iter()
            .chain(request.traffic_bypass_cidrs.iter().cloned()),
    );
    config_v2::render_remote(
        &profile,
        &config_v2::ResolvedRemoteUpstream {
            pinned_server,
            port: endpoint.port,
            protocol_config,
            secret_material: secret_material.as_ref(),
            transport_escape: config_v2::TransportEscape::EngineRouteExclude,
        },
    )
    .map_err(|_| {
        LifecycleFailure::new(
            ErrorCode::ConfigValidationFailed,
            "The controlled Linux engine configuration could not be rendered.",
            false,
        )
    })
}

fn deduplicate(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_ascii_lowercase()))
        .collect()
}

fn verify_upstream(
    profile: &StartProfileV3,
    expected_uid: u32,
) -> Result<VerifiedRuntimeUpstream, LifecycleFailure> {
    if let Some(legacy) = profile.legacy_local_profile() {
        if process_owner_uid(legacy.upstream_process_id)? != expected_uid {
            return Err(LifecycleFailure::new(
                ErrorCode::InvalidProfile,
                "The upstream listener identity validation failed.",
                true,
            ));
        }
        let identity = process_identity(legacy.upstream_process_id)?;
        if identity.uid != expected_uid
            || !process_owns_listener(identity.pid, legacy.upstream_port)?
        {
            return Err(LifecycleFailure::new(
                ErrorCode::InvalidProfile,
                "The upstream listener identity validation failed.",
                true,
            ));
        }
        let transport_escape_addresses = discover_local_transport_addresses(&legacy, &identity)?;
        let process_family = process_family(&identity)?;
        return Ok(VerifiedRuntimeUpstream {
            process_family: Some(process_family),
            transport_escape_addresses,
            identity,
            pinned_remote: None,
        });
    }
    let StartUpstreamV3::RemoteServer { endpoint, .. } = &profile.upstream else {
        return Err(invalid_profile());
    };
    let pinned_remote = resolve_endpoint_system(endpoint)
        .map_err(|_| invalid_profile())?
        .into_iter()
        .find(std::net::IpAddr::is_ipv4)
        .ok_or_else(invalid_profile)?;
    preflight_pinned_tcp(pinned_remote, endpoint.port, Duration::from_secs(4)).map_err(|_| {
        LifecycleFailure::new(
            ErrorCode::ConfigValidationFailed,
            "The remote upstream transport preflight failed.",
            true,
        )
    })?;
    let identity = process_identity(std::process::id())?;
    if identity.uid != 0 {
        return Err(LifecycleFailure::internal());
    }
    Ok(VerifiedRuntimeUpstream {
        identity,
        process_family: None,
        transport_escape_addresses: Vec::new(),
        pinned_remote: Some(pinned_remote),
    })
}

fn build_local_route_escape(
    owner_uid: u32,
    upstream: &ProcessIdentity,
) -> Result<LocalRouteEscape, LifecycleFailure> {
    if owner_uid == 0 || upstream.uid != owner_uid || upstream.pid == 0 {
        return Err(invalid_profile());
    }
    let scope_unit = format!(
        "tunbridge-upstream-u{}-p{}-s{}.scope",
        owner_uid, upstream.pid, upstream.start_time
    );
    let scope_path = format!("/user.slice/user-{owner_uid}.slice/{scope_unit}");
    let route_escape = LocalRouteEscape {
        schema_version: 1,
        stage: RouteEscapeStage::Planned,
        owner_uid,
        upstream_pid: upstream.pid,
        upstream_start_time: upstream.start_time,
        scope_unit,
        scope_path,
    };
    valid_local_route_escape(&route_escape)
        .then_some(route_escape)
        .ok_or_else(LifecycleFailure::internal)
}

fn valid_local_route_escape(route_escape: &LocalRouteEscape) -> bool {
    if route_escape.schema_version != 1
        || route_escape.owner_uid == 0
        || route_escape.upstream_pid == 0
        || route_escape.upstream_start_time == 0
    {
        return false;
    }
    let expected_unit = format!(
        "tunbridge-upstream-u{}-p{}-s{}.scope",
        route_escape.owner_uid, route_escape.upstream_pid, route_escape.upstream_start_time
    );
    let expected_path = format!(
        "/user.slice/user-{}.slice/{expected_unit}",
        route_escape.owner_uid
    );
    route_escape.scope_unit == expected_unit
        && route_escape.scope_path == expected_path
        && route_escape.scope_unit.len() <= 128
}

fn create_upstream_scope(
    route_escape: &LocalRouteEscape,
    family: &ProcessFamily,
) -> Result<(), LifecycleFailure> {
    if !valid_local_route_escape(route_escape)
        || family.pids.is_empty()
        || family.pids.len() > MAX_UPSTREAM_PROCESS_FAMILY
        || !family.pids.contains(&route_escape.upstream_pid)
    {
        return Err(route_escape_unavailable());
    }
    if family
        .pids
        .iter()
        .all(|pid| process_cgroup(*pid).as_deref() == Some(route_escape.scope_path.as_str()))
    {
        return Ok(());
    }
    let mut arguments = vec![
        "call".into(),
        "org.freedesktop.systemd1".into(),
        "/org/freedesktop/systemd1".into(),
        "org.freedesktop.systemd1.Manager".into(),
        "StartTransientUnit".into(),
        "ssa(sv)a(sa(sv))".into(),
        route_escape.scope_unit.clone(),
        "fail".into(),
        "3".into(),
        "Description".into(),
        "s".into(),
        "TunBridge isolated local upstream".into(),
        "Slice".into(),
        "s".into(),
        format!("user-{}.slice", route_escape.owner_uid),
        "PIDs".into(),
        "au".into(),
        family.pids.len().to_string(),
    ];
    arguments.extend(family.pids.iter().map(u32::to_string));
    arguments.push("0".into());
    if !system_tool_status(&["/usr/bin/busctl", "/bin/busctl"], &arguments)? {
        return Err(route_escape_unavailable());
    }
    let deadline = Instant::now() + ROUTE_ESCAPE_SCOPE_TIMEOUT;
    loop {
        let all_attached = family
            .pids
            .iter()
            .all(|pid| process_cgroup(*pid).as_deref() == Some(route_escape.scope_path.as_str()));
        if all_attached {
            let identity = process_identity(route_escape.upstream_pid)?;
            if identity.uid == route_escape.owner_uid
                && identity.start_time == route_escape.upstream_start_time
            {
                return Ok(());
            }
            return Err(route_escape_unavailable());
        }
        if Instant::now() >= deadline {
            return Err(route_escape_unavailable());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn route_escape_effects_available() -> Result<(), LifecycleFailure> {
    if !policy_rule_output("-4")?.trim().is_empty()
        || !policy_rule_output("-6")?.trim().is_empty()
        || fake_ip_rule_present()?
        || nft_route_table_exists()?
    {
        return Err(route_escape_unavailable());
    }
    Ok(())
}

fn install_route_escape_effects(route_escape: &LocalRouteEscape) -> Result<(), LifecycleFailure> {
    if !valid_local_route_escape(route_escape) || route_escape.stage != RouteEscapeStage::Installing
    {
        return Err(route_escape_unavailable());
    }
    let add_table = strings(&["add", "table", "inet", ROUTE_ESCAPE_TABLE]);
    let add_chain = vec![
        "add".into(),
        "chain".into(),
        "inet".into(),
        ROUTE_ESCAPE_TABLE.into(),
        ROUTE_ESCAPE_CHAIN.into(),
        "{ type route hook output priority mangle; policy accept; }".into(),
    ];
    let add_rule = route_escape_mark_rule_arguments(route_escape);
    let source_nat = route_escape_source_nat_arguments();
    if !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &add_table)? {
        return Err(route_escape_unavailable());
    }
    let install_result = (|| {
        if !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &add_chain)? {
            return Err(route_escape_unavailable());
        }
        for family in ["-4", "-6"] {
            let arguments = route_rule_arguments(family, "add");
            if !system_tool_status(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"], &arguments)? {
                return Err(route_escape_unavailable());
            }
        }
        if !system_tool_status(
            &["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"],
            &fake_ip_rule_arguments("add"),
        )? {
            return Err(route_escape_unavailable());
        }
        if !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &add_rule)? {
            return Err(route_escape_unavailable());
        }
        if !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &source_nat)? {
            return Err(route_escape_unavailable());
        }
        Ok(())
    })();
    if install_result.is_err() {
        let _ = remove_route_escape_effects(route_escape, RouteEscapeCleanupMode::AllowAbsent);
    }
    install_result
}

fn route_escape_mark_rule_arguments(route_escape: &LocalRouteEscape) -> Vec<String> {
    vec![
        "add".into(),
        "rule".into(),
        "inet".into(),
        ROUTE_ESCAPE_TABLE.into(),
        ROUTE_ESCAPE_CHAIN.into(),
        "socket".into(),
        "cgroupv2".into(),
        "level".into(),
        "3".into(),
        route_escape.scope_path.trim_start_matches('/').into(),
        "meta".into(),
        "mark".into(),
        "set".into(),
        ROUTE_ESCAPE_MARK.into(),
    ]
}

/// Marked upstream packets leave through the physical interface but keep the
/// TUN source address chosen before the mark re-routed them, so no reply ever
/// returns. Rewrite that source to the egress interface address. The chain is
/// (re)created idempotently so a rebind also repairs sessions started without
/// it; deleting the table at stop removes it.
fn route_escape_source_nat_arguments() -> Vec<String> {
    let mut arguments = vec![
        "add".into(),
        "chain".into(),
        "inet".into(),
        ROUTE_ESCAPE_TABLE.into(),
        ROUTE_ESCAPE_NAT_CHAIN.into(),
        "{ type nat hook postrouting priority srcnat; policy accept; }".into(),
        ";".into(),
    ];
    arguments.extend(strings(&[
        "flush",
        "chain",
        "inet",
        ROUTE_ESCAPE_TABLE,
        ROUTE_ESCAPE_NAT_CHAIN,
        ";",
        "add",
        "rule",
        "inet",
        ROUTE_ESCAPE_TABLE,
        ROUTE_ESCAPE_NAT_CHAIN,
        "meta",
        "mark",
        ROUTE_ESCAPE_MARK,
        "oifname",
        TUN_DEVICE,
        "ip",
        "daddr",
        FAKE_IP_RANGE_V4,
        "snat",
        "ip",
        "to",
        ESCAPED_FAKE_IP_SOURCE,
        ";",
    ]));
    for (family, prefix) in [("ip", TUN_SOURCE_PREFIX_V4), ("ip6", TUN_SOURCE_PREFIX_V6)] {
        arguments.extend(strings(&[
            "add",
            "rule",
            "inet",
            ROUTE_ESCAPE_TABLE,
            ROUTE_ESCAPE_NAT_CHAIN,
            "meta",
            "mark",
            ROUTE_ESCAPE_MARK,
            "oifname",
            "!=",
            TUN_DEVICE,
            family,
            "saddr",
            prefix,
            "masquerade",
            ";",
        ]));
    }
    arguments.pop();
    arguments
}

/// One nft invocation is one netlink transaction: the chain never exposes a
/// window without a mark rule, and exactly one scope stays marked.
fn route_escape_scope_replacement_arguments(route_escape: &LocalRouteEscape) -> Vec<String> {
    let mut arguments = strings(&[
        "flush",
        "chain",
        "inet",
        ROUTE_ESCAPE_TABLE,
        ROUTE_ESCAPE_CHAIN,
        ";",
    ]);
    arguments.extend(route_escape_mark_rule_arguments(route_escape));
    arguments.push(";".into());
    arguments.extend(route_escape_source_nat_arguments());
    arguments
}

/// Moves the active cgroup mark to a rebound upstream scope. Only the fixed
/// table and policy rules that this session installed are touched; if any of
/// them is missing the rebind fails and the tunnel stays failing closed.
fn replace_route_escape_scope(route_escape: &LocalRouteEscape) -> Result<(), LifecycleFailure> {
    if !valid_local_route_escape(route_escape) || route_escape.stage != RouteEscapeStage::Active {
        return Err(route_escape_unavailable());
    }
    if !nft_route_table_exists()?
        || policy_rule_output("-4")?.trim().is_empty()
        || policy_rule_output("-6")?.trim().is_empty()
    {
        return Err(route_escape_unavailable());
    }
    let arguments = route_escape_scope_replacement_arguments(route_escape);
    if !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)? {
        return Err(route_escape_unavailable());
    }
    // Sessions started before the fake-IP return path existed gain it here.
    if !fake_ip_rule_present()?
        && !system_tool_status(
            &["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"],
            &fake_ip_rule_arguments("add"),
        )?
    {
        return Err(route_escape_unavailable());
    }
    Ok(())
}

fn remove_route_escape_effects(
    route_escape: &LocalRouteEscape,
    cleanup_mode: RouteEscapeCleanupMode,
) -> Result<(), LifecycleFailure> {
    if !valid_local_route_escape(route_escape) {
        return Err(LifecycleFailure::internal());
    }
    let mut failed = false;
    let table_present = nft_route_table_exists()?;
    if table_present {
        let arguments = strings(&["delete", "table", "inet", ROUTE_ESCAPE_TABLE]);
        failed |= !system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)?;
    } else if cleanup_mode.requires_presence() {
        failed = true;
    }
    for family in ["-6", "-4"] {
        let present = !policy_rule_output(family)?.trim().is_empty();
        if present {
            let arguments = route_rule_arguments(family, "delete");
            failed |=
                !system_tool_status(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"], &arguments)?;
        } else if cleanup_mode.requires_presence() {
            failed = true;
        }
    }
    // Optional: sessions started before 0.3.18 never installed it.
    if fake_ip_rule_present()? {
        failed |= !system_tool_status(
            &["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"],
            &fake_ip_rule_arguments("delete"),
        )?;
    }
    if failed {
        Err(LifecycleFailure::internal())
    } else {
        Ok(())
    }
}

fn fake_ip_rule_arguments(operation: &str) -> Vec<String> {
    strings(&[
        "-4",
        "rule",
        operation,
        "priority",
        ROUTE_ESCAPE_FAKE_IP_PRIORITY,
        "fwmark",
        ROUTE_ESCAPE_MARK,
        "to",
        FAKE_IP_RANGE_V4,
        "lookup",
        MIHOMO_ROUTE_TABLE,
    ])
}

fn fake_ip_rule_present() -> Result<bool, LifecycleFailure> {
    let arguments = strings(&[
        "-4",
        "rule",
        "show",
        "priority",
        ROUTE_ESCAPE_FAKE_IP_PRIORITY,
    ]);
    Ok(
        !system_tool_output(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"], &arguments)?
            .trim()
            .is_empty(),
    )
}

fn route_rule_arguments(family: &str, operation: &str) -> Vec<String> {
    strings(&[
        family,
        "rule",
        operation,
        "priority",
        ROUTE_ESCAPE_PRIORITY,
        "fwmark",
        ROUTE_ESCAPE_MARK,
        "lookup",
        "main",
    ])
}

fn policy_rule_output(family: &str) -> Result<String, LifecycleFailure> {
    let arguments = strings(&[family, "rule", "show", "priority", ROUTE_ESCAPE_PRIORITY]);
    system_tool_output(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"], &arguments)
}

/// One nft transaction that (re)creates the lock chain, so the lock never has
/// a window without its final reject. The service's own cgroup holds the
/// engine; the escape mark is set earlier, at mangle priority, for the proxy
/// client's scope.
fn traffic_lock_arguments(service_cgroup: &str, escape_scope: Option<&str>) -> Option<Vec<String>> {
    let valid_cgroup = |path: &str| -> Option<(String, usize)> {
        let path = path.trim_start_matches('/');
        let level = path.split('/').count();
        (!path.is_empty()
            && level <= 8
            && path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b'@')
            })
            && !path.split('/').any(str::is_empty))
        .then(|| (path.to_owned(), level))
    };
    let (cgroup, level) = valid_cgroup(service_cgroup)?;
    let escape = match escape_scope {
        Some(scope) => Some(valid_cgroup(scope)?),
        None => None,
    };
    let rule = |tail: &[&str]| -> Vec<String> {
        let mut rule = strings(&[
            "add",
            "rule",
            "inet",
            TRAFFIC_LOCK_TABLE,
            TRAFFIC_LOCK_CHAIN,
        ]);
        rule.extend(strings(tail));
        rule.push(";".into());
        rule
    };
    let mut arguments = strings(&[
        "add",
        "table",
        "inet",
        TRAFFIC_LOCK_TABLE,
        ";",
        "add",
        "chain",
        "inet",
        TRAFFIC_LOCK_TABLE,
        TRAFFIC_LOCK_CHAIN,
        "{ type filter hook output priority filter; policy accept; }",
        ";",
        "flush",
        "chain",
        "inet",
        TRAFFIC_LOCK_TABLE,
        TRAFFIC_LOCK_CHAIN,
        ";",
    ]);
    arguments.extend(rule(&["oifname", "lo", "accept"]));
    arguments.extend(rule(&["oifname", TUN_DEVICE, "accept"]));
    arguments.extend(rule(&["ct", "direction", "reply", "accept"]));
    arguments.extend(rule(&[
        "socket",
        "cgroupv2",
        "level",
        &level.to_string(),
        &cgroup,
        "accept",
    ]));
    if let Some((scope, scope_level)) = &escape {
        arguments.extend(rule(&[
            "socket",
            "cgroupv2",
            "level",
            &scope_level.to_string(),
            scope,
            "accept",
        ]));
    }
    arguments.extend(rule(&["meta", "mark", ROUTE_ESCAPE_MARK, "accept"]));
    arguments.extend(rule(&["ip", "daddr", TRAFFIC_LOCK_LOCAL_V4, "accept"]));
    arguments.extend(rule(&["ip6", "daddr", TRAFFIC_LOCK_LOCAL_V6, "accept"]));
    arguments.extend(rule(&["udp", "dport", "{ 67, 547 }", "accept"]));
    arguments.extend(rule(&[
        "reject",
        "with",
        "icmpx",
        "type",
        "admin-prohibited",
    ]));
    arguments.pop();
    Some(arguments)
}

fn nft_route_table_exists() -> Result<bool, LifecycleFailure> {
    let arguments = strings(&["list", "table", "inet", ROUTE_ESCAPE_TABLE]);
    system_tool_status(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"], &arguments)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn system_tool_status(candidates: &[&str], arguments: &[String]) -> Result<bool, LifecycleFailure> {
    let program = trusted_system_tool(candidates)?;
    Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|_| route_escape_unavailable())
}

fn system_tool_output(
    candidates: &[&str],
    arguments: &[String],
) -> Result<String, LifecycleFailure> {
    let program = trusted_system_tool(candidates)?;
    let output = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| route_escape_unavailable())?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(route_escape_unavailable());
    }
    String::from_utf8(output.stdout).map_err(|_| route_escape_unavailable())
}

fn trusted_system_tool(candidates: &[&str]) -> Result<PathBuf, LifecycleFailure> {
    candidates
        .iter()
        .map(Path::new)
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.file_type().is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.mode() & 0o111 != 0
            })
        })
        .map(Path::to_path_buf)
        .ok_or_else(route_escape_unavailable)
}

fn process_cgroup(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/') && path.len() <= 512)
        .map(str::to_owned)
}

fn process_family(root: &ProcessIdentity) -> Result<ProcessFamily, LifecycleFailure> {
    let entries = same_uid_process_entries(root.uid)?;
    select_process_family(root, &entries).ok_or_else(invalid_profile)
}

/// One procfs snapshot of the processes owned by `uid` (kernel UID, parent
/// PID and `/proc/<pid>/exe` link). Processes of other UIDs are skipped.
fn same_uid_process_entries(uid: u32) -> Result<Vec<ProcessFamilyEntry>, LifecycleFailure> {
    let mut entries = Vec::new();
    for entry in fs::read_dir("/proc")
        .map_err(|_| owned_mismatch())?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.uid() != uid {
            continue;
        }
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(parent_pid) = process_parent_pid(&stat) else {
            continue;
        };
        let process_path = fs::read_link(entry.path().join("exe")).ok();
        entries.push(ProcessFamilyEntry {
            pid,
            parent_pid,
            uid: metadata.uid(),
            process_path,
        });
    }
    Ok(entries)
}

fn process_holds_fuse_device(pid: u32) -> bool {
    let Ok(descriptors) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    descriptors
        .flatten()
        .take(MAX_LAUNCHER_FD_SCAN)
        .any(|descriptor| {
            fs::read_link(descriptor.path()).is_ok_and(|target| target == Path::new(FUSE_DEVICE))
        })
}

fn select_process_family(
    root: &ProcessIdentity,
    entries: &[ProcessFamilyEntry],
) -> Option<ProcessFamily> {
    let processes: BTreeMap<u32, &ProcessFamilyEntry> = entries
        .iter()
        .filter(|entry| entry.uid == root.uid)
        .map(|entry| (entry.pid, entry))
        .collect();
    let app_image_root = app_image_mount_root(&root.exe_path);
    let mut family = BTreeSet::from([root.pid]);
    for entry in processes.values() {
        if app_image_root.as_ref().is_some_and(|mount_root| {
            entry
                .process_path
                .as_ref()
                .is_some_and(|path| path.starts_with(mount_root))
        }) {
            family.insert(entry.pid);
        }
    }
    bounded_process_family(family, &processes)
}

/// Extends `family` with every descendant in `processes`, failing once the
/// family exceeds `MAX_UPSTREAM_PROCESS_FAMILY`.
fn bounded_process_family(
    mut family: BTreeSet<u32>,
    processes: &BTreeMap<u32, &ProcessFamilyEntry>,
) -> Option<ProcessFamily> {
    if family.len() > MAX_UPSTREAM_PROCESS_FAMILY {
        return None;
    }
    loop {
        let previous = family.len();
        for entry in processes.values() {
            if family.contains(&entry.parent_pid) {
                family.insert(entry.pid);
                if family.len() > MAX_UPSTREAM_PROCESS_FAMILY {
                    return None;
                }
            }
        }
        if family.len() == previous {
            break;
        }
    }
    Some(ProcessFamily { pids: family })
}

fn discover_local_transport_addresses(
    profile: &StartProfile,
    root: &ProcessIdentity,
) -> Result<Vec<IpAddr>, LifecycleFailure> {
    // Each refusal names its step: a start that cannot isolate the client's
    // transport fails closed, and the log is the only evidence of why.
    let fail = |step: &str| {
        eprintln!("TunBridge Linux transport discovery failed: {step}");
        local_transport_unavailable()
    };
    let target = (DEFAULT_TEST_HOST, DEFAULT_TEST_PORT)
        .to_socket_addrs()
        .map_err(|_| fail("test host did not resolve"))?
        .find(|address| address.is_ipv4())
        .ok_or_else(|| fail("test host has no IPv4 address"))?;
    let proxy = ("127.0.0.1", profile.upstream_port)
        .to_socket_addrs()
        .map_err(|_| local_transport_unavailable())?
        .next()
        .ok_or_else(local_transport_unavailable)?;
    let auth = match (&profile.username, &profile.password) {
        (Some(username), Some(password)) => Some((username.as_str(), password.as_str())),
        _ => None,
    };
    let target_host = target.ip().to_string();
    let _tunnel = match profile.protocol {
        UpstreamProtocol::Socks5 => socks5::connect(
            proxy,
            &target_host,
            DEFAULT_TEST_PORT,
            auth,
            LOCAL_TRANSPORT_PROBE_TIMEOUT,
        ),
        UpstreamProtocol::Http => httpconnect::connect(
            proxy,
            &target_host,
            DEFAULT_TEST_PORT,
            auth,
            LOCAL_TRANSPORT_PROBE_TIMEOUT,
        ),
    }
    .map_err(|_| fail("the upstream did not open a tunnel to the test host"))?;

    // The tunnel stays open while the family is rescanned so helpers spawned
    // lazily by AppImage launchers and their transport sockets are observable.
    let family = process_family(root)?;
    let socket_inodes = process_family_socket_inodes(&family)?;
    let addresses: BTreeSet<IpAddr> = process_family_remote_endpoints(&socket_inodes)?
        .into_iter()
        .filter(|endpoint| transport_endpoint_allowed(*endpoint, Some(target.ip())))
        .map(|endpoint| endpoint.address)
        .collect();
    if addresses.is_empty() {
        return Err(fail(
            "the upstream family showed no remote transport endpoint",
        ));
    }
    if addresses.len() > MAX_TRANSPORT_ESCAPE_ADDRESSES {
        return Err(fail("the upstream family showed too many remote endpoints"));
    }
    Ok(addresses.into_iter().collect())
}

fn process_family_socket_inodes(family: &ProcessFamily) -> Result<BTreeSet<u64>, LifecycleFailure> {
    let mut inodes = BTreeSet::new();
    for pid in &family.pids {
        let entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse().ok())
            {
                inodes.insert(inode);
            }
        }
    }
    if inodes.is_empty() {
        return Err(local_transport_unavailable());
    }
    Ok(inodes)
}

fn process_family_remote_endpoints(
    socket_inodes: &BTreeSet<u64>,
) -> Result<BTreeSet<SocketEndpoint>, LifecycleFailure> {
    let mut endpoints = BTreeSet::new();
    for (table, ipv6) in [
        ("/proc/net/tcp", false),
        ("/proc/net/tcp6", true),
        ("/proc/net/udp", false),
        ("/proc/net/udp6", true),
    ] {
        let text = fs::read_to_string(table).map_err(|_| local_transport_unavailable())?;
        endpoints.extend(parse_proc_net_remote_endpoints(&text, ipv6, socket_inodes));
    }
    Ok(endpoints)
}

fn parse_proc_net_remote_endpoints(
    table: &str,
    ipv6: bool,
    socket_inodes: &BTreeSet<u64>,
) -> BTreeSet<SocketEndpoint> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            let inode = fields.get(9)?.parse::<u64>().ok()?;
            if !socket_inodes.contains(&inode) {
                return None;
            }
            let (remote_hex, remote_port) = fields.get(2)?.split_once(':')?;
            let port = u16::from_str_radix(remote_port, 16).ok()?;
            (port != 0).then_some(SocketEndpoint {
                address: parse_proc_net_address(remote_hex, ipv6)?,
                port,
            })
        })
        .collect()
}

fn transport_endpoint_allowed(endpoint: SocketEndpoint, probe_target: Option<IpAddr>) -> bool {
    const DNS_PORTS: [u16; 3] = [53, 853, 5353];
    const REJECTED_DOH_IPV4: [Ipv4Addr; 5] = [
        Ipv4Addr::new(223, 5, 5, 5),
        Ipv4Addr::new(223, 6, 6, 6),
        Ipv4Addr::new(120, 53, 53, 53),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
    ];
    routable_transport_address(endpoint.address)
        && probe_target != Some(endpoint.address)
        && !DNS_PORTS.contains(&endpoint.port)
        && !matches!(endpoint.address, IpAddr::V4(address) if REJECTED_DOH_IPV4.contains(&address))
}

fn parse_proc_net_address(value: &str, ipv6: bool) -> Option<IpAddr> {
    if !ipv6 {
        let encoded = u32::from_str_radix(value, 16).ok()?;
        return Some(IpAddr::V4(Ipv4Addr::from(encoded.to_le_bytes())));
    }
    if value.len() != 32 {
        return None;
    }
    let mut octets = [0_u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let encoded = u32::from_str_radix(chunk, 16).ok()?;
        octets[index * 4..index * 4 + 4].copy_from_slice(&encoded.to_le_bytes());
    }
    let address = Ipv6Addr::from(octets);
    Some(
        address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    )
}

fn routable_transport_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

/// An AppImage FUSE mount of one user: `/tmp/.mount_*` and its source name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppImageMount {
    root: PathBuf,
    source: String,
}

const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;

fn app_image_mounts_of(pid: u32, uid: u32) -> Vec<AppImageMount> {
    let Ok(file) = fs::File::open(format!("/proc/{pid}/mountinfo")) else {
        return Vec::new();
    };
    let mut text = String::new();
    if file
        .take(MAX_MOUNTINFO_BYTES)
        .read_to_string(&mut text)
        .is_err()
    {
        return Vec::new();
    }
    parse_app_image_mounts(&text, uid)
}

/// Parses `/proc/<pid>/mountinfo` for FUSE mounts at `/tmp/.mount_*` that
/// the given user mounted (`user_id=` super option set by the kernel).
fn parse_app_image_mounts(text: &str, uid: u32) -> Vec<AppImageMount> {
    let owner = format!("user_id={uid}");
    text.lines()
        .filter_map(|line| {
            let (mount, filesystem) = line.split_once(" - ")?;
            let root = PathBuf::from(mount.split_ascii_whitespace().nth(4)?);
            let mut filesystem = filesystem.split_ascii_whitespace();
            let fstype = filesystem.next()?;
            let source = filesystem.next()?;
            let options = filesystem.next()?;
            (fstype.starts_with("fuse.")
                && app_image_mount_root(&root).as_deref() == Some(root.as_path())
                && options.split(',').any(|option| option == owner)
                && !source.is_empty()
                && !source.contains('/'))
            .then(|| AppImageMount {
                root,
                source: source.to_owned(),
            })
        })
        .collect()
}

fn mount_source<'a>(mounts: &'a [AppImageMount], root: &Path) -> Option<&'a str> {
    let mut sources = mounts
        .iter()
        .filter(|mount| mount.root == root)
        .map(|mount| mount.source.as_str());
    match (sources.next(), sources.next()) {
        (Some(source), None) => Some(source),
        _ => None,
    }
}

fn app_image_mount_root(executable: &Path) -> Option<PathBuf> {
    let relative = executable.strip_prefix("/tmp").ok()?;
    let component = relative.components().next()?.as_os_str().to_str()?;
    (component.starts_with(".mount_") && component.len() <= 128)
        .then(|| Path::new("/tmp").join(component))
}

fn process_parent_pid(stat: &str) -> Option<u32> {
    let close = stat.rfind(')')?;
    stat[close + 2..]
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn process_owner_uid(pid: u32) -> Result<u32, LifecycleFailure> {
    fs::metadata(format!("/proc/{pid}"))
        .map(|metadata| metadata.uid())
        .map_err(|_| owned_mismatch())
}

fn process_identity(pid: u32) -> Result<ProcessIdentity, LifecycleFailure> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let metadata = fs::metadata(&proc_root).map_err(|_| owned_mismatch())?;
    let stat = fs::read_to_string(proc_root.join("stat")).map_err(|_| owned_mismatch())?;
    let close = stat.rfind(')').ok_or_else(owned_mismatch)?;
    let fields: Vec<&str> = stat[close + 2..].split_ascii_whitespace().collect();
    let start_time = fields
        .get(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(owned_mismatch)?;
    let exe = fs::read_link(proc_root.join("exe")).map_err(|_| owned_mismatch())?;
    let (exe_dev, exe_ino) = executable_file_identity(&proc_root, &exe)?;
    Ok(ProcessIdentity {
        pid,
        uid: metadata.uid(),
        start_time,
        exe_dev,
        exe_ino,
        exe_path: exe,
    })
}

fn executable_file_identity(
    proc_root: &Path,
    executable: &Path,
) -> Result<(u64, u64), LifecycleFailure> {
    match fs::metadata(proc_root.join("exe")) {
        Ok(metadata) => Ok((metadata.dev(), metadata.ino())),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let maps = fs::read_to_string(proc_root.join("maps")).map_err(|_| owned_mismatch())?;
            mapped_executable_identity(&maps, executable).ok_or_else(owned_mismatch)
        }
        Err(_) => Err(owned_mismatch()),
    }
}

fn mapped_executable_identity(maps: &str, executable: &Path) -> Option<(u64, u64)> {
    for line in maps.lines() {
        let mut rest = line;
        let mut fields = Vec::with_capacity(5);
        for _ in 0..5 {
            rest = rest.trim_start_matches(char::is_whitespace);
            let end = rest.find(char::is_whitespace)?;
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let mapped_path = Path::new(rest.trim_start_matches(char::is_whitespace));
        if fields[2] != "00000000" || mapped_path != executable {
            continue;
        }
        let (major, minor) = fields[3].split_once(':')?;
        let major = u32::from_str_radix(major, 16).ok()?;
        let minor = u32::from_str_radix(minor, 16).ok()?;
        let inode = fields[4].parse::<u64>().ok()?;
        if inode == 0 {
            continue;
        }
        return Some((libc::makedev(major, minor), inode));
    }
    None
}

fn process_owns_listener(pid: u32, port: u16) -> Result<bool, LifecycleFailure> {
    let inodes = listener_inodes(port)?;
    if inodes.is_empty() {
        return Ok(false);
    }
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| owned_mismatch())?;
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        {
            if inodes.contains(&inode) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Returns the processes holding the exact loopback listener, or `None` when
/// nothing listens on the port. The scan stops once ownership is ambiguous.
fn listener_owner_pids(port: u16) -> Result<Option<BTreeSet<u32>>, LifecycleFailure> {
    let inodes = listener_inodes(port)?;
    if inodes.is_empty() {
        return Ok(None);
    }
    let mut owners = BTreeSet::new();
    for entry in fs::read_dir("/proc")
        .map_err(|_| owned_mismatch())?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(descriptors) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let owns = descriptors.flatten().any(|descriptor| {
            fs::read_link(descriptor.path()).is_ok_and(|target| {
                target
                    .to_string_lossy()
                    .strip_prefix("socket:[")
                    .and_then(|value| value.strip_suffix(']'))
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|inode| inodes.contains(&inode))
            })
        });
        if owns {
            owners.insert(pid);
            if owners.len() > 1 {
                break;
            }
        }
    }
    Ok(Some(owners))
}

fn listener_inodes(port: u16) -> Result<BTreeSet<u64>, LifecycleFailure> {
    let mut result = BTreeSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = fs::read_to_string(table).map_err(|_| owned_mismatch())?;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" {
                continue;
            }
            let Some((address, port_hex)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(port_hex, 16).ok() != Some(port) {
                continue;
            }
            // /proc/net stores each 32-bit word in host (little-endian) order;
            // decode instead of comparing a big-endian ::1 literal.
            let loopback =
                parse_proc_net_address(address, table.ends_with('6')).is_some_and(|ip| {
                    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
                });
            if loopback {
                if let Ok(inode) = fields[9].parse() {
                    result.insert(inode);
                }
            }
        }
    }
    Ok(result)
}

fn caller_uid(caller: &Caller) -> Result<u32, LifecycleFailure> {
    caller
        .principal_id
        .strip_prefix("uid:")
        .and_then(|value| value.parse().ok())
        .filter(|uid| *uid != 0)
        .ok_or_else(invalid_profile)
}

fn controller_ready(secret: &str) -> bool {
    controller_http("GET", "/version", secret).is_ok()
}

fn controller_http(method: &str, path: &str, secret: &str) -> Result<Vec<u8>, LifecycleFailure> {
    let address = "127.0.0.1:25412"
        .parse()
        .map_err(|_| LifecycleFailure::internal())?;
    controller_http_at(address, method, path, secret)
}

fn controller_http_at(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    secret: &str,
) -> Result<Vec<u8>, LifecycleFailure> {
    const MAX_RESPONSE: usize = tunbridge_core::engine::MAX_ENGINE_RESPONSE_BYTES;
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500))
        .map_err(|_| observability_unavailable())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(2))))
        .map_err(|_| observability_unavailable())?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| observability_unavailable())?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                response.extend_from_slice(&buffer[..size]);
                if response.len() > MAX_RESPONSE {
                    return Err(observability_unavailable());
                }
                if complete_http_response(&response) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && complete_http_response(&response) =>
            {
                break;
            }
            Err(_) => return Err(observability_unavailable()),
        }
    }
    if response.len() > MAX_RESPONSE {
        return Err(observability_unavailable());
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(observability_unavailable)?;
    let headers = &response[..header_end];
    let status_ok = headers.starts_with(b"HTTP/1.1 200")
        || headers.starts_with(b"HTTP/1.0 200")
        || headers.starts_with(b"HTTP/1.1 204")
        || headers.starts_with(b"HTTP/1.0 204");
    if !status_ok {
        return Err(observability_unavailable());
    }
    let body = &response[header_end + 4..];
    if headers
        .windows(b"transfer-encoding: chunked".len())
        .any(|window| window.eq_ignore_ascii_case(b"transfer-encoding: chunked"))
    {
        decode_chunked(body)
    } else {
        let content_length = header_value(headers, b"content-length")
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(body.len());
        if body.len() < content_length {
            return Err(observability_unavailable());
        }
        Ok(body[..content_length].to_vec())
    }
}

fn complete_http_response(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = &response[..header_end];
    let body = &response[header_end + 4..];
    if headers.starts_with(b"HTTP/1.1 204") || headers.starts_with(b"HTTP/1.0 204") {
        return true;
    }
    if headers
        .windows(b"transfer-encoding: chunked".len())
        .any(|window| window.eq_ignore_ascii_case(b"transfer-encoding: chunked"))
    {
        // Only the tail can hold the terminating chunk; scanning the whole
        // body after every read is quadratic for a large /connections reply.
        return body == b"0\r\n\r\n" || body.ends_with(b"\r\n0\r\n\r\n");
    }
    header_value(headers, b"content-length")
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|length| body.len() >= length)
}

fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    headers.split(|byte| *byte == b'\n').find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let (field, value) = line.split_at(line.iter().position(|byte| *byte == b':')?);
        field
            .eq_ignore_ascii_case(name)
            .then_some(value.get(1..)?.strip_prefix(b" ").unwrap_or(&value[1..]))
    })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, LifecycleFailure> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(observability_unavailable)?;
        let size_text =
            std::str::from_utf8(&input[..line_end]).map_err(|_| observability_unavailable())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or(""), 16)
            .map_err(|_| observability_unavailable())?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(observability_unavailable());
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn interface_index(name: &str) -> Result<Option<u32>, LifecycleFailure> {
    let name = std::ffi::CString::new(name).map_err(|_| LifecycleFailure::internal())?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        Ok(Some(index))
    } else {
        let error = std::io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| matches!(code, libc::ENODEV | libc::ENXIO | libc::ENOENT))
        {
            Ok(None)
        } else {
            Err(LifecycleFailure::internal())
        }
    }
}

fn signal(pid: u32, signal: i32) -> Result<(), LifecycleFailure> {
    if unsafe { libc::kill(pid as i32, signal) } == 0 {
        Ok(())
    } else {
        Err(owned_mismatch())
    }
}

fn wait_for_exit(
    pid: u32,
    expected_start_time: u64,
    timeout: Duration,
) -> Result<bool, LifecycleFailure> {
    let deadline = Instant::now() + timeout;
    loop {
        match process_identity(pid) {
            Err(_) if process_is_gone_or_zombie(pid) => return Ok(true),
            // The caller verified this unreaped child before signalling it, so
            // its PID cannot be reused. An exiting process releases its memory
            // map (and `/proc/<pid>/exe`) before it closes its files and turns
            // into a zombie; with thousands of sockets that takes a while.
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(_) => return Err(owned_mismatch()),
            Ok(identity) if identity.start_time != expected_start_time => return Ok(true),
            Ok(_) if Instant::now() >= deadline => return Ok(false),
            Ok(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn process_is_gone_or_zombie(pid: u32) -> bool {
    let path = format!("/proc/{pid}/stat");
    let Ok(stat) = fs::read_to_string(path) else {
        return true;
    };
    let Some(close) = stat.rfind(')') else {
        return false;
    };
    stat[close + 2..]
        .split_ascii_whitespace()
        .next()
        .is_some_and(|state| state == "Z")
}

fn reap_owned_child(pid: u32) -> Result<(), LifecycleFailure> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        if result == pid as i32 {
            return Ok(());
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD)
                && !Path::new(&format!("/proc/{pid}")).exists()
            {
                return Ok(());
            }
        }
        return Err(LifecycleFailure::new(
            ErrorCode::OwnedProcessMismatch,
            "The exited Linux engine could not be reaped safely.",
            false,
        ));
    }
}

fn tun_is_safely_absent_after_exit(
    stage: OwnedStage,
    recorded_ifindex: Option<u32>,
    actual_ifindex: Option<u32>,
) -> bool {
    match (stage, recorded_ifindex, actual_ifindex) {
        (OwnedStage::Pending, None, None) => true,
        (_, Some(recorded), actual) => actual != Some(recorded),
        _ => false,
    }
}

fn write_new_synced(path: &Path, contents: &[u8]) -> Result<(), LifecycleFailure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| LifecycleFailure::internal())?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|_| LifecycleFailure::internal())
}

fn trusted_file_metadata(path: &Path) -> Result<Option<fs::Metadata>, LifecycleFailure> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LifecycleFailure::internal()),
    };
    if metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
    {
        Ok(Some(metadata))
    } else {
        Err(LifecycleFailure::internal())
    }
}

fn remove_trusted_file(path: &Path) -> Result<(), LifecycleFailure> {
    if trusted_file_metadata(path)?.is_some() {
        fs::remove_file(path).map_err(|_| LifecycleFailure::internal())?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), LifecycleFailure> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LifecycleFailure::internal())
}

fn random_hex_32() -> Result<String, LifecycleFailure> {
    let mut bytes = [0_u8; 32];
    let mut filled = 0;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result <= 0 {
            return Err(LifecycleFailure::internal());
        }
        filled += result as usize;
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

const fn invalid_profile() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::InvalidProfile,
        "The Linux start profile is invalid.",
        false,
    )
}

const fn local_transport_unavailable() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::ConfigValidationFailed,
        "The local proxy transport could not be isolated safely.",
        true,
    )
}

const fn route_escape_unavailable() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::ConfigValidationFailed,
        "The local proxy route isolation could not be installed safely.",
        true,
    )
}

const fn engine_integrity() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::EngineIntegrityFailed,
        "The fixed Linux engine integrity validation failed.",
        false,
    )
}

const fn owned_mismatch() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::OwnedProcessMismatch,
        "The Linux process identity could not be verified.",
        false,
    )
}

const fn not_running() -> LifecycleFailure {
    LifecycleFailure::new(ErrorCode::NotRunning, "TunBridge is not running.", true)
}

const fn observability_unavailable() -> LifecycleFailure {
    LifecycleFailure::new(
        ErrorCode::ObservabilityUnavailable,
        "Linux owned-engine observability is unavailable.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_engine_identity_is_frozen() {
        assert_eq!(ENGINE_PATH, "/usr/libexec/tunbridge/mihomo");
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../packaging/deb/engine-manifest.json"))
                .unwrap();
        assert_eq!(manifest["version"], "v1.19.30");
        assert_eq!(manifest["binarySize"], 50_999_422);
        assert_eq!(
            manifest["binarySha256"],
            "8ad44e28fe72be4640254b96741b677f4074991b99186cc4486a1c28ded02b1a"
        );
    }

    #[test]
    fn caller_uid_is_kernel_principal_only() {
        assert_eq!(
            caller_uid(&Caller {
                principal_id: "uid:1001".into(),
                session_id: 0,
                is_admin: false,
            })
            .unwrap(),
            1001
        );
        assert!(caller_uid(&Caller {
            principal_id: "alice".into(),
            session_id: 0,
            is_admin: false,
        })
        .is_err());
    }

    #[test]
    fn clean_state_directory_starts_without_recovery() {
        let data_root = std::env::temp_dir().join(format!(
            "tunbridge-clean-state-{}",
            random_hex_32().unwrap()
        ));
        let lifecycle = LinuxLifecycle {
            engine: "/nonexistent-test-engine".into(),
            data_root: data_root.clone(),
        };
        assert!(lifecycle.initial_record().unwrap().is_none());
        fs::remove_dir(data_root).unwrap();
    }

    #[test]
    fn pending_start_without_a_created_tun_is_safe_to_clean() {
        assert!(tun_is_safely_absent_after_exit(
            OwnedStage::Pending,
            None,
            None
        ));
        assert!(!tun_is_safely_absent_after_exit(
            OwnedStage::Pending,
            None,
            Some(42)
        ));
        assert!(!tun_is_safely_absent_after_exit(
            OwnedStage::Running,
            Some(42),
            Some(42)
        ));
        assert!(tun_is_safely_absent_after_exit(
            OwnedStage::Running,
            Some(42),
            None
        ));
    }

    #[test]
    fn wait_for_exit_follows_a_signalled_child_until_it_can_be_reaped() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let start_time = process_identity(pid).unwrap().start_time;
        signal(pid, libc::SIGTERM).unwrap();
        assert!(wait_for_exit(pid, start_time, Duration::from_secs(5)).unwrap());
        reap_owned_child(pid).unwrap();
        std::mem::forget(child);
    }

    #[test]
    fn controller_reads_a_busy_engine_connections_reply_in_full() {
        use std::io::{Read, Write};
        // About 2.4 MB, roughly 3,000 live connections: above the former 2 MiB limit.
        let body = format!("[{}]", vec!["\"x\""; 600_000].join(","));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = body.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for chunk in served.as_bytes().chunks(16 * 1024) {
                response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                response.extend_from_slice(chunk);
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
            stream.write_all(&response).unwrap();
        });
        let reply = controller_http_at(address, "GET", "/connections", "secret").unwrap();
        server.join().unwrap();
        assert_eq!(reply, body.as_bytes());
    }

    #[test]
    fn chunked_completion_checks_only_the_terminator() {
        let response = |body: &[u8]| {
            let mut bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            bytes.extend_from_slice(body);
            bytes
        };
        assert!(complete_http_response(&response(b"0\r\n\r\n")));
        assert!(complete_http_response(&response(b"2\r\n{}\r\n0\r\n\r\n")));
        assert!(!complete_http_response(&response(b"2\r\n{}\r\n")));
        assert!(!complete_http_response(&response(b"2\r\n{}\r\n0\r\n")));
    }

    #[test]
    fn reboot_recovery_allows_nonpersistent_route_effects_to_be_absent() {
        assert!(!RouteEscapeCleanupMode::AllowAbsent.requires_presence());
        assert!(RouteEscapeCleanupMode::RequirePresent.requires_presence());
    }

    #[test]
    fn executable_identity_falls_back_to_proc_maps_metadata() {
        let maps = concat!(
            "00400000-0040b000 r--p 00000000 00:56 160   /tmp/.mount_proxy/usr/bin/proxy app\n",
            "0040b000-008cf000 r-xp 0000b000 00:56 160   /tmp/.mount_proxy/usr/bin/proxy app\n",
        );
        assert_eq!(
            mapped_executable_identity(maps, Path::new("/tmp/.mount_proxy/usr/bin/proxy app")),
            Some((libc::makedev(0, 0x56), 160))
        );
    }

    #[test]
    fn executable_identity_rejects_non_initial_or_different_mappings() {
        let maps = concat!(
            "0040b000-008cf000 r-xp 0000b000 00:56 160 /tmp/.mount_proxy/usr/bin/proxy\n",
            "008cf000-01366000 r--p 00000000 00:56 161 /tmp/other\n",
        );
        assert_eq!(
            mapped_executable_identity(maps, Path::new("/tmp/.mount_proxy/usr/bin/proxy")),
            None
        );
    }

    #[test]
    fn local_upstream_excludes_same_uid_descendant_helpers() {
        let root = ProcessIdentity {
            pid: 100,
            uid: 1000,
            start_time: 1,
            exe_dev: 2,
            exe_ino: 3,
            exe_path: "/tmp/.mount_proxy/usr/bin/exampleproxy".into(),
        };
        let entries = vec![
            ProcessFamilyEntry {
                pid: 101,
                parent_pid: 100,
                uid: 1000,
                process_path: Some("/tmp/.mount_proxy/usr/bin/exampleproxy_core".into()),
            },
            ProcessFamilyEntry {
                pid: 102,
                parent_pid: 101,
                uid: 1000,
                process_path: Some("/tmp/.mount_proxy/usr/bin/proxy-helper".into()),
            },
            ProcessFamilyEntry {
                pid: 103,
                parent_pid: 100,
                uid: 2000,
                process_path: Some("/tmp/.mount_proxy/usr/bin/other-user".into()),
            },
            ProcessFamilyEntry {
                pid: 104,
                parent_pid: 1,
                uid: 1000,
                process_path: Some("/usr/bin/unrelated".into()),
            },
            ProcessFamilyEntry {
                pid: 105,
                parent_pid: 1,
                uid: 1000,
                process_path: Some("/tmp/.mount_proxy/usr/bin/detached-core".into()),
            },
        ];
        assert_eq!(
            select_process_family(&root, &entries).unwrap().pids,
            BTreeSet::from([100, 101, 102, 105])
        );
    }

    #[test]
    fn local_upstream_family_does_not_depend_on_process_rule_names() {
        let root = ProcessIdentity {
            pid: 100,
            uid: 1000,
            start_time: 1,
            exe_dev: 2,
            exe_ino: 3,
            exe_path: "/usr/bin/proxy".into(),
        };
        let entries = vec![ProcessFamilyEntry {
            pid: 101,
            parent_pid: 100,
            uid: 1000,
            process_path: Some("/usr/bin/invalid,rule".into()),
        }];
        assert_eq!(
            select_process_family(&root, &entries).unwrap().pids,
            BTreeSet::from([100, 101])
        );
    }

    #[test]
    fn local_route_escape_is_derived_only_from_verified_identity() {
        let identity = ProcessIdentity {
            pid: 4242,
            uid: 1000,
            start_time: 987_654,
            exe_dev: 2,
            exe_ino: 3,
            exe_path: "/usr/bin/proxy".into(),
        };
        let route_escape = build_local_route_escape(1000, &identity).unwrap();
        assert_eq!(
            route_escape.scope_unit,
            "tunbridge-upstream-u1000-p4242-s987654.scope"
        );
        assert_eq!(
            route_escape.scope_path,
            "/user.slice/user-1000.slice/tunbridge-upstream-u1000-p4242-s987654.scope"
        );
        assert!(valid_local_route_escape(&route_escape));

        let mut tampered = route_escape;
        tampered.scope_path = "/user.slice/unrelated.scope".into();
        assert!(!valid_local_route_escape(&tampered));
    }

    #[test]
    fn traffic_lock_allows_only_the_tunnel_engine_client_and_lan_then_rejects() {
        let arguments = traffic_lock_arguments("/system.slice/tunbridge.service", None).unwrap();
        let text = arguments.join(" ");
        let rules: Vec<_> = text.split(" ; ").collect();
        assert!(rules[0].starts_with("add table inet tunbridge_lock"));
        assert!(rules.contains(&"flush chain inet tunbridge_lock egress"));
        let chain: Vec<_> = rules
            .iter()
            .filter_map(|rule| rule.strip_prefix("add rule inet tunbridge_lock egress "))
            .collect();
        assert_eq!(
            chain,
            [
                "oifname lo accept",
                "oifname tunbridge accept",
                "ct direction reply accept",
                "socket cgroupv2 level 2 system.slice/tunbridge.service accept",
                "meta mark 0x5442 accept",
                "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept",
                "ip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept",
                "udp dport { 67, 547 } accept",
                "reject with icmpx type admin-prohibited",
            ]
        );
        for hostile in [
            "",
            "/",
            "/system.slice/x;flush ruleset",
            "/a//b",
            "/system.slice/a b",
        ] {
            assert!(traffic_lock_arguments(hostile, None).is_none(), "{hostile}");
            assert!(
                traffic_lock_arguments("/system.slice/tunbridge.service", Some(hostile)).is_none(),
                "{hostile}"
            );
        }
        let with_scope = traffic_lock_arguments(
            "/system.slice/tunbridge.service",
            Some("/user.slice/user-1000.slice/tunbridge-upstream-u1000-p7-s9.scope"),
        )
        .unwrap()
        .join(" ");
        assert!(with_scope.contains(
            "socket cgroupv2 level 3 user.slice/user-1000.slice/tunbridge-upstream-u1000-p7-s9.scope accept ; add rule inet tunbridge_lock egress meta mark 0x5442 accept"
        ));
    }

    #[test]
    fn route_escape_policy_rule_is_fixed_and_exact() {
        assert_eq!(
            route_rule_arguments("-4", "add"),
            strings(&[
                "-4", "rule", "add", "priority", "8999", "fwmark", "0x5442", "lookup", "main",
            ])
        );
        assert_eq!(
            route_rule_arguments("-6", "delete"),
            strings(&[
                "-6", "rule", "delete", "priority", "8999", "fwmark", "0x5442", "lookup", "main",
            ])
        );
    }

    #[test]
    fn local_upstream_renders_transport_route_without_process_rules() {
        let request = StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: 10801,
                protocol: StandardProtocol::Socks5,
                credentials: None,
                expected_process_id: 100,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: vec!["exampleproxy".into()],
        };
        let upstream = VerifiedRuntimeUpstream {
            identity: ProcessIdentity {
                pid: 100,
                uid: 1000,
                start_time: 1,
                exe_dev: 2,
                exe_ino: 3,
                exe_path: "/tmp/.mount_proxy/usr/bin/exampleproxy".into(),
            },
            process_family: Some(ProcessFamily {
                pids: BTreeSet::from([100]),
            }),
            transport_escape_addresses: vec!["203.0.113.8".parse().unwrap()],
            pinned_remote: None,
        };
        let yaml = render_config(&request, &upstream, &"1".repeat(64)).unwrap();
        assert!(yaml.contains("route-exclude-address"));
        assert!(yaml.contains("203.0.113.8/32"));
        assert!(!yaml.contains("PROCESS-NAME,exampleproxy"));
        assert!(!yaml.contains("PROCESS-NAME,exampleproxy_core"));
    }

    #[test]
    fn proc_socket_tables_yield_only_owned_remote_addresses() {
        let table = concat!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            "  0: 0100007F:2A30 080100CB:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 42\n",
            "  1: 0100007F:2A31 0100007F:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 43\n",
            "  2: 0100007F:2A32 01010101:0050 01 00000000:00000000 00:00000000 00000000 1000 0 99\n",
        );
        assert_eq!(
            parse_proc_net_remote_endpoints(table, false, &BTreeSet::from([42])),
            BTreeSet::from([SocketEndpoint {
                address: "203.0.1.8".parse().unwrap(),
                port: 443,
            }])
        );
    }

    #[test]
    fn transport_candidates_reject_dns_doh_and_probe_destinations() {
        let ordinary = SocketEndpoint {
            address: "203.0.113.8".parse().unwrap(),
            port: 443,
        };
        assert!(transport_endpoint_allowed(ordinary, None));
        assert!(!transport_endpoint_allowed(
            SocketEndpoint {
                address: "117.184.156.246".parse().unwrap(),
                port: 53,
            },
            None
        ));
        assert!(!transport_endpoint_allowed(
            SocketEndpoint {
                address: "223.5.5.5".parse().unwrap(),
                port: 443,
            },
            None
        ));
        assert!(!transport_endpoint_allowed(
            ordinary,
            Some(ordinary.address)
        ));
    }

    fn running_record() -> OwnedEngineRecord {
        OwnedEngineRecord {
            schema_version: 4,
            stage: OwnedStage::Running,
            owner_uid: 1000,
            engine_pid: 50,
            engine_start_time: 5,
            engine_exe_dev: 6,
            engine_exe_ino: 7,
            upstream_pid: 100,
            upstream_port: 10801,
            upstream_start_time: 10,
            upstream_exe_dev: 2,
            upstream_exe_ino: 3,
            upstream_exe_path: Some("/usr/bin/proxy".into()),
            upstream_launcher_path: Some("/usr/bin/proxy".into()),
            adopted_scope_root: None,
            remote_upstream: false,
            local_transport_escape: vec!["203.0.113.8".parse().unwrap()],
            local_route_escape: None,
            tun_ifindex: Some(42),
            controller_secret: "1".repeat(64),
        }
    }

    fn no_launcher(_: &ProcessIdentity) -> Option<String> {
        None
    }

    fn process(pid: u32, uid: u32, start_time: u64, exe_path: &str) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            uid,
            start_time,
            exe_dev: 2,
            exe_ino: 3,
            exe_path: exe_path.into(),
        }
    }

    #[test]
    fn engine_exit_is_unhealthy_but_unverified_provenance_is_unknown() {
        let record = running_record();
        let mut engine = process(50, 0, 5, "/usr/libexec/tunbridge/mihomo");
        engine.exe_dev = 6;
        engine.exe_ino = 7;
        assert_eq!(classify_engine(&record, &engine).0, HealthSignal::Healthy);

        let mut reused = engine.clone();
        reused.start_time = 99;
        assert_eq!(classify_engine(&record, &reused).0, HealthSignal::Unhealthy);

        let mut replaced = engine;
        replaced.exe_ino = 8;
        assert_eq!(classify_engine(&record, &replaced).0, HealthSignal::Unknown);
    }

    #[test]
    fn adapter_read_errors_and_foreign_interfaces_never_trigger_cleanup() {
        assert_eq!(
            classify_adapter(Some(42), Ok(Some(42))).0,
            HealthSignal::Healthy
        );
        assert_eq!(
            classify_adapter(Some(42), Ok(None)).0,
            HealthSignal::Unhealthy
        );
        assert_eq!(
            classify_adapter(Some(42), Ok(Some(43))).0,
            HealthSignal::Unknown
        );
        assert_eq!(
            classify_adapter(Some(42), Err(LifecycleFailure::internal())).0,
            HealthSignal::Unknown
        );
    }

    #[test]
    fn exited_upstream_without_a_listener_is_unavailable_not_unknown() {
        let record = running_record();
        let sample = classify_upstream_replacement(
            &record,
            None,
            |_| panic!("no listener owner must be inspected"),
            no_launcher,
        );
        assert_eq!(sample.0, UpstreamSample::Signal(HealthSignal::Unhealthy));
    }

    #[test]
    fn restarted_upstream_from_the_recorded_executable_is_rebindable() {
        let record = running_record();
        let owners = BTreeSet::from([200]);
        let sample = classify_upstream_replacement(
            &record,
            Some(&owners),
            |pid| Ok(process(pid, 1000, 20, "/usr/bin/proxy")),
            no_launcher,
        );
        assert_eq!(
            sample.0,
            UpstreamSample::Restarted(RestartedUpstream {
                previous_pid: 100,
                previous_start_time: 10,
                pid: 200,
                start_time: 20,
            })
        );
    }

    #[test]
    fn unprovable_upstream_replacements_stay_unknown() {
        let record = running_record();
        let single = BTreeSet::from([200]);
        let unknown = UpstreamSample::Signal(HealthSignal::Unknown);
        for (owner_uid, exe) in [(2000, "/usr/bin/proxy"), (1000, "/usr/bin/other")] {
            assert_eq!(
                classify_upstream_replacement(
                    &record,
                    Some(&single),
                    |pid| Ok(process(pid, owner_uid, 20, exe)),
                    no_launcher,
                )
                .0,
                unknown
            );
        }
        assert_eq!(
            classify_upstream_replacement(
                &record,
                Some(&BTreeSet::from([200, 201])),
                |pid| Ok(process(pid, 1000, 20, "/usr/bin/proxy")),
                no_launcher,
            )
            .0,
            unknown
        );
        assert_eq!(
            classify_upstream_replacement(
                &record,
                Some(&BTreeSet::new()),
                |_| panic!("an unattributed listener must not be inspected"),
                no_launcher,
            )
            .0,
            unknown
        );
        assert_eq!(
            classify_upstream_replacement(
                &record,
                Some(&single),
                |_| Err(owned_mismatch()),
                no_launcher
            )
            .0,
            unknown
        );
        let mut legacy = running_record();
        legacy.upstream_exe_path = None;
        assert_eq!(
            classify_upstream_replacement(
                &legacy,
                Some(&single),
                |pid| Ok(process(pid, 1000, 20, "/usr/bin/proxy")),
                no_launcher,
            )
            .0,
            unknown
        );
    }

    #[test]
    fn transport_drift_only_counts_unpinned_routable_transports() {
        let escape = vec!["203.0.113.8".parse().unwrap()];
        let pinned = SocketEndpoint {
            address: "203.0.113.8".parse().unwrap(),
            port: 443,
        };
        let dns = SocketEndpoint {
            address: "198.51.100.53".parse().unwrap(),
            port: 53,
        };
        assert!(!transport_escape_drifted(
            &escape,
            &BTreeSet::from([pinned, dns])
        ));
        let switched = SocketEndpoint {
            address: "203.0.113.9".parse().unwrap(),
            port: 443,
        };
        assert!(transport_escape_drifted(
            &escape,
            &BTreeSet::from([pinned, switched])
        ));
    }

    #[test]
    fn rebind_replaces_the_scope_mark_in_one_nft_transaction() {
        let identity = process(4343, 1000, 987_655, "/usr/bin/proxy");
        let mut route_escape = build_local_route_escape(1000, &identity).unwrap();
        route_escape.stage = RouteEscapeStage::Active;
        assert_eq!(
            route_escape_scope_replacement_arguments(&route_escape),
            strings(&[
                "flush",
                "chain",
                "inet",
                "tunbridge_route_escape",
                "output",
                ";",
                "add",
                "rule",
                "inet",
                "tunbridge_route_escape",
                "output",
                "socket",
                "cgroupv2",
                "level",
                "3",
                "user.slice/user-1000.slice/tunbridge-upstream-u1000-p4343-s987655.scope",
                "meta",
                "mark",
                "set",
                "0x5442",
                ";",
            ])
            .into_iter()
            .chain(route_escape_source_nat_arguments())
            .collect::<Vec<_>>()
        );
        let nat = route_escape_source_nat_arguments().join(" ");
        assert!(nat.contains("type nat hook postrouting priority srcnat"));
        assert!(
            nat.contains("meta mark 0x5442 oifname != tunbridge ip saddr 198.18.0.0/15 masquerade")
        );
        assert!(nat.contains(
            "meta mark 0x5442 oifname != tunbridge ip6 saddr fdfe:dcba:9876::/48 masquerade"
        ));
        assert!(!nat.ends_with(';'));
        assert!(nat.contains(
            "meta mark 0x5442 oifname tunbridge ip daddr 198.18.0.0/15 snat ip to 192.0.0.8"
        ));
        assert_eq!(
            fake_ip_rule_arguments("add").join(" "),
            "-4 rule add priority 8998 fwmark 0x5442 to 198.18.0.0/15 lookup 2022"
        );
    }

    #[test]
    fn an_interrupted_rebind_journal_is_recoverable_only_for_the_same_owner() {
        let mut previous =
            build_local_route_escape(1000, &process(4242, 1000, 1, "/usr/bin/proxy")).unwrap();
        let mut rebound =
            build_local_route_escape(1000, &process(4343, 1000, 2, "/usr/bin/proxy")).unwrap();
        assert!(!interrupted_upstream_rebind(&previous, &rebound));
        previous.stage = RouteEscapeStage::Active;
        rebound.stage = RouteEscapeStage::Active;
        assert!(interrupted_upstream_rebind(&previous, &rebound));
        assert!(!interrupted_upstream_rebind(&previous, &previous));
        let mut other_owner =
            build_local_route_escape(1001, &process(4343, 1001, 2, "/usr/bin/proxy")).unwrap();
        other_owner.stage = RouteEscapeStage::Active;
        assert!(!interrupted_upstream_rebind(&previous, &other_owner));
    }

    #[test]
    fn recorded_executable_path_is_optional_and_bounded() {
        let mut record = running_record();
        record.upstream_exe_path = None;
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("upstreamExePath"));
        let parsed: OwnedEngineRecord = serde_json::from_str(&json).unwrap();
        assert!(parsed.upstream_exe_path.is_none());

        assert_eq!(
            recordable_exe_path(Path::new("/tmp/.mount_proxy/usr/bin/proxy app")).as_deref(),
            Some("/tmp/.mount_proxy/usr/bin/proxy app")
        );
        assert!(recordable_exe_path(Path::new("relative/proxy")).is_none());
        assert!(recordable_exe_path(Path::new("/usr/bin/proxy\n")).is_none());
        assert!(recordable_exe_path(&PathBuf::from(format!("/{}", "a".repeat(4096)))).is_none());
    }

    #[test]
    fn proc_ipv6_address_parser_handles_kernel_word_endianness() {
        assert_eq!(
            parse_proc_net_address("00000000000000000000000001000000", true),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    const APPIMAGE: &str = "/home/user/Downloads/exampleproxy-1.0.0.AppImage";
    const OLD_MOUNT_EXE: &str = "/tmp/.mount_examplGGlJiA/usr/bin/exampleproxy";
    const NEW_MOUNT_EXE: &str = "/tmp/.mount_examploMIfmg/usr/bin/exampleproxy";
    const ADOPTED_SCOPE: &str =
        "/user.slice/user-1000.slice/tunbridge-upstream-u1000-p100-s10.scope";

    fn entry(pid: u32, parent_pid: u32, uid: u32, path: &str) -> ProcessFamilyEntry {
        ProcessFamilyEntry {
            pid,
            parent_pid,
            uid,
            process_path: Some(path.into()),
        }
    }

    fn app_image_record() -> OwnedEngineRecord {
        let mut record = running_record();
        record.upstream_exe_path = Some(OLD_MOUNT_EXE.into());
        record.upstream_launcher_path = Some(APPIMAGE.into());
        record
    }

    /// Observed Omarchy tree: the runtime execs AppRun (exampleproxy) and its
    /// forked child keeps serving the FUSE mount.
    fn forked_runtime_tree() -> Vec<ProcessFamilyEntry> {
        vec![
            entry(900, 1, 1000, "/usr/lib/systemd/systemd"),
            entry(15434, 900, 1000, NEW_MOUNT_EXE),
            entry(15443, 15434, 1000, APPIMAGE),
            entry(
                15450,
                15434,
                1000,
                "/tmp/.mount_examploMIfmg/usr/bin/exampleproxy_core",
            ),
            entry(15460, 15434, 1000, "/usr/bin/xdg-open"),
            entry(16000, 900, 1000, "/usr/bin/chromium"),
        ]
    }

    #[test]
    fn sibling_runtime_is_linked_through_the_kernel_mount_table() {
        // Observed on Omarchy: the runtime and the client are siblings under
        // the user manager after the runtime daemonized.
        const MOUNT: &str = "/tmp/.mount_examplHKBahL";
        const CLIENT: &str = "/tmp/.mount_examplHKBahL/usr/bin/exampleproxy";
        let entries = vec![
            entry(967, 1, 1000, "/usr/lib/systemd/systemd"),
            entry(18941, 967, 1000, CLIENT),
            entry(18947, 967, 1000, APPIMAGE),
            entry(19000, 967, 1000, "/usr/bin/chromium"),
        ];
        let mounts = parse_app_image_mounts(
            "275 64 0:77 / /tmp/.mount_examplHKBahL ro,nosuid,nodev,relatime shared:557 - fuse.exampleproxy-1.0.0.AppImage exampleproxy-1.0.0.AppImage ro,user_id=1000,group_id=1000\n\
             276 64 0:78 / /tmp/.mount_otherXyz ro,relatime - fuse.other.AppImage other.AppImage ro,user_id=1001,group_id=1001\n\
             22 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n",
            1000,
        );
        assert_eq!(
            mounts,
            [AppImageMount {
                root: PathBuf::from(MOUNT),
                source: "exampleproxy-1.0.0.AppImage".into(),
            }]
        );
        let client = process(18941, 1000, 20, CLIENT);
        let fuse = |pid| pid == 18947;
        assert_eq!(
            derive_launcher_path(&client, &entries, &mounts, fuse, |_| true).as_deref(),
            Some(APPIMAGE)
        );
        // Without the mount table the sibling cannot be attributed.
        assert_eq!(
            derive_launcher_path(&client, &entries, &[], fuse, |_| true),
            None
        );
        assert_eq!(
            select_adoption_candidate(
                1000,
                Path::new(APPIMAGE),
                true,
                ADOPTED_SCOPE,
                &entries,
                &mounts,
                |_| None
            ),
            AdoptionCandidate::Family {
                root_pid: 18947,
                family: ProcessFamily {
                    pids: BTreeSet::from([18941, 18947]),
                },
            }
        );
    }

    #[test]
    fn launcher_is_the_fuse_runtime_of_an_app_image_upstream() {
        let upstream = process(15434, 1000, 20, NEW_MOUNT_EXE);
        let fuse = |pid| pid == 15443;
        assert_eq!(
            derive_launcher_path(&upstream, &forked_runtime_tree(), &[], fuse, |_| true).as_deref(),
            Some(APPIMAGE)
        );
        // Parent-chain layout: runtime -> AppRun shell inside the mount -> client.
        let chain = vec![
            entry(500, 1, 1000, APPIMAGE),
            entry(501, 500, 1000, "/tmp/.mount_examploMIfmg/AppRun"),
            entry(502, 501, 1000, NEW_MOUNT_EXE),
        ];
        let client = process(502, 1000, 20, NEW_MOUNT_EXE);
        assert_eq!(
            derive_launcher_path(&client, &chain, &[], |pid| pid == 500, |_| true).as_deref(),
            Some(APPIMAGE)
        );
        // Without the FUSE session the nearest ancestor is not the launcher.
        assert_eq!(
            derive_launcher_path(&client, &chain, &[], |_| false, |_| true),
            None
        );
        // The launcher must be a regular file.
        assert_eq!(
            derive_launcher_path(&client, &chain, &[], |pid| pid == 500, |_| false),
            None
        );
    }

    #[test]
    fn launcher_of_a_plain_executable_is_the_executable() {
        let upstream = process(100, 1000, 10, "/usr/bin/proxy");
        assert_eq!(
            derive_launcher_path(
                &upstream,
                &[],
                &[],
                |_| panic!("no scan"),
                |_| panic!("no scan")
            )
            .as_deref(),
            Some("/usr/bin/proxy")
        );
        assert_eq!(
            recordable_launcher_path(Path::new("/usr/bin/proxy (deleted)")),
            None
        );
        assert_eq!(recordable_launcher_path(Path::new(OLD_MOUNT_EXE)), None);
    }

    #[test]
    fn launcher_is_unknown_for_a_missing_parent_or_another_uid() {
        let client = process(502, 1000, 20, NEW_MOUNT_EXE);
        let other_uid = vec![
            entry(500, 1, 0, APPIMAGE),
            entry(502, 500, 1000, NEW_MOUNT_EXE),
        ];
        assert_eq!(
            derive_launcher_path(&client, &other_uid, &[], |_| true, |_| true),
            None
        );
        let orphan = vec![entry(502, 499, 1000, NEW_MOUNT_EXE)];
        assert_eq!(
            derive_launcher_path(&client, &orphan, &[], |_| true, |_| true),
            None
        );
        // The upstream itself must be in the same-UID snapshot.
        assert_eq!(
            derive_launcher_path(&client, &[], &[], |_| true, |_| true),
            None
        );
        // Two FUSE runtimes for one mount are ambiguous.
        let mut doubled = forked_runtime_tree();
        doubled.push(entry(15444, 15434, 1000, "/home/user/other.AppImage"));
        let upstream = process(15434, 1000, 20, NEW_MOUNT_EXE);
        assert_eq!(
            derive_launcher_path(
                &upstream,
                &doubled,
                &[],
                |pid| pid == 15443 || pid == 15444,
                |_| true
            ),
            None
        );
    }

    #[test]
    fn adoption_selects_exactly_one_restarted_app_image_family() {
        let selection = select_adoption_candidate(
            1000,
            Path::new(APPIMAGE),
            true,
            ADOPTED_SCOPE,
            &forked_runtime_tree(),
            &[],
            |_| Some("/user.slice/user-1000.slice/app-Hyprland-gtk-launch.scope".into()),
        );
        assert_eq!(
            selection,
            AdoptionCandidate::Family {
                root_pid: 15443,
                family: ProcessFamily {
                    pids: BTreeSet::from([15434, 15443, 15450, 15460]),
                },
            }
        );
    }

    #[test]
    fn adoption_of_a_plain_executable_takes_its_descendants() {
        let entries = vec![
            entry(300, 1, 1000, "/usr/bin/proxy"),
            entry(301, 300, 1000, "/usr/bin/proxy"),
            entry(302, 301, 1000, "/usr/bin/helper"),
            entry(400, 1, 1000, "/usr/bin/unrelated"),
        ];
        assert_eq!(
            select_adoption_candidate(
                1000,
                Path::new("/usr/bin/proxy"),
                false,
                ADOPTED_SCOPE,
                &entries,
                &[],
                |_| None
            ),
            AdoptionCandidate::Family {
                root_pid: 300,
                family: ProcessFamily {
                    pids: BTreeSet::from([300, 301, 302]),
                },
            }
        );
    }

    #[test]
    fn adoption_rejects_absent_ambiguous_foreign_and_adopted_families() {
        let none = |_| None;
        let launcher = Path::new(APPIMAGE);
        // No restarted client.
        let idle = vec![entry(16000, 1, 1000, "/usr/bin/chromium")];
        assert_eq!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &idle, &[], none),
            AdoptionCandidate::None
        );
        // A runtime whose mount is not visible yet is not adopted.
        let unmounted = vec![entry(15443, 900, 1000, APPIMAGE)];
        assert_eq!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &unmounted, &[], none),
            AdoptionCandidate::None
        );
        // Two independent clients of the same launcher.
        let mut two = forked_runtime_tree();
        two.extend([
            entry(
                17000,
                900,
                1000,
                "/tmp/.mount_examploAAAAAA/usr/bin/exampleproxy",
            ),
            entry(17001, 17000, 1000, APPIMAGE),
        ]);
        assert_eq!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &two, &[], none),
            AdoptionCandidate::Ambiguous
        );
        // Another UID's client is never considered.
        let foreign: Vec<_> = forked_runtime_tree()
            .into_iter()
            .map(|mut process| {
                process.uid = 2000;
                process
            })
            .collect();
        assert_eq!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &foreign, &[], none),
            AdoptionCandidate::None
        );
        // A same-UID family mixed with a foreign process excludes that process.
        let mut mixed = forked_runtime_tree();
        mixed.push(entry(
            15470,
            15434,
            2000,
            "/tmp/.mount_examploMIfmg/usr/bin/other",
        ));
        assert!(matches!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &mixed, &[], none),
            AdoptionCandidate::Family { family, .. } if !family.pids.contains(&15470)
        ));
        // Already in the active transport scope.
        assert_eq!(
            select_adoption_candidate(
                1000,
                launcher,
                true,
                ADOPTED_SCOPE,
                &forked_runtime_tree(),
                &[],
                |_| { Some(ADOPTED_SCOPE.into()) }
            ),
            AdoptionCandidate::AlreadyAdopted
        );
        // Beyond the process bound.
        let mut large = forked_runtime_tree();
        large.extend((0..MAX_UPSTREAM_PROCESS_FAMILY as u32).map(|index| {
            entry(
                20000 + index,
                15450,
                1000,
                "/tmp/.mount_examploMIfmg/usr/bin/worker",
            )
        }));
        assert_eq!(
            select_adoption_candidate(1000, launcher, true, ADOPTED_SCOPE, &large, &[], none),
            AdoptionCandidate::Ambiguous
        );
    }

    #[test]
    fn app_image_restart_is_rebindable_only_with_the_recorded_launcher() {
        let record = app_image_record();
        let owners = BTreeSet::from([15434]);
        let accept = classify_upstream_replacement(
            &record,
            Some(&owners),
            |pid| Ok(process(pid, 1000, 20, NEW_MOUNT_EXE)),
            |_| Some(APPIMAGE.into()),
        );
        assert!(matches!(accept.0, UpstreamSample::Restarted(_)));

        let unknown = UpstreamSample::Signal(HealthSignal::Unknown);
        for (exe, launcher) in [
            // Another launcher with the same in-image path.
            (NEW_MOUNT_EXE, Some("/home/user/Downloads/other.AppImage")),
            // No provable launcher.
            (NEW_MOUNT_EXE, None),
            // Another program inside the same image.
            (
                "/tmp/.mount_examploMIfmg/usr/bin/exampleproxy_core",
                Some(APPIMAGE),
            ),
            // Same file name outside any AppImage mount.
            ("/opt/exampleproxy/usr/bin/exampleproxy", Some(APPIMAGE)),
        ] {
            assert_eq!(
                classify_upstream_replacement(
                    &record,
                    Some(&owners),
                    |pid| Ok(process(pid, 1000, 20, exe)),
                    |_| launcher.map(str::to_owned),
                )
                .0,
                unknown
            );
        }
        // Another UID never matches, even with the recorded launcher.
        assert_eq!(
            classify_upstream_replacement(
                &record,
                Some(&owners),
                |pid| Ok(process(pid, 2000, 20, NEW_MOUNT_EXE)),
                |_| Some(APPIMAGE.into()),
            )
            .0,
            unknown
        );
        // A record without a launcher keeps the exact-path rule.
        let mut legacy = app_image_record();
        legacy.upstream_launcher_path = None;
        assert_eq!(
            classify_upstream_replacement(
                &legacy,
                Some(&owners),
                |pid| Ok(process(pid, 1000, 20, NEW_MOUNT_EXE)),
                |_| Some(APPIMAGE.into()),
            )
            .0,
            unknown
        );
    }

    #[test]
    fn adopted_scope_root_names_the_active_scope_and_survives_a_rebind() {
        let mut record = app_image_record();
        let mut adopted =
            build_local_route_escape(1000, &process(15443, 1000, 30, APPIMAGE)).unwrap();
        adopted.stage = RouteEscapeStage::Active;
        record.local_route_escape = Some(adopted.clone());
        // The adopted scope does not name the recorded upstream on its own.
        assert!(!route_escape_names_scope_root(&record, &adopted));
        record.adopted_scope_root = Some(ScopeRoot {
            pid: 15443,
            start_time: 30,
        });
        assert!(route_escape_names_scope_root(&record, &adopted));
        // An interrupted adoption is recoverable like an interrupted rebind.
        let mut original =
            build_local_route_escape(1000, &process(100, 1000, 10, OLD_MOUNT_EXE)).unwrap();
        original.stage = RouteEscapeStage::Active;
        assert!(interrupted_upstream_rebind(&original, &adopted));

        // A reused scope keeps naming the adopted root after the rebind ...
        let rebound = process(15434, 1000, 20, NEW_MOUNT_EXE);
        assert_eq!(
            scope_root_for(&adopted, &rebound),
            Some(ScopeRoot {
                pid: 15443,
                start_time: 30,
            })
        );
        // ... and none is recorded when the scope names the upstream itself.
        assert_eq!(
            scope_root_for(&adopted, &process(15443, 1000, 30, APPIMAGE)),
            None
        );

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"upstreamLauncherPath\""));
        assert!(json.contains("\"adoptedScopeRoot\":{\"pid\":15443,\"startTime\":30}"));
        let parsed: OwnedEngineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.adopted_scope_root, record.adopted_scope_root);
        assert_eq!(parsed.upstream_launcher_path.as_deref(), Some(APPIMAGE));

        let mut plain = running_record();
        plain.upstream_launcher_path = None;
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("upstreamLauncherPath"));
        assert!(!json.contains("adoptedScopeRoot"));
    }
}
