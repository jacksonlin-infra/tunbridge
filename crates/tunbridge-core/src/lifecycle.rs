use crate::config;
use crate::engine;
use crate::netstate::{check_recovery, RecoveryCheck};
use crate::platform::model::NetSnapshot;
use crate::platform::{NetworkInspector, Privilege};
use crate::probe;
use crate::profile::Profile;
use crate::state::StatePaths;
use crate::{CoreError, Result};
use serde::Serialize;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
pub struct UpReport {
    pub pid: u32,
    pub controller: String,
    pub adapter_present: bool,
    pub engine_version: String,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub running: bool,
    pub pid: Option<u32>,
    pub controller: Option<String>,
    pub connections: Option<usize>,
    pub download_total: Option<u64>,
    pub upload_total: Option<u64>,
}

/// Non-cryptographic run secret; enough to keep the loopback controller from
/// being trivially reachable by other local users. Hardened in M2 (service).
pub fn gen_secret() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mix = nanos ^ ((std::process::id() as u128) << 64) ^ (nanos.rotate_left(17));
    format!("{:016x}", mix as u64)
}

fn controller_ready(controller: &str, secret: &str, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if engine::rest_version(controller, secret, Duration::from_millis(500)).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(300));
    }
    false
}

trait UpOps {
    fn preflight_upstream(&self, profile: &Profile) -> Result<()>;
    fn spawn(&self, engine_path: &Path, config: &Path, workdir: &Path) -> Result<u32>;
    fn controller_ready(&self, controller: &str, secret: &str) -> bool;
    fn adapter_ready(&self, inspector: &dyn NetworkInspector, tun_name: &str) -> bool;
    fn transparent_self_test(&self) -> Result<()>;
    fn engine_version(&self, controller: &str, secret: &str) -> String;
    fn stop_owned(&self, pid: u32, engine_path: &Path) -> Result<()>;
}

struct SystemUpOps;

impl UpOps for SystemUpOps {
    fn preflight_upstream(&self, profile: &Profile) -> Result<()> {
        let result = probe::test_upstream(
            &profile.upstream,
            probe::DEFAULT_TEST_HOST,
            probe::DEFAULT_TEST_PORT,
            probe::DEFAULT_TEST_PATH,
            Duration::from_secs(4),
        );
        if result.ok {
            Ok(())
        } else {
            Err(CoreError::Engine(format!(
                "upstream preflight failed: {}",
                result.error.unwrap_or_else(|| "unexpected response".into())
            )))
        }
    }

    fn spawn(&self, engine_path: &Path, config: &Path, workdir: &Path) -> Result<u32> {
        engine::spawn(engine_path, config, workdir)
    }

    fn controller_ready(&self, controller: &str, secret: &str) -> bool {
        controller_ready(controller, secret, Instant::now() + Duration::from_secs(20))
    }

    fn adapter_ready(&self, inspector: &dyn NetworkInspector, tun_name: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if inspector.adapter_exists(tun_name) {
                return true;
            }
            sleep(Duration::from_millis(400));
        }
        false
    }

    fn transparent_self_test(&self) -> Result<()> {
        probe::test_transparent_http(
            probe::DEFAULT_TEST_HOST,
            probe::DEFAULT_TEST_PORT,
            probe::DEFAULT_TEST_PATH,
            Duration::from_secs(8),
        )
        .map(|_| ())
        .map_err(|error| CoreError::Engine(format!("transparent self-test failed: {error}")))
    }

    fn engine_version(&self, controller: &str, secret: &str) -> String {
        engine::rest_version(controller, secret, Duration::from_secs(2))
            .unwrap_or_else(|_| "unknown".into())
    }

    fn stop_owned(&self, pid: u32, engine_path: &Path) -> Result<()> {
        engine::stop_owned(pid, engine_path)
    }
}

pub fn up(
    profile: &Profile,
    engine_path: &Path,
    state: &StatePaths,
    priv_: &dyn Privilege,
    inspector: &dyn NetworkInspector,
) -> Result<UpReport> {
    up_with_process_query(
        profile,
        engine_path,
        state,
        priv_,
        inspector,
        &engine::is_alive,
    )
}

fn up_with_process_query(
    profile: &Profile,
    engine_path: &Path,
    state: &StatePaths,
    priv_: &dyn Privilege,
    inspector: &dyn NetworkInspector,
    is_alive: &dyn Fn(u32) -> Result<bool>,
) -> Result<UpReport> {
    up_with_ops(
        profile,
        engine_path,
        state,
        priv_,
        inspector,
        is_alive,
        &SystemUpOps,
    )
}

fn up_with_ops(
    profile: &Profile,
    engine_path: &Path,
    state: &StatePaths,
    priv_: &dyn Privilege,
    inspector: &dyn NetworkInspector,
    is_alive: &dyn Fn(u32) -> Result<bool>,
    ops: &dyn UpOps,
) -> Result<UpReport> {
    if !priv_.is_elevated() {
        return Err(CoreError::NeedsElevation);
    }

    // Preflight: never spawn a second kernel. A live kernel already owns the
    // controller port, the DNS/mixed ports and the TUN adapter, so a second one
    // fails every bind and only surfaces as a confusing controller timeout.
    if let Some(pid) = state.read_pid() {
        if is_alive(pid)? {
            return Err(CoreError::AlreadyRunning(format!(
                "kernel pid {pid} is running; use `tunbridge down` to stop it first"
            )));
        }
    }
    // A leftover adapter means a kernel we do not track still holds the network
    // (or a previous run died dirty); refuse rather than collide with it.
    if inspector.adapter_exists(&profile.tun_device) {
        return Err(CoreError::AlreadyRunning(format!(
            "tun adapter `{}` already exists (untracked kernel or dirty shutdown); run `tunbridge panic-reset` first",
            profile.tun_device
        )));
    }

    // Validate the upstream before changing routes. Starting TUN with a dead
    // local proxy turns an ordinary configuration error into a system-wide
    // outage.
    ops.preflight_upstream(profile)?;

    state.ensure()?;

    // Snapshot baseline BEFORE touching the network (recovery reference).
    let baseline = inspector.snapshot()?;
    state.save_baseline(&baseline)?;

    // Render and persist the active config + secret.
    let yaml = config::render(profile)?;
    std::fs::write(state.active_config(), &yaml).map_err(|e| CoreError::Io(e.to_string()))?;
    std::fs::write(state.secret_file(), &profile.secret)
        .map_err(|e| CoreError::Io(e.to_string()))?;

    // Spawn kernel.
    let tracked_engine_path =
        std::fs::canonicalize(engine_path).unwrap_or_else(|_| engine_path.to_path_buf());
    let pid = ops.spawn(engine_path, &state.active_config(), &state.root)?;
    if let Err(error) = state.save_engine_path(&tracked_engine_path) {
        return Err(rollback_start(
            ops,
            pid,
            &tracked_engine_path,
            state,
            error.to_string(),
        ));
    }
    if let Err(error) = state.save_pid(pid) {
        return Err(rollback_start(
            ops,
            pid,
            &tracked_engine_path,
            state,
            error.to_string(),
        ));
    }

    // Wait for controller.
    if !ops.controller_ready(&profile.external_controller, &profile.secret) {
        return Err(rollback_start(
            ops,
            pid,
            &tracked_engine_path,
            state,
            "controller did not become ready; see mihomo.err.log",
        ));
    }

    if !ops.adapter_ready(inspector, &profile.tun_device) {
        return Err(rollback_start(
            ops,
            pid,
            &tracked_engine_path,
            state,
            format!("TUN adapter `{}` did not appear", profile.tun_device),
        ));
    }

    if let Err(error) = ops.transparent_self_test() {
        return Err(rollback_start(
            ops,
            pid,
            &tracked_engine_path,
            state,
            error.to_string(),
        ));
    }

    let engine_version = ops.engine_version(&profile.external_controller, &profile.secret);

    Ok(UpReport {
        pid,
        controller: profile.external_controller.clone(),
        adapter_present: true,
        engine_version,
    })
}

fn rollback_start(
    ops: &dyn UpOps,
    pid: u32,
    engine_path: &Path,
    state: &StatePaths,
    reason: impl Into<String>,
) -> CoreError {
    let mut message = reason.into();
    if let Err(error) = ops.stop_owned(pid, engine_path) {
        message.push_str(&format!("; rollback could not stop engine: {error}"));
    }
    if let Err(error) = state.clear() {
        message.push_str(&format!("; rollback could not clear state: {error}"));
    }
    CoreError::Engine(message)
}

pub fn down(
    state: &StatePaths,
    priv_: &dyn Privilege,
    inspector: &dyn NetworkInspector,
    tun_name: &str,
) -> Result<RecoveryCheck> {
    if !priv_.is_elevated() {
        return Err(CoreError::NeedsElevation);
    }
    let pid = state.read_pid().ok_or(CoreError::NotRunning)?;
    stop_tracked_process(state, pid)?;
    sleep(Duration::from_secs(2));

    let baseline = state.read_baseline().unwrap_or(NetSnapshot {
        routes: vec![],
        adapters: vec![],
    });
    let current = inspector.snapshot()?;
    let adapter_present = inspector.adapter_exists(tun_name);
    let check = check_recovery(&baseline, &current, tun_name, adapter_present);
    state.clear()?;
    Ok(check)
}

pub fn status(state: &StatePaths, secret: &str) -> Result<StatusReport> {
    let pid = match state.read_pid() {
        Some(p) => p,
        None => {
            return Ok(StatusReport {
                running: false,
                pid: None,
                controller: None,
                connections: None,
                download_total: None,
                upload_total: None,
            })
        }
    };
    if !engine::is_alive(pid)? {
        return Ok(StatusReport {
            running: false,
            pid: Some(pid),
            controller: None,
            connections: None,
            download_total: None,
            upload_total: None,
        });
    }
    let controller = read_controller_from_active(state).unwrap_or_else(|| "127.0.0.1:25412".into());
    match engine::rest_connections(&controller, secret, Duration::from_secs(2)) {
        Ok(c) => Ok(StatusReport {
            running: true,
            pid: Some(pid),
            controller: Some(controller),
            connections: Some(c.count),
            download_total: Some(c.download_total),
            upload_total: Some(c.upload_total),
        }),
        Err(_) => Ok(StatusReport {
            running: true,
            pid: Some(pid),
            controller: Some(controller),
            connections: None,
            download_total: None,
            upload_total: None,
        }),
    }
}

fn read_controller_from_active(state: &StatePaths) -> Option<String> {
    let raw = std::fs::read_to_string(state.active_config()).ok()?;
    let v: serde_yaml::Value = serde_yaml::from_str(&raw).ok()?;
    v.get("external-controller")?
        .as_str()
        .map(|s| s.to_string())
}

pub fn panic_reset(
    state: &StatePaths,
    priv_: &dyn Privilege,
    inspector: &dyn NetworkInspector,
    tun_name: &str,
) -> Result<RecoveryCheck> {
    if !priv_.is_elevated() {
        return Err(CoreError::NeedsElevation);
    }
    // Without a saved run baseline, snapshot the clean-up starting point. The
    // recovery check will still reject any remaining TunBridge/fake-IP route,
    // while ordinary machine routes are not misclassified as leftovers.
    let baseline = match state.read_baseline() {
        Ok(saved) => saved,
        Err(_) => inspector.snapshot()?,
    };
    // Only kill the exact process identity recorded by TunBridge. Never sweep
    // all mihomo.exe processes: other applications may use the same engine.
    let mut stopped_process = false;
    if let Some(pid) = state.read_pid() {
        stop_tracked_process(state, pid)?;
        stopped_process = true;
    }
    if stopped_process {
        sleep(Duration::from_secs(2));
    }

    inspector.remove_routes_for(tun_name)?;
    inspector.flush_dns()?;

    let current = inspector.snapshot()?;
    let adapter_present = inspector.adapter_exists(tun_name);
    let check = check_recovery(&baseline, &current, tun_name, adapter_present);
    state.clear()?;
    Ok(check)
}

fn stop_tracked_process(state: &StatePaths, pid: u32) -> Result<()> {
    let Some(engine_path) = state.read_engine_path() else {
        if engine::is_alive(pid)? {
            return Err(CoreError::Engine(format!(
                "refusing to stop pid {pid}: tracked engine path is missing"
            )));
        }
        return Ok(());
    };
    engine::stop_owned(pid, &engine_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::model::NetSnapshot;
    use crate::platform::{NetworkInspector, Privilege};
    use crate::Result;
    use std::cell::Cell;

    struct NotAdmin;
    impl Privilege for NotAdmin {
        fn is_elevated(&self) -> bool {
            false
        }
    }

    struct DummyInspector;
    impl NetworkInspector for DummyInspector {
        fn snapshot(&self) -> Result<NetSnapshot> {
            Ok(NetSnapshot {
                routes: vec![],
                adapters: vec![],
            })
        }
        fn adapter_exists(&self, _n: &str) -> bool {
            false
        }
        fn flush_dns(&self) -> Result<()> {
            Ok(())
        }
        fn remove_routes_for(&self, _t: &str) -> Result<()> {
            Ok(())
        }
    }

    struct NormalRouteInspector;
    impl NetworkInspector for NormalRouteInspector {
        fn snapshot(&self) -> Result<NetSnapshot> {
            Ok(NetSnapshot {
                routes: vec!["0.0.0.0/0|Ethernet|192.168.1.1".into()],
                adapters: vec!["Ethernet".into()],
            })
        }
        fn adapter_exists(&self, _n: &str) -> bool {
            false
        }
        fn flush_dns(&self) -> Result<()> {
            Ok(())
        }
        fn remove_routes_for(&self, _t: &str) -> Result<()> {
            Ok(())
        }
    }

    struct IsAdmin;
    impl Privilege for IsAdmin {
        fn is_elevated(&self) -> bool {
            true
        }
    }

    struct FakeUpOps {
        preflight_ok: bool,
        controller_ok: bool,
        adapter_ok: bool,
        transparent_ok: bool,
        spawned: Cell<bool>,
        stopped: Cell<bool>,
    }

    impl FakeUpOps {
        fn all_ok() -> Self {
            Self {
                preflight_ok: true,
                controller_ok: true,
                adapter_ok: true,
                transparent_ok: true,
                spawned: Cell::new(false),
                stopped: Cell::new(false),
            }
        }
    }

    impl UpOps for FakeUpOps {
        fn preflight_upstream(&self, _profile: &Profile) -> Result<()> {
            if self.preflight_ok {
                Ok(())
            } else {
                Err(CoreError::Engine("upstream unavailable".into()))
            }
        }

        fn spawn(&self, _engine_path: &Path, _config: &Path, _workdir: &Path) -> Result<u32> {
            self.spawned.set(true);
            Ok(4242)
        }

        fn controller_ready(&self, _controller: &str, _secret: &str) -> bool {
            self.controller_ok
        }

        fn adapter_ready(&self, _inspector: &dyn NetworkInspector, _tun_name: &str) -> bool {
            self.adapter_ok
        }

        fn transparent_self_test(&self) -> Result<()> {
            if self.transparent_ok {
                Ok(())
            } else {
                Err(CoreError::Engine("transparent path unavailable".into()))
            }
        }

        fn engine_version(&self, _controller: &str, _secret: &str) -> String {
            "v-test".into()
        }

        fn stop_owned(&self, _pid: u32, _engine_path: &Path) -> Result<()> {
            self.stopped.set(true);
            Ok(())
        }
    }

    /// An inspector reporting a leftover TUN adapter, i.e. a kernel we do not
    /// track is still holding the network (the M0/M1 orphan scenario).
    struct OrphanInspector;
    impl NetworkInspector for OrphanInspector {
        fn snapshot(&self) -> Result<NetSnapshot> {
            Ok(NetSnapshot {
                routes: vec![],
                adapters: vec!["tunbridge".into()],
            })
        }
        fn adapter_exists(&self, _n: &str) -> bool {
            true
        }
        fn flush_dns(&self) -> Result<()> {
            Ok(())
        }
        fn remove_routes_for(&self, _t: &str) -> Result<()> {
            Ok(())
        }
    }

    fn test_profile() -> crate::profile::Profile {
        use crate::profile::{Profile, Protocol, Upstream};
        Profile::with_upstream(Upstream {
            host: "127.0.0.1".into(),
            port: 7078,
            protocol: Protocol::Socks5,
            username: None,
            password: None,
            udp: true,
        })
    }

    #[test]
    fn up_refuses_when_tun_adapter_already_exists() {
        // Regression: a leftover kernel holding the adapter/ports made `up`
        // spawn a colliding second kernel whose controller could never bind,
        // surfacing as a confusing "controller did not become ready".
        let sp = StatePaths {
            root: std::env::temp_dir().join("tb-up-orphan"),
        };
        let err = up(
            &test_profile(),
            Path::new("nonexistent.exe"),
            &sp,
            &IsAdmin,
            &OrphanInspector,
        )
        .unwrap_err();
        match err {
            CoreError::AlreadyRunning(msg) => assert!(
                msg.contains("panic-reset"),
                "msg should guide recovery: {msg}"
            ),
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    #[test]
    fn up_refuses_when_tracked_pid_is_alive() {
        // A live tracked kernel must not be duplicated.
        let dir = std::env::temp_dir().join(format!("tb-up-alive-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        sp.ensure().unwrap();
        sp.save_pid(4242).unwrap();
        let err = up_with_process_query(
            &test_profile(),
            Path::new("nonexistent.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|pid| Ok(pid == 4242),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::AlreadyRunning(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_fails_closed_when_process_query_fails() {
        let dir = std::env::temp_dir().join(format!("tb-up-query-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        sp.ensure().unwrap();
        sp.save_pid(4242).unwrap();
        let err = up_with_process_query(
            &test_profile(),
            Path::new("nonexistent.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|_| Err(CoreError::Io("process query denied".into())),
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::Io(msg) if msg.contains("query denied")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_checks_upstream_before_spawning() {
        let dir = std::env::temp_dir().join(format!("tb-up-preflight-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        let mut ops = FakeUpOps::all_ok();
        ops.preflight_ok = false;
        let err = up_with_ops(
            &test_profile(),
            Path::new("fake-engine.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|_| Ok(false),
            &ops,
        )
        .unwrap_err();
        assert!(err.to_string().contains("upstream unavailable"));
        assert!(!ops.spawned.get());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_rolls_back_when_adapter_never_appears() {
        let dir = std::env::temp_dir().join(format!("tb-up-adapter-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        let mut ops = FakeUpOps::all_ok();
        ops.adapter_ok = false;
        let err = up_with_ops(
            &test_profile(),
            Path::new("fake-engine.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|_| Ok(false),
            &ops,
        )
        .unwrap_err();
        assert!(err.to_string().contains("did not appear"));
        assert!(ops.spawned.get());
        assert!(ops.stopped.get());
        assert_eq!(sp.read_pid(), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_rolls_back_when_transparent_self_test_fails() {
        let dir = std::env::temp_dir().join(format!("tb-up-selftest-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        let mut ops = FakeUpOps::all_ok();
        ops.transparent_ok = false;
        let err = up_with_ops(
            &test_profile(),
            Path::new("fake-engine.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|_| Ok(false),
            &ops,
        )
        .unwrap_err();
        assert!(err.to_string().contains("transparent path unavailable"));
        assert!(ops.stopped.get());
        assert_eq!(sp.read_pid(), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn successful_up_always_reports_adapter_present() {
        let dir = std::env::temp_dir().join(format!("tb-up-success-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        let ops = FakeUpOps::all_ok();
        let report = up_with_ops(
            &test_profile(),
            Path::new("fake-engine.exe"),
            &sp,
            &IsAdmin,
            &DummyInspector,
            &|_| Ok(false),
            &ops,
        )
        .unwrap();
        assert!(report.adapter_present);
        assert_eq!(report.engine_version, "v-test");
        assert!(!ops.stopped.get());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn panic_reset_without_saved_baseline_preserves_normal_routes() {
        let dir = std::env::temp_dir().join(format!("tb-reset-clean-{}", std::process::id()));
        let sp = StatePaths { root: dir.clone() };
        let result = panic_reset(&sp, &IsAdmin, &NormalRouteInspector, "tunbridge").unwrap();
        assert!(result.adapter_gone);
        assert!(result.routes_clean);
        assert!(result.added_routes.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_refuses_without_elevation() {
        use crate::profile::{Profile, Protocol, Upstream};
        let profile = Profile::with_upstream(Upstream {
            host: "127.0.0.1".into(),
            port: 7078,
            protocol: Protocol::Socks5,
            username: None,
            password: None,
            udp: true,
        });
        let sp = StatePaths {
            root: std::env::temp_dir().join("tb-up-noadmin"),
        };
        let err = up(
            &profile,
            Path::new("nonexistent.exe"),
            &sp,
            &NotAdmin,
            &DummyInspector,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::NeedsElevation));
    }

    #[test]
    fn gen_secret_is_16_hex() {
        let s = gen_secret();
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
