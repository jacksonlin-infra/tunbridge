use std::{
    io,
    net::TcpStream,
    os::windows::process::CommandExt as _,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::{
    adapter::{installed_wintun_instance_ids, native_adapter_exists, AdapterError},
    config::PreparedServiceConfig,
    integrity::{reject_reparse_point, validate_asset_acl, validate_engine_files, IntegrityError},
    owned::{
        capture_pending_owned_engine, promote_owned_engine_running, remove_pending_adapter,
        OwnedEngineError, OwnedEngineRecord, PendingRuntimeAssets,
    },
    process::normalized_path,
    storage::{ProtectedDataDirectory, StorageError},
};
use crate::{protocol::UpstreamProtocol, state::Caller};
use tunbridge_core::{
    engine, probe,
    profile::{Protocol, Upstream},
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ACTIVE_CONFIG_FILENAME: &str = "active-config.yaml";

/// A spawned engine that remains rollback-owned until all health checks pass.
/// Dropping this value kills and waits for the exact child handle and removes
/// its protected state on a best-effort basis.
struct PendingEngineStart {
    child: Option<Child>,
    record: Option<OwnedEngineRecord>,
    storage: ProtectedDataDirectory,
    state_persisted: bool,
}

impl PendingEngineStart {
    fn record(&self) -> &OwnedEngineRecord {
        self.record.as_ref().expect("captured record is present")
    }

    /// Release rollback ownership only after controller, TUN, and transparent
    /// path checks have succeeded. The process identity is reverified at the
    /// final boundary before its child handle is released.
    fn commit_after_health_checks(mut self) -> Result<OwnedEngineRecord, LaunchError> {
        let running =
            promote_owned_engine_running(self.record()).map_err(LaunchError::OwnedIdentity)?;
        self.storage
            .write_owned_state(&running)
            .map_err(LaunchError::Storage)?;
        self.record = Some(running);
        self.child.take();
        self.state_persisted = false;
        Ok(self.record.take().expect("captured record is present"))
    }

    fn rollback(mut self) -> Result<(), LaunchError> {
        self.terminate_child().map_err(LaunchError::RollbackStop)?;
        remove_pending_adapter(self.record()).map_err(LaunchError::OwnedIdentity)?;
        if self.state_persisted {
            self.storage
                .clear_owned_state()
                .map_err(LaunchError::RollbackStorage)?;
            self.state_persisted = false;
        }
        Ok(())
    }

    fn child_exited(&mut self) -> Result<bool, LaunchError> {
        self.child
            .as_mut()
            .expect("child is present before commit")
            .try_wait()
            .map(|status| status.is_some())
            .map_err(LaunchError::ChildStatus)
    }

    fn terminate_child(&mut self) -> io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Err(kill_error) = child.kill() {
            if child.try_wait()?.is_none() {
                self.child = Some(child);
                return Err(kill_error);
            }
            return Ok(());
        }
        match child.wait() {
            Ok(_) => Ok(()),
            Err(error) => {
                self.child = Some(child);
                Err(error)
            }
        }
    }
}

impl Drop for PendingEngineStart {
    fn drop(&mut self) {
        let had_child = self.child.is_some();
        if !had_child || self.terminate_child().is_err() {
            return;
        }
        if self
            .record
            .as_ref()
            .is_none_or(|record| remove_pending_adapter(record).is_err())
        {
            return;
        }
        if self.state_persisted && self.storage.clear_owned_state().is_ok() {
            self.state_persisted = false;
        }
    }
}

/// Spawn only from an already prepared service transaction. This function
/// revalidates the engine, active config, protected directory, and absence of
/// stale owned state immediately before CreateProcess. It does not publish the
/// IPC start capability; callers must retain the returned guard through all
/// post-spawn health checks.
fn spawn_pending_engine(
    prepared: &PreparedServiceConfig,
    owner: &Caller,
) -> Result<PendingEngineStart, LaunchError> {
    revalidate_prepared_boundary(prepared)?;
    let storage = ProtectedDataDirectory::prepare().map_err(LaunchError::Storage)?;
    if storage
        .read_owned_state()
        .map_err(LaunchError::Storage)?
        .is_some()
    {
        return Err(LaunchError::ExistingOwnedState);
    }

    let preexisting_wintun_instances =
        installed_wintun_instance_ids().map_err(LaunchError::RollbackAdapter)?;
    let child = engine_command(prepared)
        .spawn()
        .map_err(LaunchError::Spawn)?;
    let mut pending = PendingEngineStart {
        child: Some(child),
        record: None,
        storage,
        state_persisted: false,
    };
    let pid = pending.child.as_ref().expect("child is present").id();
    pending.record = Some(
        capture_pending_owned_engine(
            prepared.engine(),
            pid,
            owner,
            PendingRuntimeAssets {
                verified_upstream: prepared.upstream_identity(),
                remote_upstream: prepared.remote_upstream(),
                upstream_host: &prepared.upstream().host,
                upstream_port: prepared.upstream().port,
                upstream_protocol: match prepared.upstream().protocol {
                    Protocol::Socks5 => UpstreamProtocol::Socks5,
                    Protocol::Http => UpstreamProtocol::Http,
                },
                controller: prepared.controller(),
                preexisting_wintun_instances: &preexisting_wintun_instances,
            },
        )
        .map_err(LaunchError::OwnedIdentity)?,
    );
    pending
        .storage
        .write_owned_state(pending.record())
        .map_err(LaunchError::Storage)?;
    pending.state_persisted = true;
    Ok(pending)
}

/// Execute the bounded preflight and post-spawn health transaction. The IPC
/// capability remains independently gated by the server until real elevated
/// acceptance passes.
pub fn start_prepared_engine(
    prepared: &PreparedServiceConfig,
    owner: &Caller,
) -> Result<OwnedEngineRecord, LaunchError> {
    #[cfg(feature = "acceptance-fault-injection")]
    {
        let fault = super::acceptance::active_fault().map_err(LaunchError::AcceptanceFault)?;
        start_with_injection(prepared, owner, &SystemHealthChecks, fault)
    }
    #[cfg(not(feature = "acceptance-fault-injection"))]
    start_transaction(prepared, owner, &SystemHealthChecks, None, false)
}

#[cfg(feature = "acceptance-fault-injection")]
fn start_with_injection(
    prepared: &PreparedServiceConfig,
    owner: &Caller,
    checks: &dyn EngineHealthChecks,
    fault: Option<super::acceptance::AcceptanceFault>,
) -> Result<OwnedEngineRecord, LaunchError> {
    use super::acceptance::AcceptanceFault;

    let injected_health = match fault {
        Some(AcceptanceFault::ControllerNotReady) => Some(HealthStage::Controller),
        Some(AcceptanceFault::TunNotReady) => Some(HealthStage::Tun),
        Some(AcceptanceFault::TransparentSelfTestFailed) => Some(HealthStage::Transparent),
        _ => None,
    };
    start_transaction(
        prepared,
        owner,
        checks,
        injected_health,
        fault == Some(AcceptanceFault::EngineExitsEarly),
    )
}

fn start_transaction(
    prepared: &PreparedServiceConfig,
    owner: &Caller,
    checks: &dyn EngineHealthChecks,
    injected_health: Option<HealthStage>,
    inject_engine_exit: bool,
) -> Result<OwnedEngineRecord, LaunchError> {
    evaluate_pre_spawn_checks(prepared, checks).map_err(LaunchError::HealthCheckFailed)?;
    let mut pending = spawn_pending_engine(prepared, owner)?;
    if inject_engine_exit {
        pending
            .terminate_child()
            .map_err(LaunchError::RollbackStop)?;
        return Err(rollback_health_failure(pending, HealthStage::EngineProcess));
    }
    if let Err(stage) = evaluate_post_spawn_checks(prepared, checks, injected_health) {
        return Err(rollback_health_failure(pending, stage));
    }
    if pending.child_exited()? {
        return Err(rollback_health_failure(pending, HealthStage::EngineProcess));
    }
    pending.commit_after_health_checks()
}

fn rollback_health_failure(pending: PendingEngineStart, stage: HealthStage) -> LaunchError {
    match pending.rollback() {
        Ok(()) => LaunchError::HealthCheckFailed(stage),
        Err(rollback) => LaunchError::HealthCheckRollback {
            stage,
            rollback: Box::new(rollback),
        },
    }
}

fn evaluate_pre_spawn_checks(
    prepared: &PreparedServiceConfig,
    checks: &dyn EngineHealthChecks,
) -> Result<(), HealthStage> {
    let upstream_ready = if prepared.remote_upstream() {
        checks.remote_upstream_ready(prepared.upstream())
    } else {
        checks.upstream_ready(prepared.upstream())
    };
    if !upstream_ready {
        return Err(HealthStage::Upstream);
    }
    if !checks.controller_port_free(prepared.controller()) {
        return Err(HealthStage::ControllerPort);
    }
    if !checks.tun_absent(prepared.tun_device()) {
        return Err(HealthStage::ExistingTun);
    }
    Ok(())
}

fn evaluate_post_spawn_checks(
    prepared: &PreparedServiceConfig,
    checks: &dyn EngineHealthChecks,
    injected_health: Option<HealthStage>,
) -> Result<(), HealthStage> {
    if injected_health == Some(HealthStage::Controller) {
        return Err(HealthStage::Controller);
    }
    if !checks.controller_ready(prepared.controller(), prepared.controller_secret()) {
        return Err(HealthStage::Controller);
    }
    if injected_health == Some(HealthStage::Tun) {
        return Err(HealthStage::Tun);
    }
    if !checks.tun_ready(prepared.tun_device()) {
        return Err(HealthStage::Tun);
    }
    if injected_health == Some(HealthStage::Transparent) {
        return Err(HealthStage::Transparent);
    }
    if !checks.transparent_ready() {
        return Err(HealthStage::Transparent);
    }
    Ok(())
}

trait EngineHealthChecks {
    fn upstream_ready(&self, upstream: &Upstream) -> bool;
    fn remote_upstream_ready(&self, upstream: &Upstream) -> bool;
    fn controller_port_free(&self, controller: &str) -> bool;
    fn tun_absent(&self, tun_device: &str) -> bool;
    fn controller_ready(&self, controller: &str, secret: &str) -> bool;
    fn tun_ready(&self, tun_device: &str) -> bool;
    fn transparent_ready(&self) -> bool;
}

struct SystemHealthChecks;

impl EngineHealthChecks for SystemHealthChecks {
    fn upstream_ready(&self, upstream: &Upstream) -> bool {
        probe::test_upstream(
            upstream,
            probe::DEFAULT_TEST_HOST,
            probe::DEFAULT_TEST_PORT,
            probe::DEFAULT_TEST_PATH,
            Duration::from_secs(4),
        )
        .ok
    }

    fn remote_upstream_ready(&self, upstream: &Upstream) -> bool {
        format!("{}:{}", upstream.host, upstream.port)
            .parse()
            .is_ok_and(|address| {
                TcpStream::connect_timeout(&address, Duration::from_secs(4)).is_ok()
            })
    }

    fn controller_port_free(&self, controller: &str) -> bool {
        controller.parse().is_ok_and(|address| {
            TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_err()
        })
    }

    fn tun_absent(&self, tun_device: &str) -> bool {
        native_adapter_exists(tun_device).is_ok_and(|exists| !exists)
    }

    fn controller_ready(&self, controller: &str, secret: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if engine::rest_version(controller, secret, Duration::from_millis(500)).is_ok() {
                return true;
            }
            sleep(Duration::from_millis(300));
        }
        false
    }

    fn tun_ready(&self, tun_device: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if native_adapter_exists(tun_device).is_ok_and(|exists| exists) {
                return true;
            }
            sleep(Duration::from_millis(400));
        }
        false
    }

    fn transparent_ready(&self) -> bool {
        probe::test_transparent_http(
            probe::DEFAULT_TEST_HOST,
            probe::DEFAULT_TEST_PORT,
            probe::DEFAULT_TEST_PATH,
            Duration::from_secs(8),
        )
        .is_ok()
    }
}

fn revalidate_prepared_boundary(prepared: &PreparedServiceConfig) -> Result<(), LaunchError> {
    let data_root = prepared
        .data_root()
        .canonicalize()
        .map_err(LaunchError::BoundaryIo)?;
    let active_config = prepared
        .active_config()
        .canonicalize()
        .map_err(LaunchError::BoundaryIo)?;
    if active_config.parent() != Some(data_root.as_path())
        || active_config.file_name() != Some(ACTIVE_CONFIG_FILENAME.as_ref())
    {
        return Err(LaunchError::ActiveConfigEscape);
    }
    reject_reparse_point(&data_root, "runtime data directory").map_err(LaunchError::Integrity)?;
    validate_asset_acl(&data_root, "runtime data directory").map_err(LaunchError::Integrity)?;
    reject_reparse_point(&active_config, "active config").map_err(LaunchError::Integrity)?;
    validate_asset_acl(&active_config, "active config").map_err(LaunchError::Integrity)?;

    let install_root = prepared
        .engine()
        .path()
        .parent()
        .ok_or(LaunchError::EnginePath)?;
    let revalidated = validate_engine_files(install_root).map_err(LaunchError::Integrity)?;
    if normalized_path(revalidated.path()) != normalized_path(prepared.engine().path())
        || revalidated.version() != prepared.engine().version()
        || revalidated.size() != prepared.engine().size()
        || revalidated.sha256() != prepared.engine().sha256()
    {
        return Err(LaunchError::EngineChanged);
    }
    Ok(())
}

fn engine_command(prepared: &PreparedServiceConfig) -> Command {
    let mut command = Command::new(prepared.engine().path());
    command
        .arg("-f")
        .arg(prepared.active_config())
        .arg("-d")
        .arg(prepared.data_root())
        .current_dir(prepared.data_root())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    command
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("prepared active config escaped the protected runtime directory")]
    ActiveConfigEscape,
    #[error("validated engine path has no installation root")]
    EnginePath,
    #[error("validated engine identity changed before launch")]
    EngineChanged,
    #[error("launch boundary I/O failed: {0}")]
    BoundaryIo(#[source] io::Error),
    #[error("launch integrity validation failed: {0}")]
    Integrity(#[source] IntegrityError),
    #[error("protected runtime storage failed: {0}")]
    Storage(#[source] StorageError),
    #[error("an owned-engine state already exists; recovery is required")]
    ExistingOwnedState,
    #[error("engine process could not start: {0}")]
    Spawn(#[source] io::Error),
    #[error("engine process status could not be queried: {0}")]
    ChildStatus(#[source] io::Error),
    #[error("engine process identity failed: {0}")]
    OwnedIdentity(#[source] OwnedEngineError),
    #[error("engine start failed at the {0} health boundary")]
    HealthCheckFailed(HealthStage),
    #[error(
        "engine start failed at the {stage} health boundary; rollback also failed: {rollback}"
    )]
    HealthCheckRollback {
        stage: HealthStage,
        rollback: Box<LaunchError>,
    },
    #[error("engine rollback could not stop the owned child: {0}")]
    RollbackStop(#[source] io::Error),
    #[error("engine rollback stopped the child but could not remove its adapter: {0}")]
    RollbackAdapter(#[source] AdapterError),
    #[error("engine rollback stopped the child but could not clear state: {0}")]
    RollbackStorage(#[source] StorageError),
    #[cfg(feature = "acceptance-fault-injection")]
    #[error("acceptance fault selector failed: {0}")]
    AcceptanceFault(#[source] super::acceptance::AcceptanceFaultError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HealthStage {
    #[error("upstream preflight")]
    Upstream,
    #[error("controller-port preflight")]
    ControllerPort,
    #[error("pre-existing TUN adapter")]
    ExistingTun,
    #[error("controller readiness")]
    Controller,
    #[error("TUN readiness")]
    Tun,
    #[error("transparent-path self-test")]
    Transparent,
    #[error("engine-process liveness")]
    EngineProcess,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        path::{Path, PathBuf},
        time::Duration,
    };

    use super::super::{integrity::ValidatedEngine, process::query_process_identity};

    struct FakeChecks {
        failed: Option<HealthStage>,
    }

    impl FakeChecks {
        fn passes(&self, stage: HealthStage) -> bool {
            self.failed != Some(stage)
        }
    }

    impl EngineHealthChecks for FakeChecks {
        fn upstream_ready(&self, _upstream: &Upstream) -> bool {
            self.passes(HealthStage::Upstream)
        }

        fn remote_upstream_ready(&self, _upstream: &Upstream) -> bool {
            self.passes(HealthStage::Upstream)
        }

        fn controller_port_free(&self, _controller: &str) -> bool {
            self.passes(HealthStage::ControllerPort)
        }

        fn tun_absent(&self, _tun_device: &str) -> bool {
            self.passes(HealthStage::ExistingTun)
        }

        fn controller_ready(&self, _controller: &str, _secret: &str) -> bool {
            self.passes(HealthStage::Controller)
        }

        fn tun_ready(&self, _tun_device: &str) -> bool {
            self.passes(HealthStage::Tun)
        }

        fn transparent_ready(&self) -> bool {
            self.passes(HealthStage::Transparent)
        }
    }

    fn prepared() -> PreparedServiceConfig {
        let root = PathBuf::from(r"C:\ProgramData\TunBridge\run");
        PreparedServiceConfig::for_test(
            ValidatedEngine::for_test(PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe")),
            root.join(ACTIVE_CONFIG_FILENAME),
            root,
        )
    }

    fn pending_test_child() -> (PendingEngineStart, u32) {
        let child = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let pid = child.id();
        (
            PendingEngineStart {
                child: Some(child),
                record: None,
                storage: ProtectedDataDirectory::for_test(std::env::temp_dir()),
                state_persisted: false,
            },
            pid,
        )
    }

    fn assert_process_reaped(pid: u32) {
        for _ in 0..20 {
            if query_process_identity(pid).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("rollback guard left child PID {pid} running");
    }

    #[test]
    fn launch_command_has_only_fixed_arguments_and_paths() {
        let command = engine_command(&prepared());
        assert_eq!(
            command.get_program(),
            Path::new(r"C:\Program Files\TunBridge\mihomo.exe")
        );
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                OsString::from("-f"),
                OsString::from(r"C:\ProgramData\TunBridge\run\active-config.yaml"),
                OsString::from("-d"),
                OsString::from(r"C:\ProgramData\TunBridge\run"),
            ]
        );
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new(r"C:\ProgramData\TunBridge\run"))
        );
    }

    #[test]
    fn health_checks_fail_closed_at_every_boundary() {
        let prepared = prepared();
        for stage in [
            HealthStage::Upstream,
            HealthStage::ControllerPort,
            HealthStage::ExistingTun,
        ] {
            assert_eq!(
                evaluate_pre_spawn_checks(
                    &prepared,
                    &FakeChecks {
                        failed: Some(stage),
                    },
                ),
                Err(stage)
            );
        }
        assert!(evaluate_pre_spawn_checks(&prepared, &FakeChecks { failed: None }).is_ok());

        for stage in [
            HealthStage::Controller,
            HealthStage::Tun,
            HealthStage::Transparent,
        ] {
            assert_eq!(
                evaluate_post_spawn_checks(
                    &prepared,
                    &FakeChecks {
                        failed: Some(stage),
                    },
                    None,
                ),
                Err(stage)
            );
            assert_eq!(
                evaluate_post_spawn_checks(&prepared, &FakeChecks { failed: None }, Some(stage),),
                Err(stage)
            );
        }
        assert!(evaluate_post_spawn_checks(&prepared, &FakeChecks { failed: None }, None).is_ok());
    }

    #[test]
    fn pending_guard_kills_and_waits_for_the_exact_child_handle() {
        let (pending, pid) = pending_test_child();
        drop(pending);
        assert_process_reaped(pid);
    }

    #[test]
    fn explicit_pending_termination_kills_and_waits_for_the_exact_child_handle() {
        let (mut pending, pid) = pending_test_child();
        pending.terminate_child().unwrap();
        assert_process_reaped(pid);
    }
}
