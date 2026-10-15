//! Exact state adapter between native start preparation and protected engine handles.

use crate::{
    engine_config::DarwinEngineConfig,
    engine_process::{EngineLauncher, RunningEngine, SuspendedEngine},
    lifecycle_plan::{NetworkBaseline, ProcessIdentity},
    native_start::{prepare_native_start, prepare_native_start_v3, NativeStartPreparation},
    upstream_owner::VerifiedUpstream,
};
use std::net::IpAddr;
use tunbridge_service::{
    protocol::{StartProfile, StartProfileV3},
    state::Caller,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEngineError {
    InvalidState,
    UpstreamMismatch,
    ProcessUnavailable,
}

pub trait EngineRuntime {
    type Suspended;
    type Running;

    fn spawn_suspended(
        &mut self,
        config: &DarwinEngineConfig,
        run_id: &str,
    ) -> Result<Self::Suspended, NativeEngineError>;
    fn suspended_identity(handle: &Self::Suspended) -> &ProcessIdentity;
    fn abort_suspended(handle: Self::Suspended) -> Result<(), NativeEngineError>;
    fn resume(handle: Self::Suspended) -> Result<Self::Running, NativeEngineError>;
    fn running_identity(handle: &Self::Running) -> &ProcessIdentity;
    fn terminate_running(handle: Self::Running) -> Result<(), NativeEngineError>;
}

#[derive(Debug, Clone)]
pub struct SystemEngineRuntime {
    launcher: EngineLauncher,
}

impl Default for SystemEngineRuntime {
    fn default() -> Self {
        Self {
            launcher: EngineLauncher::system(),
        }
    }
}

impl EngineRuntime for SystemEngineRuntime {
    type Suspended = SuspendedEngine;
    type Running = RunningEngine;

    fn spawn_suspended(
        &mut self,
        config: &DarwinEngineConfig,
        run_id: &str,
    ) -> Result<Self::Suspended, NativeEngineError> {
        self.launcher
            .stage_and_spawn_suspended(config, run_id)
            .map_err(|_| NativeEngineError::ProcessUnavailable)
    }

    fn suspended_identity(handle: &Self::Suspended) -> &ProcessIdentity {
        handle.identity()
    }

    fn abort_suspended(handle: Self::Suspended) -> Result<(), NativeEngineError> {
        handle
            .terminate()
            .map_err(|_| NativeEngineError::ProcessUnavailable)
    }

    fn resume(handle: Self::Suspended) -> Result<Self::Running, NativeEngineError> {
        handle
            .resume()
            .map_err(|_| NativeEngineError::ProcessUnavailable)
    }

    fn running_identity(handle: &Self::Running) -> &ProcessIdentity {
        handle.identity()
    }

    fn terminate_running(handle: Self::Running) -> Result<(), NativeEngineError> {
        handle
            .terminate()
            .map_err(|_| NativeEngineError::ProcessUnavailable)
    }
}

enum EngineSlot<S, R> {
    Empty,
    Suspended(S),
    Running(R),
    Unknown,
}

pub struct NativeEngineLifecycle<R: EngineRuntime = SystemEngineRuntime> {
    runtime: R,
    slot: EngineSlot<R::Suspended, R::Running>,
    configured_device: Option<String>,
}

impl Default for NativeEngineLifecycle<SystemEngineRuntime> {
    fn default() -> Self {
        Self::new(SystemEngineRuntime::default())
    }
}

impl<R: EngineRuntime> NativeEngineLifecycle<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            slot: EngineSlot::Empty,
            configured_device: None,
        }
    }

    pub fn spawn_verified(
        &mut self,
        profile: &StartProfile,
        caller: &Caller,
        baseline: &NetworkBaseline,
        expected_upstream: &ProcessIdentity,
        run_id: &str,
        controller_secret: &str,
    ) -> Result<ProcessIdentity, NativeEngineError> {
        if !matches!(self.slot, EngineSlot::Empty) {
            return Err(NativeEngineError::InvalidState);
        }
        let preparation =
            prepare_native_start(profile, caller, baseline, run_id, controller_secret)
                .map_err(|_| NativeEngineError::ProcessUnavailable)?;
        self.spawn_prepared(preparation, expected_upstream)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spawn_verified_v3(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
        baseline: &NetworkBaseline,
        expected_upstream: &VerifiedUpstream,
        pinned_remote: Option<IpAddr>,
        run_id: &str,
        controller_secret: &str,
    ) -> Result<ProcessIdentity, NativeEngineError> {
        if !matches!(self.slot, EngineSlot::Empty) {
            return Err(NativeEngineError::InvalidState);
        }
        let preparation = prepare_native_start_v3(
            profile,
            caller,
            baseline,
            expected_upstream,
            pinned_remote,
            run_id,
            controller_secret,
        )
        .map_err(|_| NativeEngineError::ProcessUnavailable)?;
        self.spawn_prepared(preparation, &expected_upstream.identity)
    }

    pub fn abort_suspended(&mut self, expected: &ProcessIdentity) -> Result<(), NativeEngineError> {
        let EngineSlot::Suspended(handle) = &self.slot else {
            return Err(NativeEngineError::InvalidState);
        };
        if R::suspended_identity(handle) != expected {
            return Err(NativeEngineError::InvalidState);
        }
        let EngineSlot::Suspended(handle) = std::mem::replace(&mut self.slot, EngineSlot::Unknown)
        else {
            unreachable!("slot checked above");
        };
        let result = R::abort_suspended(handle);
        if result.is_ok() {
            self.slot = EngineSlot::Empty;
            self.configured_device = None;
        }
        result
    }

    pub fn resume(&mut self, expected: &ProcessIdentity) -> Result<(), NativeEngineError> {
        let EngineSlot::Suspended(handle) = &self.slot else {
            return Err(NativeEngineError::InvalidState);
        };
        if R::suspended_identity(handle) != expected {
            return Err(NativeEngineError::InvalidState);
        }
        let EngineSlot::Suspended(handle) = std::mem::replace(&mut self.slot, EngineSlot::Unknown)
        else {
            unreachable!("slot checked above");
        };
        let running = R::resume(handle)?;
        if R::running_identity(&running) != expected {
            if R::terminate_running(running).is_ok() {
                self.slot = EngineSlot::Empty;
                self.configured_device = None;
            }
            return Err(NativeEngineError::ProcessUnavailable);
        }
        self.slot = EngineSlot::Running(running);
        Ok(())
    }

    pub fn terminate_running(
        &mut self,
        expected: &ProcessIdentity,
    ) -> Result<(), NativeEngineError> {
        let EngineSlot::Running(handle) = &self.slot else {
            return Err(NativeEngineError::InvalidState);
        };
        if R::running_identity(handle) != expected {
            return Err(NativeEngineError::InvalidState);
        }
        let EngineSlot::Running(handle) = std::mem::replace(&mut self.slot, EngineSlot::Unknown)
        else {
            unreachable!("slot checked above");
        };
        let result = R::terminate_running(handle);
        if result.is_ok() {
            self.slot = EngineSlot::Empty;
            self.configured_device = None;
        }
        result
    }

    /// Forgets a running engine that exited on its own so the session can
    /// spawn its replacement. The process is already gone (and reaped);
    /// recovery removes its config by run id.
    pub fn forget_exited(&mut self, expected: &ProcessIdentity) {
        if matches!(&self.slot, EngineSlot::Running(handle) if R::running_identity(handle) == expected)
        {
            self.slot = EngineSlot::Empty;
            self.configured_device = None;
        }
    }

    pub fn configured_device(&self) -> Option<&str> {
        self.configured_device.as_deref()
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    fn spawn_prepared(
        &mut self,
        preparation: NativeStartPreparation,
        expected_upstream: &ProcessIdentity,
    ) -> Result<ProcessIdentity, NativeEngineError> {
        if !matches!(self.slot, EngineSlot::Empty) {
            return Err(NativeEngineError::InvalidState);
        }
        if &preparation.upstream().identity != expected_upstream {
            return Err(NativeEngineError::UpstreamMismatch);
        }
        let configured_device = preparation.engine_config().configured_device().to_owned();
        let handle = self
            .runtime
            .spawn_suspended(preparation.engine_config(), preparation.run_id())?;
        let identity = R::suspended_identity(&handle).clone();
        self.configured_device = Some(configured_device);
        self.slot = EngineSlot::Suspended(handle);
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lifecycle_plan::ProcessIdentity, native_start::assemble_native_start,
        upstream_owner::VerifiedUpstream,
    };
    use std::cell::{Cell, RefCell};

    #[derive(Debug)]
    struct FakeRuntime {
        next_identity: ProcessIdentity,
        fail_resume: bool,
        fail_terminate: bool,
        spawns: Cell<usize>,
        last_run_id: RefCell<Option<String>>,
    }

    #[derive(Debug)]
    struct FakeSuspended {
        identity: ProcessIdentity,
        fail_resume: bool,
        fail_terminate: bool,
    }

    #[derive(Debug)]
    struct FakeRunning {
        identity: ProcessIdentity,
        fail_terminate: bool,
    }

    impl EngineRuntime for FakeRuntime {
        type Suspended = FakeSuspended;
        type Running = FakeRunning;

        fn spawn_suspended(
            &mut self,
            _config: &DarwinEngineConfig,
            run_id: &str,
        ) -> Result<Self::Suspended, NativeEngineError> {
            self.spawns.set(self.spawns.get() + 1);
            self.last_run_id.replace(Some(run_id.to_owned()));
            Ok(FakeSuspended {
                identity: self.next_identity.clone(),
                fail_resume: self.fail_resume,
                fail_terminate: self.fail_terminate,
            })
        }

        fn suspended_identity(handle: &Self::Suspended) -> &ProcessIdentity {
            &handle.identity
        }

        fn abort_suspended(_handle: Self::Suspended) -> Result<(), NativeEngineError> {
            Ok(())
        }

        fn resume(handle: Self::Suspended) -> Result<Self::Running, NativeEngineError> {
            if handle.fail_resume {
                Err(NativeEngineError::ProcessUnavailable)
            } else {
                Ok(FakeRunning {
                    identity: handle.identity,
                    fail_terminate: handle.fail_terminate,
                })
            }
        }

        fn running_identity(handle: &Self::Running) -> &ProcessIdentity {
            &handle.identity
        }

        fn terminate_running(handle: Self::Running) -> Result<(), NativeEngineError> {
            if handle.fail_terminate {
                Err(NativeEngineError::ProcessUnavailable)
            } else {
                Ok(())
            }
        }
    }

    fn identity(pid: u32, byte: char) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: pid as u64 * 100,
            executable_file_id: pid as u64 * 10,
            executable_sha256: byte.to_string().repeat(64),
        }
    }

    fn profile() -> StartProfile {
        StartProfile {
            upstream_host: "127.0.0.1".into(),
            upstream_port: 7890,
            protocol: tunbridge_service::protocol::UpstreamProtocol::Socks5,
            username: None,
            password: None,
            upstream_process_id: 600,
            bypass_domains: Vec::new(),
            bypass_cidrs: Vec::new(),
            bypass_process_names: Vec::new(),
        }
    }

    fn preparation(upstream: ProcessIdentity) -> NativeStartPreparation {
        assemble_native_start(
            &profile(),
            502,
            &"a".repeat(32),
            &"b".repeat(64),
            "utun7".into(),
            "en0".into(),
            VerifiedUpstream {
                identity: upstream,
                process_name: "fixture-proxy".into(),
                auto_bypass_cidrs: Vec::new(),
            },
        )
        .unwrap()
    }

    fn runtime(engine: ProcessIdentity) -> FakeRuntime {
        FakeRuntime {
            next_identity: engine,
            fail_resume: false,
            fail_terminate: false,
            spawns: Cell::new(0),
            last_run_id: RefCell::new(None),
        }
    }

    #[test]
    fn prepared_spawn_resume_and_terminate_preserve_exact_identity() {
        let upstream = identity(600, 'a');
        let engine = identity(700, 'b');
        let mut lifecycle = NativeEngineLifecycle::new(runtime(engine.clone()));
        assert_eq!(
            lifecycle.spawn_prepared(preparation(upstream.clone()), &upstream),
            Ok(engine.clone())
        );
        assert_eq!(lifecycle.configured_device(), Some("utun7"));
        assert_eq!(lifecycle.resume(&engine), Ok(()));
        assert_eq!(lifecycle.terminate_running(&engine), Ok(()));
        assert_eq!(lifecycle.configured_device(), None);
        assert_eq!(lifecycle.runtime().spawns.get(), 1);
        assert_eq!(
            lifecycle.runtime().last_run_id.borrow().as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn mismatched_upstream_or_engine_never_advances_the_slot() {
        let upstream = identity(600, 'a');
        let wrong_upstream = identity(601, 'c');
        let engine = identity(700, 'b');
        let mut lifecycle = NativeEngineLifecycle::new(runtime(engine.clone()));
        assert_eq!(
            lifecycle.spawn_prepared(preparation(upstream.clone()), &wrong_upstream),
            Err(NativeEngineError::UpstreamMismatch)
        );
        assert_eq!(lifecycle.runtime().spawns.get(), 0);

        let mut lifecycle = NativeEngineLifecycle::new(runtime(engine.clone()));
        lifecycle
            .spawn_prepared(preparation(upstream.clone()), &upstream)
            .unwrap();
        assert_eq!(
            lifecycle.resume(&identity(701, 'd')),
            Err(NativeEngineError::InvalidState)
        );
        assert_eq!(lifecycle.abort_suspended(&engine), Ok(()));
    }

    #[test]
    fn an_exited_engine_is_forgotten_so_its_replacement_can_spawn() {
        let upstream = identity(600, 'a');
        let engine = identity(700, 'b');
        let mut lifecycle = NativeEngineLifecycle::new(runtime(engine.clone()));
        lifecycle
            .spawn_prepared(preparation(upstream.clone()), &upstream)
            .unwrap();
        lifecycle.resume(&engine).unwrap();
        lifecycle.forget_exited(&identity(701, 'd'));
        assert_eq!(
            lifecycle.spawn_prepared(preparation(upstream.clone()), &upstream),
            Err(NativeEngineError::InvalidState)
        );
        lifecycle.forget_exited(&engine);
        assert_eq!(lifecycle.configured_device(), None);
        assert!(lifecycle
            .spawn_prepared(preparation(upstream.clone()), &upstream)
            .is_ok());
        assert_eq!(lifecycle.runtime().spawns.get(), 2);
    }

    #[test]
    fn duplicate_spawn_and_wrong_state_operations_fail_closed() {
        let upstream = identity(600, 'a');
        let engine = identity(700, 'b');
        let mut lifecycle = NativeEngineLifecycle::new(runtime(engine.clone()));
        lifecycle
            .spawn_prepared(preparation(upstream.clone()), &upstream)
            .unwrap();
        assert_eq!(
            lifecycle.spawn_prepared(preparation(upstream), &identity(600, 'a')),
            Err(NativeEngineError::InvalidState)
        );
        assert_eq!(
            lifecycle.terminate_running(&engine),
            Err(NativeEngineError::InvalidState)
        );
        assert_eq!(lifecycle.abort_suspended(&engine), Ok(()));
    }

    #[test]
    fn consumed_handle_failure_poisoning_requires_observation_and_recovery() {
        let upstream = identity(600, 'a');
        let engine = identity(700, 'b');
        let mut failing_runtime = runtime(engine.clone());
        failing_runtime.fail_resume = true;
        let mut lifecycle = NativeEngineLifecycle::new(failing_runtime);
        lifecycle
            .spawn_prepared(preparation(upstream.clone()), &upstream)
            .unwrap();
        assert_eq!(
            lifecycle.resume(&engine),
            Err(NativeEngineError::ProcessUnavailable)
        );
        assert_eq!(
            lifecycle.spawn_prepared(preparation(upstream), &identity(600, 'a')),
            Err(NativeEngineError::InvalidState)
        );
        assert_eq!(lifecycle.configured_device(), Some("utun7"));
    }
}
