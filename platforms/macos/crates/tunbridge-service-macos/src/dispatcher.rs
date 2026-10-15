use crate::lifecycle_host::{
    HostError, LifecycleBackend, MacosLifecycleHost, OwnedJournal, StartMaterial,
};
use crate::observability::{MacosObservability, ObservabilityFailure};
#[cfg(all(feature = "macos-development-bootstrap", unix))]
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tunbridge_service::mihomo_logs::{MihomoLogMonitor, MihomoLogSession};
use tunbridge_service::{
    frame,
    lease::{
        LeaseContext, LeaseDecision, LeaseError, LeaseOwner, LeasePolicy, LeaseProof, LeaseSecrets,
        Secret256,
    },
    protocol::{
        ActiveStartProfile, Capability, Command, ConnectionPage, ConnectionState, ErrorCode, Hello,
        HelloOk, Request, Response, ResponseData, SessionGuard, TrafficSnapshot,
    },
    state::{Action, Caller, Owner, Phase, ServiceState, StateError, WatchdogReason},
    telemetry::GenerationId,
    watchdog::{HealthSignal, RuntimeObservation, WatchdogDecision, WatchdogPolicy},
};
#[cfg(feature = "macos-development-bootstrap")]
use tunbridge_setup_macos::bootstrap_protocol::BootstrapCaller;
#[cfg(all(feature = "macos-development-bootstrap", unix))]
use tunbridge_setup_macos::{
    bootstrap_protocol::GenerationMaterial, bundle_assets::resolve_development_bundle,
    generation_store::GenerationStore,
};
#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
use zeroize::Zeroizing;

const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(all(feature = "macos-development-bootstrap", target_os = "macos"))]
fn development_debug_log(message: &str) {
    crate::xpc_listener::debug_log(message);
}

#[cfg(all(feature = "macos-development-bootstrap", not(target_os = "macos")))]
fn development_debug_log(_message: &str) {}

#[cfg(all(
    feature = "macos-controller-client",
    feature = "macos-development-bootstrap"
))]
const CAPABILITIES: &[Capability] = &[
    Capability::Status,
    Capability::Start,
    Capability::Stop,
    Capability::Recover,
    Capability::Lease,
    Capability::Provision,
    Capability::ObserveLocalTraffic,
    Capability::CloseOwnedConnections,
    Capability::RemoteUpstream,
    Capability::ObserveMihomoLogs,
];
#[cfg(all(
    feature = "macos-controller-client",
    not(feature = "macos-development-bootstrap")
))]
const CAPABILITIES: &[Capability] = &[
    Capability::Status,
    Capability::Start,
    Capability::Stop,
    Capability::Recover,
    Capability::Lease,
    Capability::ObserveLocalTraffic,
    Capability::CloseOwnedConnections,
    Capability::RemoteUpstream,
    Capability::ObserveMihomoLogs,
];
#[cfg(all(
    not(feature = "macos-controller-client"),
    feature = "macos-development-bootstrap"
))]
const CAPABILITIES: &[Capability] = &[
    Capability::Status,
    Capability::Start,
    Capability::Stop,
    Capability::Recover,
    Capability::Lease,
    Capability::Provision,
    Capability::RemoteUpstream,
];
#[cfg(all(
    not(feature = "macos-controller-client"),
    not(feature = "macos-development-bootstrap")
))]
const CAPABILITIES: &[Capability] = &[
    Capability::Status,
    Capability::Start,
    Capability::Stop,
    Capability::Recover,
    Capability::Lease,
    Capability::RemoteUpstream,
];

pub trait HelperLifecycle: Send {
    /// Runtime health of the running session's local upstream.
    fn sample_upstream(&mut self) -> HealthSignal {
        HealthSignal::NotSampled
    }
    /// Liveness of the running session's engine.
    fn sample_engine(&mut self) -> HealthSignal {
        HealthSignal::NotSampled
    }
    /// The owner of a journaled session that is still exactly in place.
    fn adopt_running(&mut self) -> Result<Option<Owner>, HostError> {
        Ok(None)
    }
    fn has_owned_record(&mut self) -> Result<bool, HostError> {
        Ok(false)
    }
    /// The traffic lock belongs to the user's start and stop: it keeps
    /// traffic from leaving around the tunnel and outlives the engine.
    fn install_traffic_lock(&mut self) -> Result<(), HostError> {
        Ok(())
    }
    fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
        Ok(())
    }
    fn traffic_lock_present(&mut self) -> bool {
        false
    }
    fn start(
        &mut self,
        profile: &ActiveStartProfile,
        caller: &Caller,
        material: StartMaterial,
    ) -> Result<(), HostError>;
    fn recover(&mut self) -> Result<(), HostError>;
    fn observe_traffic(
        &mut self,
        _observability: &mut MacosObservability,
    ) -> Result<TrafficSnapshot, ObservabilityFailure> {
        Err(observability_unavailable())
    }
    fn list_connections(
        &mut self,
        _observability: &mut MacosObservability,
        _state: ConnectionState,
        _offset: u32,
        _limit: u16,
    ) -> Result<ConnectionPage, ObservabilityFailure> {
        Err(observability_unavailable())
    }
    fn close_connections(
        &mut self,
        _observability: &mut MacosObservability,
        _connection_id: Option<&str>,
    ) -> Result<u32, ObservabilityFailure> {
        Err(observability_unavailable())
    }
    fn mihomo_log_session(&mut self) -> Result<MihomoLogSession, ObservabilityFailure> {
        Err(observability_unavailable())
    }
}

impl<B, J> HelperLifecycle for MacosLifecycleHost<B, J>
where
    B: LifecycleBackend + Send,
    J: OwnedJournal + Send,
{
    fn start(
        &mut self,
        profile: &ActiveStartProfile,
        caller: &Caller,
        material: StartMaterial,
    ) -> Result<(), HostError> {
        MacosLifecycleHost::start(self, profile, caller, material)
    }

    fn recover(&mut self) -> Result<(), HostError> {
        MacosLifecycleHost::recover(self)
    }

    fn sample_upstream(&mut self) -> HealthSignal {
        MacosLifecycleHost::sample_upstream(self)
    }

    fn sample_engine(&mut self) -> HealthSignal {
        MacosLifecycleHost::sample_engine(self)
    }

    fn adopt_running(&mut self) -> Result<Option<Owner>, HostError> {
        Ok(
            MacosLifecycleHost::adopt_running(self)?.map(|(principal_id, session_id)| Owner {
                principal_id,
                session_id,
            }),
        )
    }

    fn has_owned_record(&mut self) -> Result<bool, HostError> {
        Ok(self.owned_record()?.is_some())
    }

    fn install_traffic_lock(&mut self) -> Result<(), HostError> {
        MacosLifecycleHost::install_traffic_lock(self)
    }

    fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
        MacosLifecycleHost::remove_traffic_lock(self)
    }

    fn traffic_lock_present(&mut self) -> bool {
        MacosLifecycleHost::traffic_lock_present(self)
    }

    #[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
    fn observe_traffic(
        &mut self,
        observability: &mut MacosObservability,
    ) -> Result<TrafficSnapshot, ObservabilityFailure> {
        let mut source = self.native_observability_source()?;
        observability.sample(&mut source)
    }

    #[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
    fn list_connections(
        &mut self,
        observability: &mut MacosObservability,
        state: ConnectionState,
        offset: u32,
        limit: u16,
    ) -> Result<ConnectionPage, ObservabilityFailure> {
        let mut source = self.native_observability_source()?;
        observability.page(&mut source, state, offset, limit)
    }

    #[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
    fn close_connections(
        &mut self,
        observability: &mut MacosObservability,
        connection_id: Option<&str>,
    ) -> Result<u32, ObservabilityFailure> {
        let mut source = self.native_observability_source()?;
        observability.close(&mut source, connection_id)
    }

    #[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
    fn mihomo_log_session(&mut self) -> Result<MihomoLogSession, ObservabilityFailure> {
        use crate::controller::ControllerOwnerVerifier;

        let record = self
            .owned_record()
            .map_err(|_| observability_unavailable())?
            .ok_or_else(observability_unavailable)?;
        record.validate().map_err(|_| observability_unavailable())?;
        if record.stage != crate::lifecycle_plan::OwnedStage::Running {
            return Err(observability_unavailable());
        }
        let engine = record
            .engine
            .as_ref()
            .ok_or_else(observability_unavailable)?;
        let mut verifier = crate::controller_owner::NativeControllerOwnerVerifier;
        if !verifier
            .is_exact_owner(crate::engine_config::CONTROLLER_ADDRESS, engine)
            .map_err(|_| observability_unavailable())?
        {
            return Err(observability_unavailable());
        }
        let controller = crate::engine_config::CONTROLLER_ADDRESS
            .parse()
            .map_err(|_| observability_unavailable())?;
        MihomoLogSession::new(
            record.run_id.clone(),
            controller,
            Zeroizing::new(record.controller_secret.clone()),
        )
        .map_err(|_| observability_unavailable())
    }
}

#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
trait NativeObservabilitySource {
    fn native_observability_source(
        &self,
    ) -> Result<
        crate::native_observability::NativeOwnedControllerSource<
            crate::controller::TcpControllerTransport,
            crate::controller_owner::NativeControllerOwnerVerifier,
        >,
        ObservabilityFailure,
    >;
}

#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
impl<B, J> NativeObservabilitySource for MacosLifecycleHost<B, J>
where
    B: LifecycleBackend,
    J: OwnedJournal,
{
    fn native_observability_source(
        &self,
    ) -> Result<
        crate::native_observability::NativeOwnedControllerSource<
            crate::controller::TcpControllerTransport,
            crate::controller_owner::NativeControllerOwnerVerifier,
        >,
        ObservabilityFailure,
    > {
        let record = self
            .owned_record()
            .map_err(|_| observability_unavailable())?
            .ok_or_else(observability_unavailable)?;
        crate::native_observability::NativeOwnedControllerSource::new(
            record,
            crate::controller::TcpControllerTransport,
            crate::controller_owner::NativeControllerOwnerVerifier,
        )
    }
}

pub trait SecretSource: Send {
    fn next_32(&mut self) -> Result<[u8; 32], HostError>;
}

struct LeaseRuntime {
    policy: LeasePolicy,
    owner: LeaseOwner,
}

pub struct MacosServiceContext<L, S> {
    state: Mutex<ServiceState>,
    lifecycle: Mutex<L>,
    lease: Mutex<Option<LeaseRuntime>>,
    secrets: Mutex<S>,
    observability: Mutex<MacosObservability>,
    mihomo_logs: MihomoLogMonitor,
    lease_clock: Option<Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>>,
    upstream_watchdog: Mutex<UpstreamWatchdog>,
    /// What the user started, kept in memory so the helper can restart a
    /// dead engine for the same session without the App.
    restart: Mutex<Option<EngineRestart>>,
}

/// Upstream sampling is an lsof call; run it on every other one-second tick.
const UPSTREAM_SAMPLE_EVERY_TICKS: u64 = 2;
/// Engine restarts are spaced out and bounded; after that the session is
/// reported and left to the user.
const ENGINE_RESTART_SPACING_TICKS: u64 = 5;
const ENGINE_RESTART_ATTEMPTS: u8 = 3;

#[derive(Default)]
struct UpstreamWatchdog {
    policy: WatchdogPolicy,
    ticks: u64,
}

struct EngineRestart {
    profile: ActiveStartProfile,
    caller: Caller,
    failures: u8,
    next_tick: u64,
}

impl<L, S> MacosServiceContext<L, S>
where
    L: HelperLifecycle,
    S: SecretSource,
{
    /// A restarted helper keeps a session that is still exactly in place;
    /// tearing it down would send traffic directly. Only a session that is no
    /// longer intact is recovered, and that is reported as an engine exit.
    pub fn recovered(mut lifecycle: L, secrets: S) -> Result<Self, HostError> {
        if let Some(owner) = lifecycle.adopt_running()? {
            #[cfg(feature = "macos-development-bootstrap")]
            development_debug_log("startup-adopted-running-session");
            let context = Self::stopped(lifecycle, secrets);
            *context
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)? =
                ServiceState::recovered_running(owner);
            return Ok(context);
        }
        let had_session = lifecycle.has_owned_record()?;
        lifecycle.recover()?;
        // A lock that outlived its session keeps traffic blocked until the
        // user decides, so the lost session is a fault, not a stop.
        let locked = lifecycle.traffic_lock_present();
        let context = Self::stopped(lifecycle, secrets);
        if had_session || locked {
            let mut state = context
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            state.last_watchdog_reason = Some(WatchdogReason::EngineExited);
            if locked {
                state.phase = Phase::Faulted;
                state.last_error = Some(ErrorCode::RecoveryRequired);
            }
        }
        Ok(context)
    }

    pub fn stopped(lifecycle: L, secrets: S) -> Self {
        Self {
            state: Mutex::new(ServiceState::default()),
            lifecycle: Mutex::new(lifecycle),
            lease: Mutex::new(None),
            secrets: Mutex::new(secrets),
            observability: Mutex::new(MacosObservability::default()),
            mihomo_logs: MihomoLogMonitor::default(),
            lease_clock: None,
            upstream_watchdog: Mutex::new(UpstreamWatchdog::default()),
            restart: Mutex::new(None),
        }
    }

    pub(crate) fn with_lease_clock(
        mut self,
        clock: Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>,
    ) -> Self {
        self.lease_clock = Some(clock);
        self
    }

    // Call only while holding the lease lock. Controller work and concurrent
    // requests can make a timestamp sampled before this lock obsolete.
    fn current_lease_tick(&self, supplied_tick: u64) -> Result<u64, HostError> {
        match &self.lease_clock {
            Some(clock) => clock(),
            None => Ok(supplied_tick),
        }
    }

    pub fn snapshot(&self) -> Result<ServiceState, HostError> {
        self.state
            .lock()
            .map_err(|_| HostError::BackendUnavailable)
            .map(|state| state.clone())
    }

    pub fn response_for(
        &self,
        request: &Request,
        caller: &Caller,
        now_tick: u64,
    ) -> Result<Response, HostError> {
        #[cfg(feature = "macos-development-bootstrap")]
        {
            self.response_for_with_bootstrap(request, caller, now_tick, None)
        }
        #[cfg(not(feature = "macos-development-bootstrap"))]
        {
            match &request.command {
                Command::Status => {
                    let state = self
                        .state
                        .lock()
                        .map_err(|_| HostError::BackendUnavailable)?;
                    Ok(status_response(request, &state, caller))
                }
                Command::Start { .. } | Command::Stop | Command::Recover => {
                    self.execute_lifecycle(request, caller)
                }
                Command::AcquireLease {}
                | Command::RenewLease { .. }
                | Command::ReleaseLease { .. } => self.execute_lease(request, caller, now_tick),
                Command::ObserveTraffic {}
                | Command::ListConnections { .. }
                | Command::CloseConnection { .. }
                | Command::CloseAllConnections {} => self.execute_observability(request, caller),
                Command::ListMihomoLogs { .. } => self.execute_mihomo_logs(request, caller),
            }
        }
    }

    #[cfg(feature = "macos-development-bootstrap")]
    pub fn response_for_with_bootstrap(
        &self,
        request: &Request,
        caller: &Caller,
        now_tick: u64,
        bootstrap: Option<(&BootstrapCaller, &Path)>,
    ) -> Result<Response, HostError> {
        match &request.command {
            Command::Status => {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| HostError::BackendUnavailable)?;
                Ok(status_response(request, &state, caller))
            }
            Command::Start { .. } | Command::Stop | Command::Recover => {
                self.execute_lifecycle(request, caller)
            }
            #[cfg(feature = "macos-development-bootstrap")]
            Command::ProvisionGeneration { .. } => {
                let (bootstrap_caller, bundle_path) = bootstrap.ok_or(HostError::InvalidInput)?;
                self.provision_generation(request, bootstrap_caller, bundle_path)?;
                let state = self
                    .state
                    .lock()
                    .map_err(|_| HostError::BackendUnavailable)?;
                Ok(status_response(request, &state, caller))
            }
            Command::AcquireLease {}
            | Command::RenewLease { .. }
            | Command::ReleaseLease { .. } => self.execute_lease(request, caller, now_tick),
            Command::ObserveTraffic {}
            | Command::ListConnections { .. }
            | Command::CloseConnection { .. }
            | Command::CloseAllConnections {} => self.execute_observability(request, caller),
            Command::ListMihomoLogs { .. } => self.execute_mihomo_logs(request, caller),
        }
    }

    #[cfg(all(feature = "macos-development-bootstrap", unix))]
    fn provision_generation(
        &self,
        request: &Request,
        bootstrap_caller: &BootstrapCaller,
        bundle_path: &Path,
    ) -> Result<(), HostError> {
        let Command::ProvisionGeneration {
            transaction_id,
            caller_cdhash,
            policy_json,
            engine_manifest_sha256,
            engine_sha256,
            engine_size,
            target_triple,
        } = &request.command
        else {
            development_debug_log("provision-command-shape-error");
            return Err(HostError::InvalidInput);
        };
        if caller_cdhash != &bootstrap_caller.cdhash {
            development_debug_log("provision-caller-cdhash-mismatch");
            return Err(HostError::InvalidInput);
        }
        let material = GenerationMaterial {
            transaction_id: transaction_id.clone(),
            caller_cdhash: caller_cdhash.clone(),
            policy_sha256: format!("{:x}", Sha256::digest(policy_json)),
            engine_manifest_sha256: engine_manifest_sha256.clone(),
            engine_sha256: engine_sha256.clone(),
            engine_size: *engine_size,
            target_triple: target_triple.clone(),
        };
        let assets = resolve_development_bundle(
            bundle_path,
            bootstrap_caller,
            &material,
            policy_json.clone(),
        )
        .map_err(|error| {
            development_debug_log(&format!("provision-assets-error={error:?}"));
            HostError::InvalidInput
        })?;
        let mut store = GenerationStore::open_system().map_err(|error| {
            development_debug_log(&format!("provision-store-open-error={error:?}"));
            HostError::JournalUnavailable
        })?;
        store.recover_pending().map_err(|error| {
            development_debug_log(&format!("provision-recover-error={error:?}"));
            HostError::RecoveryRequired
        })?;
        store
            .prepare_generation(transaction_id, &assets)
            .map_err(|error| {
                development_debug_log(&format!("provision-prepare-error={error:?}"));
                HostError::RecoveryRequired
            })?;
        store.commit_generation(transaction_id).map_err(|error| {
            development_debug_log(&format!("provision-commit-error={error:?}"));
            HostError::RecoveryRequired
        })
    }

    #[cfg(all(feature = "macos-development-bootstrap", not(unix)))]
    fn provision_generation(
        &self,
        _request: &Request,
        _bootstrap_caller: &BootstrapCaller,
        _bundle_path: &Path,
    ) -> Result<(), HostError> {
        Err(HostError::InvalidInput)
    }

    /// Grants the App a bounded window to renew after a system sleep. Its
    /// renewal thread was frozen while the uptime-based lease clock paused,
    /// and a maintenance wake can advance the clock before the App runs.
    pub fn note_system_resume(&self, now_tick: u64) -> Result<(), HostError> {
        let mut lease = self
            .lease
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let Some(runtime) = lease.as_mut() else {
            return Ok(());
        };
        let now_tick = self.current_lease_tick(now_tick)?;
        // A clock regression is reported by the following watchdog evaluation.
        let _ = runtime.policy.grant_resume_grace(now_tick);
        #[cfg(feature = "macos-development-bootstrap")]
        development_debug_log(&format!("system-resume-grace tick={now_tick}"));
        Ok(())
    }

    /// Keeps the tunnel up whatever fails: an unusable upstream marks the
    /// session degraded (traffic fails closed, it never goes direct), a dead
    /// engine is restarted for the same session, and an unverifiable listener
    /// faults closed in place.
    fn apply_watchdog(&self, now_tick: u64) -> Result<(), HostError> {
        let phase = self.snapshot()?.phase;
        let mut watchdog = self
            .upstream_watchdog
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        watchdog.ticks = watchdog.ticks.wrapping_add(1);
        let (engine, upstream) = if phase == Phase::Running {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            let upstream = if watchdog.ticks.is_multiple_of(UPSTREAM_SAMPLE_EVERY_TICKS) {
                lifecycle.sample_upstream()
            } else {
                HealthSignal::NotSampled
            };
            (lifecycle.sample_engine(), upstream)
        } else {
            (HealthSignal::NotSampled, HealthSignal::NotSampled)
        };
        let decision = watchdog.policy.evaluate(
            phase,
            RuntimeObservation {
                engine,
                upstream,
                controller: HealthSignal::NotSampled,
                adapter: HealthSignal::NotSampled,
            },
        );
        drop(watchdog);
        if let WatchdogDecision::RestartEngine(reason) = decision {
            return self.restart_engine(reason, now_tick);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        match decision {
            WatchdogDecision::Degraded(reason) => {
                let _ = state.mark_degraded(reason);
            }
            WatchdogDecision::Healthy => {
                state.clear_degraded();
            }
            WatchdogDecision::FaultClosed(reason) => {
                let _ = state.record_automatic_fault(reason, ErrorCode::OwnedProcessMismatch);
            }
            WatchdogDecision::Dormant
            | WatchdogDecision::Hold { .. }
            | WatchdogDecision::RestartEngine(_) => {}
        }
        Ok(())
    }

    /// Restarts the engine of the running session from the material the user
    /// started it with. The session stays Running and owned, reported as
    /// degraded, while attempts are spaced out. A helper that restarted has no
    /// material, and repeated failures give up; either way the session is
    /// reported as stopped by an engine exit so the user decides what next.
    fn restart_engine(&self, reason: WatchdogReason, now_tick: u64) -> Result<(), HostError> {
        let mut restart = self
            .restart
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let attempt = match restart.as_mut() {
            Some(pending) if pending.failures >= ENGINE_RESTART_ATTEMPTS => None,
            Some(pending) if now_tick < pending.next_tick => return Ok(()),
            Some(pending) => Some((pending.profile.clone(), pending.caller.clone())),
            None => None,
        };
        let Some((profile, caller)) = attempt else {
            *restart = None;
            drop(restart);
            #[cfg(feature = "macos-development-bootstrap")]
            development_debug_log(&format!("engine-restart=abandoned reason={reason:?}"));
            return self.stop_after_engine_loss(reason);
        };
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            let _ = state.mark_degraded(reason);
        }
        let material = self.start_material()?;
        let result = match self.lifecycle.lock() {
            Ok(mut lifecycle) => lifecycle
                .recover()
                .and_then(|()| lifecycle.start(&profile, &caller, material))
                .and_then(|()| lifecycle.install_traffic_lock()),
            Err(_) => Err(HostError::BackendUnavailable),
        };
        #[cfg(feature = "macos-development-bootstrap")]
        development_debug_log(&format!(
            "engine-restart reason={reason:?} tick={now_tick} result={result:?}"
        ));
        let pending = restart.as_mut().ok_or(HostError::BackendUnavailable)?;
        match result {
            Ok(()) => {
                pending.failures = 0;
                drop(restart);
                self.upstream_watchdog
                    .lock()
                    .map_err(|_| HostError::BackendUnavailable)?
                    .policy
                    .reset();
                self.observability
                    .lock()
                    .map_err(|_| HostError::BackendUnavailable)?
                    .reset();
                self.state
                    .lock()
                    .map_err(|_| HostError::BackendUnavailable)?
                    .clear_degraded();
                let _ = self.sync_mihomo_logs();
            }
            Err(_) => {
                pending.failures = pending.failures.saturating_add(1);
                pending.next_tick = now_tick.saturating_add(ENGINE_RESTART_SPACING_TICKS);
            }
        }
        Ok(())
    }

    /// The engine is gone and cannot be brought back: clean up what is left
    /// and report the stop with its reason.
    fn stop_after_engine_loss(&self, reason: WatchdogReason) -> Result<(), HostError> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            state
                .begin_automatic_recovery(reason, lower_hex(&self.next_secret()?[..16]))
                .map_err(|_| HostError::RecoveryRequired)?;
        }
        let (result, locked) = match self.lifecycle.lock() {
            Ok(mut lifecycle) => {
                let result = lifecycle.recover();
                (result, lifecycle.traffic_lock_present())
            }
            Err(_) => (Err(HostError::BackendUnavailable), true),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        // The traffic lock stays: without an engine, traffic is blocked
        // instead of sent directly until the user decides.
        match result {
            Ok(()) if locked => state
                .finish_failure(ErrorCode::RecoveryRequired)
                .map_err(|_| HostError::BackendUnavailable)?,
            Ok(()) => state
                .finish_success(Action::Recover)
                .map_err(|_| HostError::BackendUnavailable)?,
            Err(error) => {
                let (code, _, _) = host_error_response(error);
                state
                    .finish_failure(code)
                    .map_err(|_| HostError::BackendUnavailable)?;
            }
        }
        drop(state);
        *self
            .lease
            .lock()
            .map_err(|_| HostError::BackendUnavailable)? = None;
        self.observability
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?
            .reset();
        Ok(())
    }

    pub fn tick(&self, now_tick: u64) -> Result<(), HostError> {
        let _ = self.sync_mihomo_logs();
        self.apply_watchdog(now_tick)?;
        let snapshot = self.snapshot()?;
        #[cfg_attr(not(feature = "macos-development-bootstrap"), allow(unused_variables))]
        let (evaluated_tick, decision) = {
            let mut lease = self
                .lease
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            let Some(runtime) = lease.as_mut() else {
                return Ok(());
            };
            let now_tick = self.current_lease_tick(now_tick)?;
            let decision = runtime
                .policy
                .evaluate(&lease_context(&snapshot, &runtime.owner), now_tick);
            (now_tick, decision)
        };
        // The lease only says whether the App is present; it never stops
        // the tunnel. A relaunched App re-acquires it.
        let noteworthy = matches!(decision, LeaseDecision::Lapsed | LeaseDecision::Unknown);
        #[cfg(feature = "macos-development-bootstrap")]
        if noteworthy {
            development_debug_log(&format!(
                "lease-decision={decision:?} tick={evaluated_tick} phase={:?}",
                snapshot.phase
            ));
        }
        #[cfg(not(feature = "macos-development-bootstrap"))]
        let _ = (noteworthy, evaluated_tick);
        Ok(())
    }

    fn execute_lifecycle(&self, request: &Request, caller: &Caller) -> Result<Response, HostError> {
        let action = match request.command {
            Command::Start { .. } => Action::Start,
            Command::Stop => Action::Stop,
            Command::Recover => Action::Recover,
            _ => return Err(HostError::InvalidInput),
        };
        #[cfg(feature = "macos-development-bootstrap")]
        development_debug_log(&format!("lifecycle-command action={action:?}"));
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            if let Err(error) = state.begin(action, caller, &request.request_id) {
                return Ok(state_error_response(request, error));
            }
        }

        // The traffic lock goes up once the tunnel and its pinned routes exist
        // (earlier it would cut the proxy client's open connections to its
        // servers; before the tunnel is up traffic was going directly anyway)
        // and comes down after the tunnel. A start that cannot be locked is
        // rolled back to the state before it.
        let result = match self.lifecycle.lock() {
            Ok(mut lifecycle) => match &request.command {
                Command::Start { profile } => match self.start_material() {
                    Ok(material) => lifecycle
                        .start(profile, caller, material)
                        .and_then(|()| lifecycle.install_traffic_lock())
                        .inspect_err(|_| {
                            let _ = lifecycle.recover();
                            let _ = lifecycle.remove_traffic_lock();
                        }),
                    Err(error) => Err(error),
                },
                Command::Stop | Command::Recover => lifecycle
                    .recover()
                    .and_then(|()| lifecycle.remove_traffic_lock()),
                _ => Err(HostError::InvalidInput),
            },
            Err(_) => Err(HostError::BackendUnavailable),
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        *self
            .restart
            .lock()
            .map_err(|_| HostError::BackendUnavailable)? = match (&request.command, &result) {
            (Command::Start { profile }, Ok(())) => Some(EngineRestart {
                profile: profile.clone(),
                caller: caller.clone(),
                failures: 0,
                next_tick: 0,
            }),
            _ => None,
        };
        let response = match result {
            Ok(()) => {
                #[cfg(feature = "macos-development-bootstrap")]
                development_debug_log("lifecycle-result=ok");
                state
                    .finish_success(action)
                    .map_err(|_| HostError::BackendUnavailable)?;
                status_response(request, &state, caller)
            }
            Err(error) => {
                #[cfg(feature = "macos-development-bootstrap")]
                development_debug_log(&format!("lifecycle-result=error error={error:?}"));
                let (code, message, retryable) = host_error_response(error);
                state
                    .finish_failure(code)
                    .map_err(|_| HostError::BackendUnavailable)?;
                Response::error(request, code, message, retryable)
            }
        };
        drop(state);
        *self
            .lease
            .lock()
            .map_err(|_| HostError::BackendUnavailable)? = None;
        self.observability
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?
            .reset();
        let _ = self.sync_mihomo_logs();
        Ok(response)
    }

    fn sync_mihomo_logs(&self) -> Result<(), HostError> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let snapshot = self.snapshot()?;
        if snapshot.phase != Phase::Running {
            return self
                .mihomo_logs
                .stop()
                .map_err(|_| HostError::BackendUnavailable);
        }
        match lifecycle.mihomo_log_session() {
            Ok(session) => self
                .mihomo_logs
                .sync(Some(session))
                .map_err(|_| HostError::BackendUnavailable),
            Err(_) => {
                let _ = self.mihomo_logs.stop();
                Ok(())
            }
        }
    }

    fn execute_mihomo_logs(
        &self,
        request: &Request,
        caller: &Caller,
    ) -> Result<Response, HostError> {
        let snapshot = self.snapshot()?;
        if snapshot.phase != Phase::Running || !snapshot.is_owner(caller) {
            return Ok(Response::error(
                request,
                if snapshot.phase == Phase::Running {
                    ErrorCode::NotOwner
                } else {
                    ErrorCode::NotRunning
                },
                if snapshot.phase == Phase::Running {
                    "The caller does not own the running session."
                } else {
                    "TunBridge is not running."
                },
                snapshot.phase != Phase::Running,
            ));
        }
        let _ = self.sync_mihomo_logs();
        let Command::ListMihomoLogs {
            after_sequence,
            limit,
        } = request.command
        else {
            return Err(HostError::InvalidInput);
        };
        match self.mihomo_logs.page(after_sequence, limit) {
            Ok(page) => Ok(Response::success(
                request,
                ResponseData::MihomoLogPage { page },
            )),
            Err(_) => Ok(Response::error(
                request,
                ErrorCode::ObservabilityUnavailable,
                "Mihomo logs are temporarily unavailable.",
                true,
            )),
        }
    }

    fn execute_observability(
        &self,
        request: &Request,
        caller: &Caller,
    ) -> Result<Response, HostError> {
        // Lifecycle-first establishes one linearization point with Start/Stop/
        // Recover. A stop may begin before this lock (and is then observed as
        // non-running), or after the controller operation has completed.
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let snapshot = self.snapshot()?;
        if snapshot.phase != Phase::Running || !snapshot.is_owner(caller) {
            return Ok(Response::error(
                request,
                if snapshot.phase == Phase::Running {
                    ErrorCode::NotOwner
                } else {
                    ErrorCode::NotRunning
                },
                if snapshot.phase == Phase::Running {
                    "The caller does not own the running session."
                } else {
                    "TunBridge is not running."
                },
                snapshot.phase != Phase::Running,
            ));
        }
        let mut observability = self
            .observability
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let result = match &request.command {
            Command::ObserveTraffic {} => lifecycle
                .observe_traffic(&mut observability)
                .map(|snapshot| ResponseData::TrafficSnapshot { snapshot }),
            Command::ListConnections {
                state,
                offset,
                limit,
            } => lifecycle
                .list_connections(&mut observability, *state, *offset, *limit)
                .map(|page| ResponseData::ConnectionPage { page }),
            Command::CloseConnection { connection_id } => lifecycle
                .close_connections(&mut observability, Some(connection_id))
                .map(|closed| ResponseData::ConnectionsClosed { closed }),
            Command::CloseAllConnections {} => lifecycle
                .close_connections(&mut observability, None)
                .map(|closed| ResponseData::ConnectionsClosed { closed }),
            _ => return Err(HostError::InvalidInput),
        };
        Ok(match result {
            Ok(data) => Response::success(request, data),
            Err(error) => Response::error(request, error.code, error.safe_message, error.retryable),
        })
    }

    fn execute_lease(
        &self,
        request: &Request,
        caller: &Caller,
        now_tick: u64,
    ) -> Result<Response, HostError> {
        let snapshot = self.snapshot()?;
        if snapshot.phase != Phase::Running || !snapshot.is_owner(caller) {
            return Ok(lease_error_response(
                request,
                if snapshot.phase == Phase::Running {
                    LeaseError::NotOwner
                } else {
                    LeaseError::NotRunning
                },
            ));
        }
        let mut lease = self
            .lease
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?;
        let now_tick = self.current_lease_tick(now_tick)?;
        if lease.is_none() {
            let owner = LeaseOwner {
                principal_id: caller.principal_id.clone(),
                session_id: caller.session_id,
                generation: GenerationId::from_bytes(self.next_secret()?),
            };
            *lease = Some(LeaseRuntime {
                policy: LeasePolicy::new(Secret256::from_bytes(self.next_secret()?)),
                owner,
            });
        }
        let runtime = lease.as_mut().ok_or(HostError::BackendUnavailable)?;
        let context = lease_context(&snapshot, &runtime.owner);
        let result = match &request.command {
            Command::AcquireLease {} => runtime
                .policy
                .acquire(
                    &context,
                    caller,
                    now_tick,
                    LeaseSecrets {
                        lease_id: Secret256::from_bytes(self.next_secret()?),
                        lease_nonce: Secret256::from_bytes(self.next_secret()?),
                    },
                )
                .map(lease_data),
            Command::RenewLease {
                lease_id,
                lease_nonce,
                lease_seq,
            } => lease_proof(lease_id, lease_nonce, *lease_seq)
                .and_then(|proof| {
                    runtime.policy.renew(
                        &context,
                        caller,
                        now_tick,
                        proof,
                        Secret256::from_bytes(self.next_secret().map_err(|_| LeaseError::Invalid)?),
                    )
                })
                .map(lease_data),
            Command::ReleaseLease {
                lease_id,
                lease_nonce,
                lease_seq,
            } => lease_proof(lease_id, lease_nonce, *lease_seq)
                .and_then(|proof| runtime.policy.release(&context, caller, now_tick, proof))
                .map(|()| ResponseData::LeaseReleased { released: true }),
            _ => return Err(HostError::InvalidInput),
        };
        Ok(match result {
            Ok(data) => {
                #[cfg(feature = "macos-development-bootstrap")]
                development_debug_log(&format!("lease-accepted tick={now_tick}"));
                Response::success(request, data)
            }
            Err(error) => {
                #[cfg(feature = "macos-development-bootstrap")]
                development_debug_log(&format!("lease-rejected error={error:?} tick={now_tick}"));
                lease_error_response(request, error)
            }
        })
    }

    fn start_material(&self) -> Result<StartMaterial, HostError> {
        Ok(StartMaterial {
            run_id: lower_hex(&self.next_secret()?[..16]),
            controller_secret: lower_hex(&self.next_secret()?),
        })
    }

    fn next_secret(&self) -> Result<[u8; 32], HostError> {
        self.secrets
            .lock()
            .map_err(|_| HostError::BackendUnavailable)?
            .next_32()
    }
}

#[cfg(all(target_os = "macos", feature = "macos-native-lifecycle"))]
pub type SystemMacosServiceContext = MacosServiceContext<
    crate::native_backend::SystemNativeLifecycleHost,
    crate::native::SystemSecretSource,
>;

#[cfg(all(target_os = "macos", feature = "macos-native-lifecycle"))]
pub fn open_system_native_context() -> Result<SystemMacosServiceContext, HostError> {
    MacosServiceContext::recovered(
        crate::native_backend::open_system_native_lifecycle()?,
        crate::native::SystemSecretSource,
    )
}

pub struct MacosHelperConnection {
    caller: Caller,
    guard: SessionGuard,
}

impl MacosHelperConnection {
    pub fn accept(
        caller: Caller,
        hello_frame: &[u8],
        session_nonce: String,
    ) -> Result<(Self, Vec<u8>), HostError> {
        let hello: Hello = frame::decode(hello_frame).map_err(|_| HostError::InvalidInput)?;
        hello.validate().map_err(|_| HostError::InvalidInput)?;
        let guard =
            SessionGuard::new(session_nonce.clone()).map_err(|_| HostError::InvalidInput)?;
        let response =
            HelloOk::with_capabilities(SERVICE_VERSION, session_nonce, CAPABILITIES.to_vec());
        let response_frame = frame::encode(&response).map_err(|_| HostError::InvalidInput)?;
        Ok((Self { caller, guard }, response_frame))
    }

    pub fn handle<L, S>(
        &mut self,
        context: &MacosServiceContext<L, S>,
        request_frame: &[u8],
        now_tick: u64,
    ) -> Result<Vec<u8>, HostError>
    where
        L: HelperLifecycle,
        S: SecretSource,
    {
        #[cfg(feature = "macos-development-bootstrap")]
        {
            self.handle_with_bootstrap(context, request_frame, now_tick, None)
        }
        #[cfg(not(feature = "macos-development-bootstrap"))]
        {
            let request: Request =
                frame::decode(request_frame).map_err(|_| HostError::InvalidInput)?;
            self.guard
                .accept(&request)
                .map_err(|_| HostError::InvalidInput)?;
            let response = context.response_for(&request, &self.caller, now_tick)?;
            frame::encode(&response).map_err(|_| HostError::InvalidInput)
        }
    }

    #[cfg(feature = "macos-development-bootstrap")]
    pub fn handle_with_bootstrap<L, S>(
        &mut self,
        context: &MacosServiceContext<L, S>,
        request_frame: &[u8],
        now_tick: u64,
        bootstrap: Option<(&BootstrapCaller, &Path)>,
    ) -> Result<Vec<u8>, HostError>
    where
        L: HelperLifecycle,
        S: SecretSource,
    {
        let request: Request = frame::decode(request_frame).map_err(|_| HostError::InvalidInput)?;
        self.guard
            .accept(&request)
            .map_err(|_| HostError::InvalidInput)?;
        let response =
            context.response_for_with_bootstrap(&request, &self.caller, now_tick, bootstrap)?;
        frame::encode(&response).map_err(|_| HostError::InvalidInput)
    }
}

fn status_response(request: &Request, state: &ServiceState, caller: &Caller) -> Response {
    Response::success(
        request,
        ResponseData::Status {
            service_phase: state.phase,
            caller_is_owner: state.is_owner(caller),
            engine_running: state.phase == Phase::Running,
            service_version: SERVICE_VERSION.into(),
            stop_reason: state.stop_reason(),
            degraded_reason: state.degraded_reason,
        },
    )
}

fn state_error_response(request: &Request, error: StateError) -> Response {
    Response::error(
        request,
        error.code(),
        error.to_string(),
        error == StateError::OperationInProgress,
    )
}

fn host_error_response(error: HostError) -> (ErrorCode, &'static str, bool) {
    match error {
        HostError::InvalidInput => (
            ErrorCode::InvalidProfile,
            "The macOS helper rejected invalid lifecycle input.",
            false,
        ),
        HostError::JournalUnavailable | HostError::RecoveryRequired => (
            ErrorCode::RecoveryRequired,
            "The macOS helper requires exact recovery.",
            false,
        ),
        HostError::BackendUnavailable => (
            ErrorCode::InternalError,
            "The macOS helper backend is unavailable.",
            true,
        ),
    }
}

fn lease_context(state: &ServiceState, owner: &LeaseOwner) -> LeaseContext {
    LeaseContext {
        phase: state.phase,
        owner: state.owner.as_ref().map(|_| owner.clone()),
    }
}

fn lease_proof(lease_id: &str, lease_nonce: &str, sequence: u64) -> Result<LeaseProof, LeaseError> {
    Ok(LeaseProof {
        lease_id: Secret256::from_lower_hex(lease_id).ok_or(LeaseError::Invalid)?,
        lease_nonce: Secret256::from_lower_hex(lease_nonce).ok_or(LeaseError::Invalid)?,
        seq: sequence,
    })
}

fn lease_data(grant: tunbridge_service::lease::LeaseGrant) -> ResponseData {
    ResponseData::Lease {
        lease_id: grant.lease_id.to_lower_hex(),
        lease_nonce: grant.lease_nonce.to_lower_hex(),
        next_seq: grant.next_seq,
        ttl_ticks: grant.ttl_ticks,
        renew_after_ticks: grant.renew_after_ticks,
    }
}

fn lease_error_response(request: &Request, error: LeaseError) -> Response {
    let (code, message, retryable) = match error {
        LeaseError::NotRunning => (ErrorCode::NotRunning, "TunBridge is not running.", true),
        LeaseError::NotOwner => (
            ErrorCode::NotOwner,
            "The caller does not own the running session.",
            false,
        ),
        LeaseError::AlreadyActive => (
            ErrorCode::LeaseAlreadyActive,
            "The owner already has an active App lease.",
            false,
        ),
        LeaseError::Expired => (ErrorCode::LeaseExpired, "The App lease expired.", true),
        LeaseError::Invalid | LeaseError::Replay | LeaseError::InvalidTime => (
            ErrorCode::LeaseInvalid,
            "The App lease proof is invalid.",
            false,
        ),
    };
    Response::error(request, code, message, retryable)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn observability_unavailable() -> ObservabilityFailure {
    ObservabilityFailure {
        code: ErrorCode::ObservabilityUnavailable,
        safe_message: "The owned macOS controller is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_service::{
        protocol::{RequestKind, ResponseResult, PROTOCOL_VERSION},
        state::Phase,
    };

    #[derive(Debug, Default)]
    struct MemoryLifecycle {
        running: bool,
        starts: usize,
        recovers: usize,
        upstream: Option<HealthSignal>,
        engine_dead: bool,
        failing_starts: usize,
        adoptable: Option<Owner>,
        journaled: bool,
        locked: bool,
        lock_installs: usize,
    }

    impl HelperLifecycle for MemoryLifecycle {
        fn start(
            &mut self,
            _profile: &ActiveStartProfile,
            _caller: &Caller,
            material: StartMaterial,
        ) -> Result<(), HostError> {
            assert_eq!(material.run_id.len(), 32);
            assert_eq!(material.controller_secret.len(), 64);
            self.starts += 1;
            if self.failing_starts > 0 {
                self.failing_starts -= 1;
                return Err(HostError::BackendUnavailable);
            }
            self.running = true;
            self.engine_dead = false;
            Ok(())
        }

        fn recover(&mut self) -> Result<(), HostError> {
            self.running = false;
            self.recovers += 1;
            Ok(())
        }

        fn sample_upstream(&mut self) -> HealthSignal {
            self.upstream.unwrap_or(HealthSignal::NotSampled)
        }

        fn sample_engine(&mut self) -> HealthSignal {
            match (self.running, self.engine_dead) {
                (true, true) => HealthSignal::Unhealthy,
                (true, false) => HealthSignal::Healthy,
                (false, _) => HealthSignal::NotSampled,
            }
        }

        fn adopt_running(&mut self) -> Result<Option<Owner>, HostError> {
            Ok(self.adoptable.clone())
        }

        fn has_owned_record(&mut self) -> Result<bool, HostError> {
            Ok(self.journaled)
        }

        fn install_traffic_lock(&mut self) -> Result<(), HostError> {
            self.locked = true;
            self.lock_installs += 1;
            Ok(())
        }

        fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
            self.locked = false;
            Ok(())
        }

        fn traffic_lock_present(&mut self) -> bool {
            self.locked
        }
    }

    #[derive(Debug, Default)]
    struct DeterministicSecrets(u8);

    impl SecretSource for DeterministicSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            self.0 = self.0.checked_add(1).ok_or(HostError::BackendUnavailable)?;
            Ok([self.0; 32])
        }
    }

    struct FailingSecrets;

    impl SecretSource for FailingSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            Err(HostError::BackendUnavailable)
        }
    }

    #[derive(Default)]
    struct ObservingLifecycle {
        calls: usize,
    }

    impl HelperLifecycle for ObservingLifecycle {
        fn start(
            &mut self,
            _profile: &ActiveStartProfile,
            _caller: &Caller,
            _material: StartMaterial,
        ) -> Result<(), HostError> {
            Ok(())
        }

        fn recover(&mut self) -> Result<(), HostError> {
            Ok(())
        }

        fn observe_traffic(
            &mut self,
            _observability: &mut MacosObservability,
        ) -> Result<TrafficSnapshot, ObservabilityFailure> {
            self.calls += 1;
            Ok(TrafficSnapshot {
                schema_version: 1,
                engine_generation: "a".repeat(32),
                sequence: 1,
                sampled_at_unix_ms: 1,
                interval_ms: 1000,
                upload_bps: 0,
                download_bps: 0,
                upload_total: 0,
                download_total: 0,
                active_connections: 0,
                memory_bytes: 0,
                stale: true,
            })
        }
    }

    fn caller(uid: u32, session: u32) -> Caller {
        Caller {
            principal_id: format!("macos:{uid}:ABCDE12345:com.tunbridge.desktop"),
            session_id: session,
            is_admin: false,
        }
    }

    fn profile() -> ActiveStartProfile {
        tunbridge_service::protocol::StartProfileV3 {
            upstream: tunbridge_service::protocol::StartUpstreamV3::LocalListener {
                port: 7890,
                protocol: tunbridge_core::upstream::StandardProtocol::Socks5,
                credentials: None,
                expected_process_id: 600,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: vec!["proxy".into()],
        }
    }

    fn request(seq: u64, request_id: char, command: Command) -> Request {
        Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: "a".repeat(64),
            seq,
            request_id: request_id.to_string().repeat(32),
            command,
        }
    }

    fn response_data(response: &Response) -> &ResponseData {
        response.result.data.as_ref().unwrap()
    }

    #[test]
    fn authenticated_connection_runs_start_status_lease_and_stop_in_order() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let (mut connection, hello_ok) = MacosHelperConnection::accept(
            caller(502, 42),
            &frame::encode(&Hello::new("0.2.3")).unwrap(),
            "a".repeat(64),
        )
        .unwrap();
        let hello_ok: HelloOk = frame::decode(&hello_ok).unwrap();
        assert_eq!(hello_ok.capabilities, CAPABILITIES);

        let start = request(1, 'b', Command::Start { profile: profile() });
        let response: Response = frame::decode(
            &connection
                .handle(&context, &frame::encode(&start).unwrap(), 0)
                .unwrap(),
        )
        .unwrap();
        assert!(response.result.ok);
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);

        let acquire = request(2, 'c', Command::AcquireLease {});
        let response: Response = frame::decode(
            &connection
                .handle(&context, &frame::encode(&acquire).unwrap(), 1)
                .unwrap(),
        )
        .unwrap();
        let ResponseData::Lease {
            lease_id,
            lease_nonce,
            next_seq,
            ..
        } = response_data(&response)
        else {
            panic!("expected lease")
        };
        let renew = request(
            3,
            'd',
            Command::RenewLease {
                lease_id: lease_id.clone(),
                lease_nonce: lease_nonce.clone(),
                lease_seq: *next_seq,
            },
        );
        let response: Response = frame::decode(
            &connection
                .handle(&context, &frame::encode(&renew).unwrap(), 6)
                .unwrap(),
        )
        .unwrap();
        assert!(response.result.ok);

        let stop = request(4, 'e', Command::Stop);
        let response: Response = frame::decode(
            &connection
                .handle(&context, &frame::encode(&stop).unwrap(), 7)
                .unwrap(),
        )
        .unwrap();
        assert!(response.result.ok);
        assert_eq!(context.snapshot().unwrap(), ServiceState::default());
    }

    #[test]
    fn recovered_context_converges_journal_before_serving_requests() {
        let lifecycle = MemoryLifecycle {
            running: true,
            ..MemoryLifecycle::default()
        };
        let context =
            MacosServiceContext::recovered(lifecycle, DeterministicSecrets::default()).unwrap();
        assert_eq!(context.snapshot().unwrap(), ServiceState::default());
        let lifecycle = context.lifecycle.lock().unwrap();
        assert!(!lifecycle.running);
        assert_eq!(lifecycle.recovers, 1);
    }

    #[test]
    fn failed_startup_recovery_never_constructs_a_service_context() {
        struct FailedRecovery;

        impl HelperLifecycle for FailedRecovery {
            fn start(
                &mut self,
                _profile: &ActiveStartProfile,
                _caller: &Caller,
                _material: StartMaterial,
            ) -> Result<(), HostError> {
                unreachable!()
            }

            fn recover(&mut self) -> Result<(), HostError> {
                Err(HostError::RecoveryRequired)
            }
        }

        assert!(matches!(
            MacosServiceContext::recovered(FailedRecovery, DeterministicSecrets::default()),
            Err(HostError::RecoveryRequired)
        ));
    }

    #[test]
    fn another_authenticated_session_cannot_stop_the_owner() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        let start = request(1, 'b', Command::Start { profile: profile() });
        assert!(context.response_for(&start, &owner, 0).unwrap().result.ok);
        let response = context
            .response_for(&request(1, 'c', Command::Stop), &caller(502, 43), 1)
            .unwrap();
        assert_eq!(
            response.result,
            ResponseResult {
                ok: false,
                data: None,
                error: response.result.error.clone(),
            }
        );
        assert_eq!(response.result.error.unwrap().code, ErrorCode::NotOwner);
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
    }

    #[test]
    fn observability_requires_running_owner_before_touching_controller_source() {
        let context = MacosServiceContext::stopped(
            ObservingLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        let observe = request(1, 'o', Command::ObserveTraffic {});
        let stopped = context.response_for(&observe, &owner, 0).unwrap();
        assert_eq!(stopped.result.error.unwrap().code, ErrorCode::NotRunning);
        assert_eq!(context.lifecycle.lock().unwrap().calls, 0);

        assert!(
            context
                .response_for(
                    &request(2, 's', Command::Start { profile: profile() }),
                    &owner,
                    0
                )
                .unwrap()
                .result
                .ok
        );
        let not_owner = context.response_for(&observe, &caller(502, 43), 0).unwrap();
        assert_eq!(not_owner.result.error.unwrap().code, ErrorCode::NotOwner);
        assert_eq!(context.lifecycle.lock().unwrap().calls, 0);

        let response = context.response_for(&observe, &owner, 0).unwrap();
        assert!(matches!(
            response_data(&response),
            ResponseData::TrafficSnapshot { .. }
        ));
        assert_eq!(context.lifecycle.lock().unwrap().calls, 1);
    }

    #[test]
    fn replay_is_rejected_before_dispatch() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let (mut connection, _) = MacosHelperConnection::accept(
            caller(502, 42),
            &frame::encode(&Hello::new("0.2.3")).unwrap(),
            "a".repeat(64),
        )
        .unwrap();
        let status = frame::encode(&request(1, 'b', Command::Status)).unwrap();
        connection.handle(&context, &status, 0).unwrap();
        assert_eq!(
            connection.handle(&context, &status, 0),
            Err(HostError::InvalidInput)
        );
    }

    #[test]
    fn secret_source_failure_finishes_start_as_faulted_instead_of_sticking() {
        let context = MacosServiceContext::stopped(MemoryLifecycle::default(), FailingSecrets);
        let response = context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &caller(502, 42),
                0,
            )
            .unwrap();
        assert!(!response.result.ok);
        assert_eq!(
            response.result.error.unwrap().code,
            ErrorCode::InternalError
        );
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert!(state.operation_id.is_none());
    }

    #[test]
    fn lapsed_lease_keeps_the_tunnel_and_the_app_reattaches() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        context
            .response_for(&request(2, 'c', Command::AcquireLease {}), &owner, 1)
            .unwrap();
        context.tick(17).unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert!(state.is_owner(&owner));
        assert_eq!(state.stop_reason(), None);
        assert_eq!(context.lifecycle.lock().unwrap().recovers, 0);

        // A relaunched App takes the lease over.
        assert!(
            context
                .response_for(&request(3, 'd', Command::AcquireLease {}), &owner, 18)
                .unwrap()
                .result
                .ok
        );
    }

    #[test]
    fn dead_engine_is_restarted_for_the_same_session() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        context.lifecycle.lock().unwrap().engine_dead = true;
        context.tick(1).unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert!(state.is_owner(&owner));
        assert_eq!(state.degraded_reason, None);
        let lifecycle = context.lifecycle.lock().unwrap();
        assert_eq!((lifecycle.starts, lifecycle.recovers), (2, 1));
        assert!(lifecycle.running && !lifecycle.engine_dead);
    }

    #[test]
    fn engine_restart_failures_are_spaced_then_fault_with_the_lock_kept() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        {
            let mut lifecycle = context.lifecycle.lock().unwrap();
            lifecycle.engine_dead = true;
            lifecycle.failing_starts = usize::MAX;
        }
        context.tick(1).unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.degraded_reason, Some(WatchdogReason::EngineExited));
        // The failed restart left nothing running, so later ticks keep the
        // engine streak instead of resampling it.
        context.lifecycle.lock().unwrap().running = true;
        for tick in 2..=5 {
            context.tick(tick).unwrap();
        }
        assert_eq!(context.lifecycle.lock().unwrap().starts, 2);
        context.tick(6).unwrap();
        context.tick(11).unwrap();
        assert_eq!(context.lifecycle.lock().unwrap().starts, 4);
        context.tick(16).unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert_eq!(state.stop_reason(), Some(WatchdogReason::EngineExited));
        assert!(context.lifecycle.lock().unwrap().locked);
    }

    #[test]
    fn traffic_lock_follows_only_the_users_start_and_stop() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        {
            let lifecycle = context.lifecycle.lock().unwrap();
            // Up once the tunnel and its routes exist.
            assert!(lifecycle.locked);
            assert_eq!(lifecycle.lock_installs, 1);
        }
        // An engine restart refreshes the lock and never drops it.
        context.lifecycle.lock().unwrap().engine_dead = true;
        context.tick(1).unwrap();
        assert!(context.lifecycle.lock().unwrap().locked);
        context
            .response_for(&request(2, 'c', Command::Stop), &owner, 2)
            .unwrap();
        assert!(!context.lifecycle.lock().unwrap().locked);

        let failing = MacosServiceContext::stopped(
            MemoryLifecycle {
                failing_starts: 1,
                ..MemoryLifecycle::default()
            },
            DeterministicSecrets::default(),
        );
        failing
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        assert!(!failing.lifecycle.lock().unwrap().locked);
    }

    #[test]
    fn restarted_helper_keeps_a_lock_whose_session_was_lost_as_a_fault() {
        let context = MacosServiceContext::recovered(
            MemoryLifecycle {
                journaled: true,
                locked: true,
                ..MemoryLifecycle::default()
            },
            DeterministicSecrets::default(),
        )
        .unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert_eq!(state.stop_reason(), Some(WatchdogReason::EngineExited));
        assert!(context.lifecycle.lock().unwrap().locked);
    }

    #[test]
    fn restarted_helper_adopts_an_intact_session_and_reports_a_lost_one() {
        let owner = Owner {
            principal_id: caller(502, 42).principal_id,
            session_id: 42,
        };
        let context = MacosServiceContext::recovered(
            MemoryLifecycle {
                adoptable: Some(owner.clone()),
                ..MemoryLifecycle::default()
            },
            DeterministicSecrets::default(),
        )
        .unwrap();
        let state = context.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.owner, Some(owner));
        assert_eq!(context.lifecycle.lock().unwrap().recovers, 0);
        assert!(
            context
                .response_for(
                    &request(1, 'b', Command::AcquireLease {}),
                    &caller(502, 42),
                    1
                )
                .unwrap()
                .result
                .ok
        );

        let lost = MacosServiceContext::recovered(
            MemoryLifecycle {
                journaled: true,
                ..MemoryLifecycle::default()
            },
            DeterministicSecrets::default(),
        )
        .unwrap();
        let state = lost.snapshot().unwrap();
        assert_eq!(state.phase, Phase::Stopped);
        assert_eq!(state.stop_reason(), Some(WatchdogReason::EngineExited));
        assert_eq!(lost.lifecycle.lock().unwrap().recovers, 1);
    }

    #[test]
    fn delayed_lease_lapse_never_stops_the_tunnel() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let clock = Arc::new(AtomicU64::new(10));
        let read_clock = Arc::clone(&clock);
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        )
        .with_lease_clock(Arc::new(move || Ok(read_clock.load(Ordering::SeqCst))));
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        assert!(
            context
                .response_for(&request(2, 'c', Command::AcquireLease {}), &owner, 10)
                .unwrap()
                .result
                .ok
        );
        // A ticker sampled second 9 before blocking behind controller work,
        // while an acquire/renew already consumed second 10.
        clock.store(11, Ordering::SeqCst);
        context.tick(9).unwrap();
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
        clock.store(26, Ordering::SeqCst);
        context.tick(9).unwrap();
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
        assert_eq!(context.lifecycle.lock().unwrap().recovers, 0);
    }

    #[test]
    fn exited_local_upstream_degrades_without_stopping_and_recovers() {
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        );
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        context.lifecycle.lock().unwrap().upstream = Some(HealthSignal::Unhealthy);
        for tick in 1..=12 {
            context.tick(tick).unwrap();
        }
        let snapshot = context.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Running);
        assert_eq!(
            snapshot.degraded_reason,
            Some(WatchdogReason::UpstreamUnavailable)
        );
        assert_eq!(context.lifecycle.lock().unwrap().recovers, 0);

        // The client restarted (any owner check passed in the sampler).
        context.lifecycle.lock().unwrap().upstream = Some(HealthSignal::Healthy);
        for tick in 13..=14 {
            context.tick(tick).unwrap();
        }
        let snapshot = context.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Running);
        assert_eq!(snapshot.degraded_reason, None);
    }

    #[test]
    fn system_resume_grace_keeps_the_tunnel_while_the_app_catches_up() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let clock = Arc::new(AtomicU64::new(10));
        let read_clock = Arc::clone(&clock);
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        )
        .with_lease_clock(Arc::new(move || Ok(read_clock.load(Ordering::SeqCst))));
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        assert!(
            context
                .response_for(&request(2, 'c', Command::AcquireLease {}), &owner, 10)
                .unwrap()
                .result
                .ok
        );
        // Wake detected at uptime 12; a maintenance wake then runs past the
        // normal 15-tick deadline before the App renews.
        clock.store(12, Ordering::SeqCst);
        context.note_system_resume(12).unwrap();
        clock.store(40, Ordering::SeqCst);
        context.tick(40).unwrap();
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
        clock.store(
            12 + tunbridge_service::lease::LEASE_RESUME_GRACE_TICKS,
            Ordering::SeqCst,
        );
        context.tick(0).unwrap();
        let snapshot = context.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Running);
        assert_eq!(snapshot.stop_reason(), None);
    }

    #[test]
    fn queued_acquire_uses_fresh_clock_and_clock_regression_keeps_the_tunnel() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let clock = Arc::new(AtomicU64::new(10));
        let read_clock = Arc::clone(&clock);
        let context = MacosServiceContext::stopped(
            MemoryLifecycle::default(),
            DeterministicSecrets::default(),
        )
        .with_lease_clock(Arc::new(move || Ok(read_clock.load(Ordering::SeqCst))));
        let owner = caller(502, 42);
        context
            .response_for(
                &request(1, 'b', Command::Start { profile: profile() }),
                &owner,
                0,
            )
            .unwrap();
        assert!(
            context
                .response_for(&request(2, 'c', Command::AcquireLease {}), &owner, 0)
                .unwrap()
                .result
                .ok
        );
        clock.store(16, Ordering::SeqCst);
        context.tick(16).unwrap();
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
        clock.store(15, Ordering::SeqCst);
        context.tick(17).unwrap();
        assert_eq!(context.snapshot().unwrap().phase, Phase::Running);
    }
}
