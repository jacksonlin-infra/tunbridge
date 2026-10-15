use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    protocol::{
        ActiveStartProfile, Capability, Command, ErrorCode, HelloOk, Request, Response,
        ResponseData, SessionGuard, MAX_REQUESTS_PER_CONNECTION,
    },
    state::{Action, Caller, Phase, ServiceState, StateError, WatchdogReason},
    watchdog::{RuntimeObservation, WatchdogDecision, WatchdogPolicy},
};

#[cfg(feature = "production-mihomo-logs-v4")]
use crate::mihomo_logs::{LogMonitorError, MihomoLogMonitor, MihomoLogSession};

#[cfg(feature = "acceptance-m2b5")]
use crate::telemetry::{TelemetryBatch, TelemetryDecision, TelemetryPolicy};
#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
use crate::{
    lease::{
        LeaseContext, LeaseDecision, LeaseError, LeaseOwner, LeasePolicy, LeaseProof, LeaseSecrets,
        Secret256,
    },
    telemetry::GenerationId,
};

#[cfg(feature = "production-local-observability")]
use super::local_observability::{LocalObservabilityState, ObservabilityError};
use super::{
    random::random_hex_32, CallerIdentity, LifecycleFailure, PipeConnection,
    SharedLifecycleExecutor,
};

pub const MAX_AUTHENTICATED_CONNECTIONS: usize = 16;
/// Engine restarts are spaced out and bounded; after that the session is
/// reported and left to the user.
const ENGINE_RESTART_SPACING: Duration = Duration::from_secs(5);
const ENGINE_RESTART_ATTEMPTS: u8 = 3;

/// What the user started, kept in memory so the service can restart a dead
/// engine for the same session without the App.
struct EngineRestart {
    profile: ActiveStartProfile,
    caller: Caller,
    failures: u8,
    next_attempt: Option<Instant>,
    /// Set while a failed restart waits for its next attempt. The session's
    /// runtime facts are gone in between, so sampling would misread the wait
    /// as an unprovable identity.
    pending: Option<WatchdogReason>,
}

#[derive(Clone, Default)]
pub struct ShutdownToken {
    cancelled: Arc<AtomicBool>,
}

impl ShutdownToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub struct ServiceContext {
    state: Arc<Mutex<ServiceState>>,
    lifecycle: Option<SharedLifecycleExecutor>,
    lifecycle_enabled: bool,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    lease: Mutex<Option<LeaseRuntime>>,
    #[cfg(feature = "production-local-observability")]
    observability: Mutex<LocalObservabilityState>,
    #[cfg(feature = "production-mihomo-logs-v4")]
    mihomo_logs: MihomoLogMonitor,
    #[cfg(feature = "production-mihomo-logs-v4")]
    mihomo_log_generation: Mutex<Option<((u32, u64), String)>>,
    restart: Mutex<Option<EngineRestart>>,
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
struct LeaseRuntime {
    policy: LeasePolicy,
    owner: Option<LeaseOwner>,
    tick: u64,
}

impl ServiceContext {
    pub fn status_only(initial_state: ServiceState) -> Self {
        Self {
            state: Arc::new(Mutex::new(initial_state)),
            lifecycle: None,
            lifecycle_enabled: false,
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            lease: Mutex::new(None),
            #[cfg(feature = "production-local-observability")]
            observability: Mutex::new(LocalObservabilityState::default()),
            #[cfg(feature = "production-mihomo-logs-v4")]
            mihomo_logs: MihomoLogMonitor::default(),
            #[cfg(feature = "production-mihomo-logs-v4")]
            mihomo_log_generation: Mutex::new(None),
            restart: Mutex::new(None),
        }
    }

    pub fn with_lifecycle(
        initial_state: ServiceState,
        lifecycle: SharedLifecycleExecutor,
        lifecycle_enabled: bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(initial_state)),
            lifecycle: Some(lifecycle),
            lifecycle_enabled,
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            lease: Mutex::new(None),
            #[cfg(feature = "production-local-observability")]
            observability: Mutex::new(LocalObservabilityState::default()),
            #[cfg(feature = "production-mihomo-logs-v4")]
            mihomo_logs: MihomoLogMonitor::default(),
            #[cfg(feature = "production-mihomo-logs-v4")]
            mihomo_log_generation: Mutex::new(None),
            restart: Mutex::new(None),
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        let mut capabilities = vec![Capability::Status];
        if self.lifecycle_enabled {
            capabilities.extend([Capability::Start, Capability::Stop, Capability::Recover]);
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            capabilities.push(Capability::Lease);
            #[cfg(feature = "production-local-observability")]
            capabilities.extend([
                Capability::ObserveLocalTraffic,
                Capability::CloseOwnedConnections,
            ]);
            #[cfg(feature = "remote-upstream-v3")]
            capabilities.push(Capability::RemoteUpstream);
            #[cfg(feature = "production-mihomo-logs-v4")]
            capabilities.push(Capability::ObserveMihomoLogs);
        }
        capabilities
    }

    pub(super) fn phase(&self) -> Result<Phase, ServerError> {
        self.state
            .lock()
            .map(|state| state.phase)
            .map_err(|_| ServerError::StatePoisoned)
    }

    #[cfg(feature = "production-mihomo-logs-v4")]
    pub(super) fn sync_mihomo_log_monitor(&self) -> Result<(), ServerError> {
        if self.phase()? != Phase::Running {
            *self
                .mihomo_log_generation
                .lock()
                .map_err(|_| ServerError::MihomoLogStatePoisoned)? = None;
            return self.mihomo_logs.stop().map_err(ServerError::MihomoLogs);
        }
        let ((pid, creation_time), controller, secret) =
            match super::local_observability::owned_log_session_parts() {
                Ok(parts) => parts,
                Err(_) => {
                    *self
                        .mihomo_log_generation
                        .lock()
                        .map_err(|_| ServerError::MihomoLogStatePoisoned)? = None;
                    self.mihomo_logs.stop().map_err(ServerError::MihomoLogs)?;
                    return Ok(());
                }
            };
        let generation = {
            let mut state = self
                .mihomo_log_generation
                .lock()
                .map_err(|_| ServerError::MihomoLogStatePoisoned)?;
            let key = (pid, creation_time);
            if state.as_ref().is_none_or(|(current, _)| *current != key) {
                *state = Some((
                    key,
                    super::random::random_hex_32().map_err(ServerError::Random)?,
                ));
            }
            state
                .as_ref()
                .map(|(_, generation)| generation.clone())
                .expect("generation was initialized")
        };
        let session = MihomoLogSession::new(generation, controller, secret)
            .map_err(ServerError::MihomoLogs)?;
        self.mihomo_logs
            .sync(Some(session))
            .map_err(ServerError::MihomoLogs)
    }

    #[cfg(feature = "production-mihomo-logs-v4")]
    pub(super) fn stop_mihomo_log_monitor(&self) -> Result<(), ServerError> {
        *self
            .mihomo_log_generation
            .lock()
            .map_err(|_| ServerError::MihomoLogStatePoisoned)? = None;
        self.mihomo_logs.stop().map_err(ServerError::MihomoLogs)
    }

    pub(super) fn apply_watchdog_observation(
        &self,
        policy: &mut WatchdogPolicy,
        observation: RuntimeObservation,
        operation_id: &str,
    ) -> Result<WatchdogDecision, ServerError> {
        let pending = self
            .restart
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?
            .as_ref()
            .and_then(|restart| restart.pending);
        if let Some(reason) = pending {
            if self.restart_engine(reason, Instant::now(), operation_id)? {
                policy.reset();
            }
            return Ok(WatchdogDecision::RestartEngine(reason));
        }
        let phase = self.phase()?;
        let decision = policy.evaluate(phase, observation);
        match decision {
            // Nothing here tears the session down: a dead engine or adapter
            // is restarted, an unavailable upstream or controller is reported
            // as degraded, an unproven identity faults closed in place.
            WatchdogDecision::RestartEngine(reason) => {
                if self.restart_engine(reason, Instant::now(), operation_id)? {
                    policy.reset();
                }
            }
            WatchdogDecision::FaultClosed(reason) => {
                self.record_automatic_fault(reason)?;
            }
            WatchdogDecision::Degraded(reason) => {
                self.mark_degraded(reason)?;
            }
            WatchdogDecision::Healthy => {
                self.state
                    .lock()
                    .map_err(|_| ServerError::StatePoisoned)?
                    .clear_degraded();
            }
            WatchdogDecision::Dormant | WatchdogDecision::Hold { .. } => {}
        }
        Ok(decision)
    }

    /// Adopts a restarted local upstream client while the session is Running
    /// and no lifecycle operation can race the owned-record update.
    pub(super) fn rebind_restarted_upstream(
        &self,
        restarted: super::upstream::RestartedUpstream,
    ) -> Result<bool, ServerError> {
        let state = self.state.lock().map_err(|_| ServerError::StatePoisoned)?;
        if state.phase != Phase::Running || state.operation_id.is_some() {
            return Ok(false);
        }
        Ok(super::runtime_watchdog::persist_restarted_upstream(
            restarted,
        ))
    }

    fn mark_degraded(&self, reason: crate::state::WatchdogReason) -> Result<(), ServerError> {
        let mut state = self.state.lock().map_err(|_| ServerError::StatePoisoned)?;
        match state.mark_degraded(reason) {
            Ok(_) => Ok(()),
            Err(error) if expected_watchdog_race(error) => Ok(()),
            Err(error) => Err(ServerError::StateTransition(error)),
        }
    }

    /// Restarts the engine of the running session from the material the user
    /// started it with. The session stays Running and owned, reported as
    /// degraded, while attempts are spaced out. A service that restarted has
    /// no material, and repeated failures give up; either way the session is
    /// reported as stopped by an engine exit so the user decides what next.
    /// Returns whether a restart succeeded.
    fn restart_engine(
        &self,
        reason: WatchdogReason,
        now: Instant,
        operation_id: &str,
    ) -> Result<bool, ServerError> {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return Err(ServerError::MissingLifecycleExecutor);
        };
        let mut restart = self
            .restart
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        let attempt = match restart.as_mut() {
            Some(pending) if pending.failures >= ENGINE_RESTART_ATTEMPTS => None,
            Some(pending) if pending.next_attempt.is_some_and(|next| now < next) => {
                return Ok(false);
            }
            Some(pending) => Some((pending.profile.clone(), pending.caller.clone())),
            None => None,
        };
        let Some((profile, caller)) = attempt else {
            *restart = None;
            drop(restart);
            self.apply_automatic_recovery(reason, operation_id)?;
            return Ok(false);
        };
        self.mark_degraded(reason)?;
        if self.phase()? != Phase::Running {
            return Ok(false);
        }
        let result = lifecycle
            .recover()
            .and_then(|()| lifecycle.start(&profile, &caller))
            .and_then(|()| lifecycle.install_traffic_lock());
        let pending = restart.as_mut().ok_or(ServerError::StatePoisoned)?;
        if result.is_ok() {
            pending.failures = 0;
            pending.next_attempt = None;
            pending.pending = None;
            drop(restart);
            self.state
                .lock()
                .map_err(|_| ServerError::StatePoisoned)?
                .clear_degraded();
            return Ok(true);
        }
        pending.failures = pending.failures.saturating_add(1);
        pending.next_attempt = Some(now + ENGINE_RESTART_SPACING);
        pending.pending = Some(reason);
        Ok(false)
    }

    /// The engine is gone and cannot be brought back: clean up what is left
    /// and report the stop with its reason.
    fn apply_automatic_recovery(
        &self,
        reason: crate::state::WatchdogReason,
        operation_id: &str,
    ) -> Result<(), ServerError> {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return Err(ServerError::MissingLifecycleExecutor);
        };
        {
            let mut state = self.state.lock().map_err(|_| ServerError::StatePoisoned)?;
            if let Err(error) = state.begin_automatic_recovery(reason, operation_id) {
                if expected_watchdog_race(error) {
                    return Ok(());
                }
                return Err(ServerError::StateTransition(error));
            }
        }
        let result = lifecycle.recover();
        // The traffic lock stays: without an engine, traffic is blocked
        // instead of sent directly until the user decides.
        let locked = lifecycle.traffic_lock_present();
        let mut state = self.state.lock().map_err(|_| ServerError::StatePoisoned)?;
        let transition = match result {
            Ok(()) if locked => state
                .finish_failure(ErrorCode::RecoveryRequired)
                .map_err(ServerError::StateTransition),
            Ok(()) => state
                .finish_success(Action::Recover)
                .map_err(ServerError::StateTransition),
            Err(failure) => state
                .finish_failure(failure.code)
                .map_err(ServerError::StateTransition),
        };
        drop(state);
        transition?;
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        self.reset_lease_runtime()?;
        Ok(())
    }

    fn record_automatic_fault(
        &self,
        reason: crate::state::WatchdogReason,
    ) -> Result<(), ServerError> {
        let mut state = self.state.lock().map_err(|_| ServerError::StatePoisoned)?;
        if let Err(error) = state.record_automatic_fault(reason, ErrorCode::OwnedProcessMismatch) {
            if !expected_watchdog_race(error) {
                return Err(ServerError::StateTransition(error));
            }
        }
        drop(state);
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        self.reset_lease_runtime()?;
        Ok(())
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    fn acquire_lease(
        &self,
        caller: &crate::state::Caller,
    ) -> Result<crate::lease::LeaseGrant, LeaseRequestError> {
        let snapshot = self.lease_state_snapshot()?;
        let mut lease = self.lease.lock().map_err(|_| ServerError::LeasePoisoned)?;
        let runtime = ensure_lease_runtime(&mut lease, &snapshot)?;
        let context = runtime.sync_context(&snapshot)?;
        let secrets = LeaseSecrets {
            lease_id: Secret256::from_bytes(
                super::random::random_bytes_32().map_err(ServerError::Random)?,
            ),
            lease_nonce: Secret256::from_bytes(
                super::random::random_bytes_32().map_err(ServerError::Random)?,
            ),
        };
        runtime
            .policy
            .acquire(&context, caller, runtime.tick, secrets)
            .map_err(LeaseRequestError::Policy)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    fn renew_lease(
        &self,
        caller: &crate::state::Caller,
        proof: LeaseProof,
    ) -> Result<crate::lease::LeaseGrant, LeaseRequestError> {
        let snapshot = self.lease_state_snapshot()?;
        let mut lease = self.lease.lock().map_err(|_| ServerError::LeasePoisoned)?;
        let runtime = ensure_lease_runtime(&mut lease, &snapshot)?;
        let context = runtime.sync_context(&snapshot)?;
        let next_nonce =
            Secret256::from_bytes(super::random::random_bytes_32().map_err(ServerError::Random)?);
        runtime
            .policy
            .renew(&context, caller, runtime.tick, proof, next_nonce)
            .map_err(LeaseRequestError::Policy)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    fn release_lease(
        &self,
        caller: &crate::state::Caller,
        proof: LeaseProof,
    ) -> Result<(), LeaseRequestError> {
        let snapshot = self.lease_state_snapshot()?;
        let mut lease = self.lease.lock().map_err(|_| ServerError::LeasePoisoned)?;
        let runtime = ensure_lease_runtime(&mut lease, &snapshot)?;
        let context = runtime.sync_context(&snapshot)?;
        runtime
            .policy
            .release(&context, caller, runtime.tick, proof)
            .map_err(LeaseRequestError::Policy)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    pub(super) fn apply_lease_tick(
        &self,
        operation_id: &str,
    ) -> Result<LeaseDecision, ServerError> {
        let snapshot = self.lease_state_snapshot()?;
        let decision = {
            let mut lease = self.lease.lock().map_err(|_| ServerError::LeasePoisoned)?;
            let runtime = ensure_lease_runtime(&mut lease, &snapshot)?;
            // The Desktop's renewal thread is frozen while the system sleeps
            // or a Modern Standby display is off; pause the lease clock too.
            if super::power::POWER.lease_clock_paused() {
                return Ok(LeaseDecision::Held);
            }
            runtime.tick = runtime
                .tick
                .checked_add(1)
                .ok_or(ServerError::LeaseClockOverflow)?;
            if super::power::POWER.take_resume() {
                // A clock regression is reported by the evaluation below.
                let _ = runtime.policy.grant_resume_grace(runtime.tick);
            }
            let context = runtime.sync_context(&snapshot)?;
            runtime.policy.evaluate(&context, runtime.tick)
        };
        // The lease only says whether the App is present; it never stops the
        // tunnel. A relaunched App re-acquires it, and a clock regression has
        // nothing to protect.
        let _ = operation_id;
        Ok(decision)
    }

    #[cfg(feature = "acceptance-m2b5")]
    pub(super) fn m2b5_generation(&self) -> Result<Option<GenerationId>, ServerError> {
        let snapshot = self.lease_state_snapshot()?;
        let mut lease = self.lease.lock().map_err(|_| ServerError::LeasePoisoned)?;
        let runtime = ensure_lease_runtime(&mut lease, &snapshot)?;
        let context = runtime.sync_context(&snapshot)?;
        Ok(context.owner.map(|owner| owner.generation))
    }

    #[cfg(feature = "acceptance-m2b5")]
    pub(super) fn apply_telemetry_batch(
        &self,
        policy: &mut TelemetryPolicy,
        now: u64,
        generation: GenerationId,
        batch: TelemetryBatch<'_>,
        operation_id: &str,
    ) -> Result<TelemetryDecision, ServerError> {
        let decision = policy.observe(now, generation, batch);
        match decision {
            TelemetryDecision::Converge(reason) => {
                self.apply_automatic_recovery(reason, operation_id)?;
            }
            TelemetryDecision::FaultClosed(reason) => {
                self.record_automatic_fault(reason)?;
            }
            TelemetryDecision::Disabled
            | TelemetryDecision::Healthy
            | TelemetryDecision::Hold
            | TelemetryDecision::HoldUnknown { .. } => {}
        }
        Ok(decision)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    fn lease_state_snapshot(&self) -> Result<ServiceState, ServerError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| ServerError::StatePoisoned)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    fn reset_lease_runtime(&self) -> Result<(), ServerError> {
        *self.lease.lock().map_err(|_| ServerError::LeasePoisoned)? = None;
        Ok(())
    }
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
fn ensure_lease_runtime<'a>(
    slot: &'a mut Option<LeaseRuntime>,
    snapshot: &ServiceState,
) -> Result<&'a mut LeaseRuntime, ServerError> {
    if slot.is_none() {
        let boot_epoch =
            Secret256::from_bytes(super::random::random_bytes_32().map_err(ServerError::Random)?);
        *slot = Some(LeaseRuntime {
            policy: LeasePolicy::new(boot_epoch),
            owner: None,
            tick: 0,
        });
    }
    let runtime = slot.as_mut().expect("lease runtime was initialized");
    let _ = runtime.sync_context(snapshot)?;
    Ok(runtime)
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
impl LeaseRuntime {
    fn sync_context(&mut self, snapshot: &ServiceState) -> Result<LeaseContext, ServerError> {
        let Some(owner) = snapshot
            .owner
            .as_ref()
            .filter(|_| snapshot.phase == Phase::Running)
        else {
            self.owner = None;
            return Ok(LeaseContext {
                phase: snapshot.phase,
                owner: None,
            });
        };
        let owner_changed = self.owner.as_ref().is_none_or(|current| {
            current.principal_id != owner.principal_id || current.session_id != owner.session_id
        });
        if owner_changed {
            let lease_owner = LeaseOwner {
                principal_id: owner.principal_id.clone(),
                session_id: owner.session_id,
                generation: GenerationId::from_bytes(
                    super::random::random_bytes_32().map_err(ServerError::Random)?,
                ),
            };
            self.policy = LeasePolicy::recovered_running(
                self.policy.boot_epoch(),
                lease_owner.clone(),
                self.tick,
            )
            .map_err(ServerError::LeasePolicy)?;
            self.owner = Some(lease_owner);
        }
        Ok(LeaseContext {
            phase: snapshot.phase,
            owner: self.owner.clone(),
        })
    }
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
#[derive(Debug, thiserror::Error)]
enum LeaseRequestError {
    #[error(transparent)]
    Server(#[from] ServerError),
    #[error(transparent)]
    Policy(#[from] LeaseError),
}

fn expected_watchdog_race(error: StateError) -> bool {
    matches!(
        error,
        StateError::OperationInProgress | StateError::NotRunning | StateError::RecoveryRequired
    )
}

#[derive(Clone)]
pub struct ConnectionLimiter {
    inner: Arc<LimiterInner>,
}

struct LimiterInner {
    active: Mutex<usize>,
    available: Condvar,
    max: usize,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Self {
        assert!(max > 0, "connection limit must be non-zero");
        Self {
            inner: Arc::new(LimiterInner {
                active: Mutex::new(0),
                available: Condvar::new(),
                max,
            }),
        }
    }

    pub fn acquire(&self) -> Result<ConnectionPermit, ServerError> {
        self.acquire_until_shutdown(&ShutdownToken::default())
    }

    pub fn acquire_until_shutdown(
        &self,
        shutdown: &ShutdownToken,
    ) -> Result<ConnectionPermit, ServerError> {
        let mut active = self
            .inner
            .active
            .lock()
            .map_err(|_| ServerError::LimiterPoisoned)?;
        while *active >= self.inner.max {
            if shutdown.is_cancelled() {
                return Err(ServerError::ShuttingDown);
            }
            let (next, _) = self
                .inner
                .available
                .wait_timeout(active, Duration::from_millis(50))
                .map_err(|_| ServerError::LimiterPoisoned)?;
            active = next;
        }
        if shutdown.is_cancelled() {
            return Err(ServerError::ShuttingDown);
        }
        *active += 1;
        Ok(ConnectionPermit {
            inner: Arc::clone(&self.inner),
        })
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        *self.inner.active.lock().unwrap()
    }
}

pub struct ConnectionPermit {
    inner: Arc<LimiterInner>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.inner.active.lock() {
            *active = active.saturating_sub(1);
            self.inner.available.notify_one();
        }
    }
}

/// Serve one authenticated client connection. The SCM host advertises
/// lifecycle capabilities only for an explicitly selected product or
/// acceptance feature set.
pub fn serve_connection(
    connection: PipeConnection,
    context: Arc<ServiceContext>,
) -> Result<(), ServerError> {
    serve_connection_until_shutdown(connection, context, ShutdownToken::default())
}

pub(super) fn serve_connection_until_shutdown(
    mut connection: PipeConnection,
    context: Arc<ServiceContext>,
    shutdown: ShutdownToken,
) -> Result<(), ServerError> {
    if shutdown.is_cancelled() {
        return Ok(());
    }
    let nonce = random_hex_32().map_err(ServerError::Random)?;
    let hello = HelloOk::with_capabilities(
        env!("CARGO_PKG_VERSION"),
        nonce.clone(),
        context.capabilities(),
    );
    connection.write(&hello)?;
    let mut guard = SessionGuard::new(nonce)?;

    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let request: Request = match connection.read_until_shutdown(&shutdown) {
            Ok(request) => request,
            Err(super::pipe::PipeError::Shutdown) => return Ok(()),
            Err(error) if error.is_disconnect() => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        guard.accept(&request)?;
        let response = response_for(&request, &connection.identity, &context)?;
        connection.write(&response)?;
    }
    Ok(())
}

fn response_for(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
) -> Result<Response, ServerError> {
    match &request.command {
        Command::Status => {
            let state = context
                .state
                .lock()
                .map_err(|_| ServerError::StatePoisoned)?;
            Ok(status_response(request, &state, identity))
        }
        Command::Start { .. } | Command::Stop | Command::Recover => {
            execute_lifecycle(request, identity, context)
        }
        #[cfg(feature = "macos-development-bootstrap")]
        Command::ProvisionGeneration { .. } => Ok(Response::error(
            request,
            ErrorCode::CapabilityUnavailable,
            "macOS development bootstrap is not available on Windows",
            false,
        )),
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::AcquireLease {} => execute_lease(request, identity, context, None),
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::RenewLease {
            lease_id,
            lease_nonce,
            lease_seq,
        } => execute_lease(
            request,
            identity,
            context,
            Some((lease_id, lease_nonce, *lease_seq, false)),
        ),
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::ReleaseLease {
            lease_id,
            lease_nonce,
            lease_seq,
        } => execute_lease(
            request,
            identity,
            context,
            Some((lease_id, lease_nonce, *lease_seq, true)),
        ),
        #[cfg(feature = "production-local-observability")]
        Command::ObserveTraffic {} => execute_observe_traffic(request, identity, context),
        #[cfg(feature = "production-local-observability")]
        Command::ListConnections {
            state,
            offset,
            limit,
        } => execute_list_connections(request, identity, context, *state, *offset, *limit),
        #[cfg(feature = "production-local-observability")]
        Command::CloseConnection { connection_id } => {
            execute_close_connections(request, identity, context, Some(connection_id))
        }
        #[cfg(feature = "production-local-observability")]
        Command::CloseAllConnections {} => {
            execute_close_connections(request, identity, context, None)
        }
        #[cfg(feature = "production-mihomo-logs-v4")]
        Command::ListMihomoLogs {
            after_sequence,
            limit,
        } => execute_list_mihomo_logs(request, identity, context, *after_sequence, *limit),
    }
}

#[cfg(feature = "production-mihomo-logs-v4")]
fn execute_list_mihomo_logs(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
    after_sequence: u64,
    limit: u16,
) -> Result<Response, ServerError> {
    {
        let state = context
            .state
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        if state.phase != Phase::Running {
            return Ok(Response::error(
                request,
                ErrorCode::NotRunning,
                "TunBridge is not running",
                true,
            ));
        }
        if !state.is_owner(&identity.caller) {
            return Ok(Response::error(
                request,
                ErrorCode::NotOwner,
                "the caller does not own the running session",
                false,
            ));
        }
    }
    context.sync_mihomo_log_monitor()?;
    match context.mihomo_logs.page(after_sequence, limit) {
        Ok(page) => Ok(Response::success(
            request,
            ResponseData::MihomoLogPage { page },
        )),
        Err(_) => Ok(Response::error(
            request,
            ErrorCode::ObservabilityUnavailable,
            "Mihomo logs are temporarily unavailable",
            true,
        )),
    }
}

#[cfg(feature = "production-local-observability")]
fn execute_observe_traffic(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
) -> Result<Response, ServerError> {
    {
        let state = context
            .state
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        if state.phase != Phase::Running {
            return Ok(Response::error(
                request,
                ErrorCode::NotRunning,
                "TunBridge is not running",
                true,
            ));
        }
        if !state.is_owner(&identity.caller) {
            return Ok(Response::error(
                request,
                ErrorCode::NotOwner,
                "the caller does not own the running session",
                false,
            ));
        }
    }
    let result = context
        .observability
        .lock()
        .map_err(|_| ServerError::ObservabilityPoisoned)?
        .sample();
    match result {
        Ok(snapshot) => Ok(Response::success(
            request,
            ResponseData::TrafficSnapshot { snapshot },
        )),
        Err(ObservabilityError::NotRunning) => Ok(Response::error(
            request,
            ErrorCode::NotRunning,
            "TunBridge is not running",
            true,
        )),
        Err(_) => Ok(Response::error(
            request,
            ErrorCode::ObservabilityUnavailable,
            "local traffic data is temporarily unavailable",
            true,
        )),
    }
}

#[cfg(feature = "production-local-observability")]
fn execute_list_connections(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
    state: crate::protocol::ConnectionState,
    offset: u32,
    limit: u16,
) -> Result<Response, ServerError> {
    {
        let service_state = context
            .state
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        if service_state.phase != Phase::Running {
            return Ok(Response::error(
                request,
                ErrorCode::NotRunning,
                "TunBridge is not running",
                true,
            ));
        }
        if !service_state.is_owner(&identity.caller) {
            return Ok(Response::error(
                request,
                ErrorCode::NotOwner,
                "the caller does not own the running session",
                false,
            ));
        }
    }
    let result = context
        .observability
        .lock()
        .map_err(|_| ServerError::ObservabilityPoisoned)?
        .connections_page(state, offset, limit);
    match result {
        Ok(page) => Ok(Response::success(
            request,
            ResponseData::ConnectionPage { page },
        )),
        Err(ObservabilityError::NotRunning) => Ok(Response::error(
            request,
            ErrorCode::NotRunning,
            "TunBridge is not running",
            true,
        )),
        Err(_) => Ok(Response::error(
            request,
            ErrorCode::ObservabilityUnavailable,
            "local connection data is temporarily unavailable",
            true,
        )),
    }
}

#[cfg(feature = "production-local-observability")]
fn execute_close_connections(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
    connection_id: Option<&str>,
) -> Result<Response, ServerError> {
    {
        let service_state = context
            .state
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        if service_state.phase != Phase::Running {
            return Ok(Response::error(
                request,
                ErrorCode::NotRunning,
                "TunBridge is not running",
                true,
            ));
        }
        if !service_state.is_owner(&identity.caller) {
            return Ok(Response::error(
                request,
                ErrorCode::NotOwner,
                "the caller does not own the running session",
                false,
            ));
        }
    }
    let mut observability = context
        .observability
        .lock()
        .map_err(|_| ServerError::ObservabilityPoisoned)?;
    let result = match connection_id {
        Some(connection_id) => observability.close_connection(connection_id),
        None => observability.close_all_connections(),
    };
    match result {
        Ok(closed) => Ok(Response::success(
            request,
            ResponseData::ConnectionsClosed { closed },
        )),
        Err(ObservabilityError::ConnectionNotFound) => Ok(Response::error(
            request,
            ErrorCode::ConnectionNotFound,
            "the connection is no longer active",
            true,
        )),
        Err(ObservabilityError::NotRunning) => Ok(Response::error(
            request,
            ErrorCode::NotRunning,
            "TunBridge is not running",
            true,
        )),
        Err(_) => Ok(Response::error(
            request,
            ErrorCode::ObservabilityUnavailable,
            "the connection close operation is temporarily unavailable",
            true,
        )),
    }
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
fn execute_lease(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
    proof: Option<(&str, &str, u64, bool)>,
) -> Result<Response, ServerError> {
    if !context.lifecycle_enabled {
        return Ok(Response::error(
            request,
            ErrorCode::CapabilityUnavailable,
            "App lease capability is unavailable in this service build",
            false,
        ));
    }
    let result = match proof {
        None => context
            .acquire_lease(&identity.caller)
            .map(|grant| ResponseData::Lease {
                lease_id: grant.lease_id.to_lower_hex(),
                lease_nonce: grant.lease_nonce.to_lower_hex(),
                next_seq: grant.next_seq,
                ttl_ticks: grant.ttl_ticks,
                renew_after_ticks: grant.renew_after_ticks,
            }),
        Some((lease_id, lease_nonce, lease_seq, release)) => {
            let Some(lease_id) = Secret256::from_lower_hex(lease_id) else {
                return Ok(lease_error_response(request, LeaseError::Invalid));
            };
            let Some(lease_nonce) = Secret256::from_lower_hex(lease_nonce) else {
                return Ok(lease_error_response(request, LeaseError::Invalid));
            };
            let proof = LeaseProof {
                lease_id,
                lease_nonce,
                seq: lease_seq,
            };
            if release {
                context
                    .release_lease(&identity.caller, proof)
                    .map(|()| ResponseData::LeaseReleased { released: true })
            } else {
                context
                    .renew_lease(&identity.caller, proof)
                    .map(|grant| ResponseData::Lease {
                        lease_id: grant.lease_id.to_lower_hex(),
                        lease_nonce: grant.lease_nonce.to_lower_hex(),
                        next_seq: grant.next_seq,
                        ttl_ticks: grant.ttl_ticks,
                        renew_after_ticks: grant.renew_after_ticks,
                    })
            }
        }
    };
    match result {
        Ok(data) => Ok(Response::success(request, data)),
        Err(LeaseRequestError::Policy(error)) => Ok(lease_error_response(request, error)),
        Err(LeaseRequestError::Server(error)) => Err(error),
    }
}

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
fn lease_error_response(request: &Request, error: LeaseError) -> Response {
    let (code, message) = match error {
        LeaseError::AlreadyActive => (
            ErrorCode::LeaseAlreadyActive,
            "the running owner already has an active App lease",
        ),
        LeaseError::Expired => (ErrorCode::LeaseExpired, "the App lease has expired"),
        LeaseError::NotRunning => (ErrorCode::NotRunning, "TunBridge is not running"),
        LeaseError::NotOwner => (
            ErrorCode::NotOwner,
            "the caller does not own the running session",
        ),
        LeaseError::Invalid | LeaseError::Replay => {
            (ErrorCode::LeaseInvalid, "the App lease proof is invalid")
        }
        LeaseError::InvalidTime => (ErrorCode::InternalError, "the App lease clock is invalid"),
    };
    Response::error(request, code, message, false)
}

fn execute_lifecycle(
    request: &Request,
    identity: &CallerIdentity,
    context: &ServiceContext,
) -> Result<Response, ServerError> {
    if !context.lifecycle_enabled {
        return Ok(Response::error(
            request,
            ErrorCode::CapabilityUnavailable,
            "privileged lifecycle commands are not published by this service artifact",
            false,
        ));
    }
    let Some(lifecycle) = context.lifecycle.as_ref() else {
        return Err(ServerError::MissingLifecycleExecutor);
    };
    let action = match &request.command {
        Command::Start { .. } => Action::Start,
        Command::Stop => Action::Stop,
        Command::Recover => Action::Recover,
        Command::Status => Action::Status,
        #[cfg(feature = "macos-development-bootstrap")]
        Command::ProvisionGeneration { .. } => {
            unreachable!("macOS bootstrap is rejected before lifecycle execution")
        }
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            unreachable!("lease commands are handled before lifecycle execution")
        }
        #[cfg(feature = "production-local-observability")]
        Command::ObserveTraffic {}
        | Command::ListConnections { .. }
        | Command::CloseConnection { .. }
        | Command::CloseAllConnections {} => {
            unreachable!("traffic observation is handled before lifecycle execution")
        }
        #[cfg(feature = "production-mihomo-logs-v4")]
        Command::ListMihomoLogs { .. } => {
            unreachable!("Mihomo log observation is handled before lifecycle execution")
        }
    };
    {
        let mut state = context
            .state
            .lock()
            .map_err(|_| ServerError::StatePoisoned)?;
        if let Err(error) = state.begin(action, &identity.caller, &request.request_id) {
            return Ok(state_error_response(request, error));
        }
    }

    // The traffic lock goes up once the tunnel exists (before it, traffic was
    // going directly anyway) and comes down after the tunnel. A start that
    // cannot be locked is rolled back to the state before it.
    let result = match &request.command {
        Command::Start { profile } => lifecycle
            .start(profile, &identity.caller)
            .and_then(|()| lifecycle.install_traffic_lock())
            .inspect_err(|_| {
                let _ = lifecycle.recover();
                let _ = lifecycle.remove_traffic_lock();
            }),
        Command::Stop => lifecycle
            .stop()
            .and_then(|()| lifecycle.remove_traffic_lock()),
        Command::Recover => lifecycle
            .recover()
            .and_then(|()| lifecycle.remove_traffic_lock()),
        Command::Status => unreachable!("status is handled before lifecycle execution"),
        #[cfg(feature = "macos-development-bootstrap")]
        Command::ProvisionGeneration { .. } => {
            unreachable!("macOS bootstrap is rejected before lifecycle execution")
        }
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            unreachable!("lease commands are handled before lifecycle execution")
        }
        #[cfg(feature = "production-local-observability")]
        Command::ObserveTraffic {}
        | Command::ListConnections { .. }
        | Command::CloseConnection { .. }
        | Command::CloseAllConnections {} => {
            unreachable!("traffic observation is handled before lifecycle execution")
        }
        #[cfg(feature = "production-mihomo-logs-v4")]
        Command::ListMihomoLogs { .. } => {
            unreachable!("Mihomo log observation is handled before lifecycle execution")
        }
    };
    *context
        .restart
        .lock()
        .map_err(|_| ServerError::StatePoisoned)? = match (&request.command, &result) {
        (Command::Start { profile }, Ok(())) => Some(EngineRestart {
            profile: profile.clone(),
            caller: identity.caller.clone(),
            failures: 0,
            next_attempt: None,
            pending: None,
        }),
        _ => None,
    };
    let mut state = context
        .state
        .lock()
        .map_err(|_| ServerError::StatePoisoned)?;
    let response = match result {
        Ok(()) => {
            state
                .finish_success(action)
                .map_err(ServerError::StateTransition)?;
            status_response(request, &state, identity)
        }
        Err(failure) => {
            state
                .finish_failure(failure.code)
                .map_err(ServerError::StateTransition)?;
            lifecycle_error_response(request, failure)
        }
    };
    drop(state);
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    context.reset_lease_runtime()?;
    Ok(response)
}

fn status_response(request: &Request, state: &ServiceState, identity: &CallerIdentity) -> Response {
    Response::success(
        request,
        ResponseData::Status {
            service_phase: state.phase,
            caller_is_owner: state.is_owner(&identity.caller),
            engine_running: state.phase == Phase::Running,
            service_version: env!("CARGO_PKG_VERSION").into(),
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

fn lifecycle_error_response(request: &Request, failure: LifecycleFailure) -> Response {
    Response::error(
        request,
        failure.code,
        failure.safe_message,
        failure.retryable,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Pipe(#[from] super::pipe::PipeError),
    #[error(transparent)]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("service state lock is poisoned")]
    StatePoisoned,
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[error("lease state lock is poisoned")]
    LeasePoisoned,
    #[cfg(feature = "production-local-observability")]
    #[error("local observability state lock is poisoned")]
    ObservabilityPoisoned,
    #[cfg(feature = "production-mihomo-logs-v4")]
    #[error("Mihomo log generation state lock is poisoned")]
    MihomoLogStatePoisoned,
    #[cfg(feature = "production-mihomo-logs-v4")]
    #[error("Mihomo log monitor is unavailable")]
    MihomoLogs(#[source] LogMonitorError),
    #[error("connection limiter lock is poisoned")]
    LimiterPoisoned,
    #[error("service is shutting down")]
    ShuttingDown,
    #[error("lifecycle capability is enabled without an executor")]
    MissingLifecycleExecutor,
    #[error("service state transition failed: {0}")]
    StateTransition(#[source] StateError),
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[error("lease policy failed: {0}")]
    LeasePolicy(#[source] LeaseError),
    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[error("lease monotonic clock overflowed")]
    LeaseClockOverflow,
    #[error("Windows CSPRNG failed: {0}")]
    Random(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{RequestKind, PROTOCOL_VERSION},
        state::{Action, Caller, WatchdogReason},
        watchdog::{HealthSignal, RuntimeObservation, WatchdogDecision, WatchdogPolicy},
        windows::LifecycleExecutor,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    struct FakeLifecycle {
        calls: AtomicUsize,
        failure: Option<LifecycleFailure>,
    }

    impl FakeLifecycle {
        fn successful() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                failure: None,
            })
        }

        fn failing(failure: LifecycleFailure) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                failure: Some(failure),
            })
        }

        fn execute(&self) -> Result<(), LifecycleFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.failure.map_or(Ok(()), Err)
        }
    }

    impl LifecycleExecutor for FakeLifecycle {
        fn start(
            &self,
            _profile: &crate::protocol::ActiveStartProfile,
            _caller: &Caller,
        ) -> Result<(), LifecycleFailure> {
            self.execute()
        }

        fn stop(&self) -> Result<(), LifecycleFailure> {
            self.execute()
        }

        fn recover(&self) -> Result<(), LifecycleFailure> {
            self.execute()
        }
    }

    struct BlockingLifecycle {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl LifecycleExecutor for BlockingLifecycle {
        fn start(
            &self,
            _profile: &crate::protocol::ActiveStartProfile,
            _caller: &Caller,
        ) -> Result<(), LifecycleFailure> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            Ok(())
        }

        fn stop(&self) -> Result<(), LifecycleFailure> {
            Ok(())
        }

        fn recover(&self) -> Result<(), LifecycleFailure> {
            Ok(())
        }
    }

    fn identity(name: &str, session_id: u32) -> CallerIdentity {
        CallerIdentity {
            caller: Caller {
                principal_id: name.into(),
                session_id,
                is_admin: false,
            },
            client_process_id: 42,
        }
    }

    fn request(command: Command) -> Request {
        Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: "a".repeat(64),
            seq: 1,
            request_id: "b".repeat(32),
            command,
        }
    }

    fn profile() -> crate::protocol::ActiveStartProfile {
        crate::protocol::StartProfileV3 {
            upstream: crate::protocol::StartUpstreamV3::LocalListener {
                port: 1080,
                protocol: tunbridge_core::upstream::StandardProtocol::Socks5,
                credentials: None,
                expected_process_id: 42,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: Vec::new(),
        }
    }

    #[test]
    fn status_is_read_only_and_marks_the_owner() {
        let alice = identity("alice", 1);
        let mut service_state = ServiceState::default();
        service_state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        service_state.finish_success(Action::Start).unwrap();
        let context = ServiceContext::status_only(service_state);

        let response = response_for(&request(Command::Status), &alice, &context).unwrap();
        assert!(response.result.ok);
        assert!(matches!(
            response.result.data,
            Some(ResponseData::Status {
                service_phase: Phase::Running,
                caller_is_owner: true,
                engine_running: true,
                ..
            })
        ));
    }

    #[test]
    fn lifecycle_commands_are_not_advertised_or_executed_yet() {
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(ServiceState::default(), lifecycle, false);
        let response =
            response_for(&request(Command::Stop), &identity("alice", 1), &context).unwrap();
        assert!(!response.result.ok);
        assert_eq!(
            response.result.error.unwrap().code,
            ErrorCode::CapabilityUnavailable
        );

        assert_eq!(context.capabilities(), vec![Capability::Status]);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn enabled_start_executes_backend_and_commits_running_state() {
        let alice = identity("alice", 1);
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(ServiceState::default(), lifecycle, true);

        let response = response_for(
            &request(Command::Start { profile: profile() }),
            &alice,
            &context,
        )
        .unwrap();

        assert!(response.result.ok);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert!(state.is_owner(&alice.caller));
        let expected = vec![
            Capability::Status,
            Capability::Start,
            Capability::Stop,
            Capability::Recover,
        ];
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        let expected = {
            let mut expected = expected;
            expected.push(Capability::Lease);
            expected
        };
        #[cfg(feature = "production-local-observability")]
        let expected = {
            let mut expected = expected;
            expected.extend([
                Capability::ObserveLocalTraffic,
                Capability::CloseOwnedConnections,
            ]);
            expected
        };
        #[cfg(feature = "remote-upstream-v3")]
        let expected = {
            let mut expected = expected;
            expected.push(Capability::RemoteUpstream);
            expected
        };
        #[cfg(feature = "production-mihomo-logs-v4")]
        let expected = {
            let mut expected = expected;
            expected.push(Capability::ObserveMihomoLogs);
            expected
        };
        assert_eq!(context.capabilities(), expected);
    }

    #[test]
    fn backend_failure_faults_state_with_a_redacted_error() {
        let failure = LifecycleFailure::new(
            ErrorCode::EngineIntegrityFailed,
            "the installed engine failed integrity validation",
            false,
        );
        let fake = FakeLifecycle::failing(failure);
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(ServiceState::default(), lifecycle, true);

        let response = response_for(
            &request(Command::Start { profile: profile() }),
            &identity("alice", 1),
            &context,
        )
        .unwrap();

        let error = response.result.error.unwrap();
        assert_eq!(error.code, ErrorCode::EngineIntegrityFailed);
        assert_eq!(error.safe_message, failure.safe_message);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert_eq!(state.last_error, Some(ErrorCode::EngineIntegrityFailed));
    }

    #[test]
    fn engine_loss_without_restart_material_is_reported_as_a_stop() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, false);
        let observation = RuntimeObservation::engine_only(HealthSignal::Unhealthy);

        let decision = context
            .apply_watchdog_observation(
                &mut WatchdogPolicy::default(),
                observation,
                "watchdog-test",
            )
            .unwrap();

        assert_eq!(
            decision,
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Stopped);
        assert!(state.owner.is_none());
        assert_eq!(
            state.last_watchdog_reason,
            Some(WatchdogReason::EngineExited)
        );
    }

    #[test]
    fn dead_engine_is_restarted_for_the_same_session() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, false);
        *context.restart.lock().unwrap() = Some(EngineRestart {
            profile: profile(),
            caller: alice.caller.clone(),
            failures: 0,
            next_attempt: None,
            pending: None,
        });
        let decision = context
            .apply_watchdog_observation(
                &mut WatchdogPolicy::default(),
                RuntimeObservation::engine_only(HealthSignal::Unhealthy),
                "watchdog-test",
            )
            .unwrap();
        assert_eq!(
            decision,
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
        // Recover the dead engine's residue, then start it again.
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert!(state.is_owner(&alice.caller));
        assert_eq!(state.degraded_reason, None);
    }

    #[test]
    fn failing_engine_restarts_are_spaced_and_keep_the_session_degraded() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::failing(LifecycleFailure::new(
            ErrorCode::EngineIntegrityFailed,
            "the engine did not start",
            true,
        ));
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, false);
        *context.restart.lock().unwrap() = Some(EngineRestart {
            profile: profile(),
            caller: alice.caller.clone(),
            failures: 0,
            next_attempt: None,
            pending: None,
        });
        let now = Instant::now();
        assert!(!context
            .restart_engine(WatchdogReason::EngineExited, now, "watchdog-1")
            .unwrap());
        assert!(!context
            .restart_engine(WatchdogReason::EngineExited, now, "watchdog-2")
            .unwrap());
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.degraded_reason, Some(WatchdogReason::EngineExited));
    }

    #[test]
    fn unavailable_upstream_degrades_without_restoring_the_network() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, false);
        let mut policy = WatchdogPolicy::default();
        let upstream_down = RuntimeObservation {
            engine: HealthSignal::Healthy,
            upstream: HealthSignal::Unhealthy,
            controller: HealthSignal::Healthy,
            adapter: HealthSignal::Healthy,
        };

        let mut decision = WatchdogDecision::Dormant;
        for index in 0..10 {
            decision = context
                .apply_watchdog_observation(
                    &mut policy,
                    upstream_down,
                    &format!("watchdog-{index}"),
                )
                .unwrap();
        }
        assert_eq!(
            decision,
            WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        {
            let state = context.state.lock().unwrap();
            assert_eq!(state.phase, Phase::Running);
            assert!(state.is_owner(&alice.caller));
            assert_eq!(
                state.degraded_reason,
                Some(WatchdogReason::UpstreamUnavailable)
            );
        }

        context
            .apply_watchdog_observation(
                &mut policy,
                RuntimeObservation::healthy(),
                "watchdog-healthy",
            )
            .unwrap();
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.degraded_reason, None);
    }

    #[test]
    fn watchdog_identity_failure_faults_without_running_cleanup() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, false);
        let observation = RuntimeObservation::engine_only(HealthSignal::Unknown);
        let mut policy = WatchdogPolicy::default();

        for index in 0..3 {
            let decision = context
                .apply_watchdog_observation(&mut policy, observation, &format!("watchdog-{index}"))
                .unwrap();
            if index < 2 {
                assert!(matches!(decision, WatchdogDecision::Hold { .. }));
            } else {
                assert_eq!(
                    decision,
                    WatchdogDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
                );
            }
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert!(state.owner.is_none());
        assert_eq!(state.last_error, Some(ErrorCode::OwnedProcessMismatch));
    }

    #[test]
    fn non_owner_is_rejected_before_the_stop_backend_runs() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let fake = FakeLifecycle::successful();
        let lifecycle: SharedLifecycleExecutor = fake.clone();
        let context = ServiceContext::with_lifecycle(state, lifecycle, true);

        let response =
            response_for(&request(Command::Stop), &identity("bob", 2), &context).unwrap();

        assert_eq!(response.result.error.unwrap().code, ErrorCode::NotOwner);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    #[cfg(feature = "production-local-observability")]
    #[test]
    fn non_owner_is_rejected_before_local_traffic_is_sampled() {
        let alice = identity("alice", 1);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice.caller, "start-traffic")
            .unwrap();
        state.finish_success(Action::Start).unwrap();
        let lifecycle: SharedLifecycleExecutor = FakeLifecycle::successful();
        let context = ServiceContext::with_lifecycle(state, lifecycle, true);

        let response = response_for(
            &request(Command::ObserveTraffic {}),
            &identity("bob", 2),
            &context,
        )
        .unwrap();

        assert_eq!(response.result.error.unwrap().code, ErrorCode::NotOwner);
        let close_response = response_for(
            &request(Command::CloseConnection {
                connection_id: "opaque-id".into(),
            }),
            &identity("bob", 2),
            &context,
        )
        .unwrap();
        assert_eq!(
            close_response.result.error.unwrap().code,
            ErrorCode::NotOwner
        );
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    #[test]
    fn status_observes_starting_without_waiting_for_the_backend() {
        use std::time::Duration;

        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let lifecycle: SharedLifecycleExecutor = Arc::new(BlockingLifecycle {
            entered: entered_sender,
            release: Mutex::new(release_receiver),
        });
        let context = Arc::new(ServiceContext::with_lifecycle(
            ServiceState::default(),
            lifecycle,
            true,
        ));
        let start_context = Arc::clone(&context);
        let starter = std::thread::spawn(move || {
            response_for(
                &request(Command::Start { profile: profile() }),
                &identity("alice", 1),
                &start_context,
            )
            .unwrap()
        });
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let status_context = Arc::clone(&context);
        let (status_sender, status_receiver) = mpsc::sync_channel(1);
        let status_reader = std::thread::spawn(move || {
            let response = response_for(
                &request(Command::Status),
                &identity("alice", 1),
                &status_context,
            )
            .unwrap();
            status_sender.send(response).unwrap();
        });
        let status = status_receiver.recv_timeout(Duration::from_secs(1));
        release_sender.send(()).unwrap();
        let start_response = starter.join().unwrap();
        status_reader.join().unwrap();

        let status = status.expect("status must not wait for the lifecycle backend");
        assert!(matches!(
            status.result.data,
            Some(ResponseData::Status {
                service_phase: Phase::Starting,
                engine_running: false,
                ..
            })
        ));
        assert!(start_response.result.ok);
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    #[test]
    fn nonce_comes_from_windows_csprng() {
        let first = random_hex_32().unwrap();
        let second = random_hex_32().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn connection_permits_are_bounded_and_released() {
        use std::{sync::mpsc, time::Duration};

        let limiter = ConnectionLimiter::new(2);
        let first = limiter.acquire().unwrap();
        let second = limiter.acquire().unwrap();
        assert_eq!(limiter.active(), 2);

        let waiting_limiter = limiter.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let permit = waiting_limiter.acquire().unwrap();
            sender.send(permit).unwrap();
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        let third = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(limiter.active(), 2);
        drop(third);
        drop(second);
        waiter.join().unwrap();
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn shutdown_cancels_a_waiting_connection_permit() {
        let limiter = ConnectionLimiter::new(1);
        let first = limiter.acquire().unwrap();
        let shutdown = ShutdownToken::default();
        let waiting_limiter = limiter.clone();
        let waiting_shutdown = shutdown.clone();
        let waiter =
            std::thread::spawn(move || waiting_limiter.acquire_until_shutdown(&waiting_shutdown));

        std::thread::sleep(Duration::from_millis(20));
        shutdown.cancel();
        assert!(matches!(
            waiter.join().unwrap(),
            Err(ServerError::ShuttingDown)
        ));
        drop(first);
        assert_eq!(limiter.active(), 0);
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[test]
    fn platform_lease_binds_authenticated_owner_and_rotates_nonce() {
        let alice = identity("alice", 1);
        let other_session = identity("alice", 2);
        let state = ServiceState::recovered_running(crate::state::Owner {
            principal_id: alice.caller.principal_id.clone(),
            session_id: alice.caller.session_id,
        });
        let context = ServiceContext::with_lifecycle(state, FakeLifecycle::successful(), true);
        let grant = context.acquire_lease(&alice.caller).unwrap();
        let proof = LeaseProof {
            lease_id: grant.lease_id,
            lease_nonce: grant.lease_nonce,
            seq: grant.next_seq,
        };
        assert!(matches!(
            context.renew_lease(&other_session.caller, proof),
            Err(LeaseRequestError::Policy(LeaseError::NotOwner))
        ));
        let renewed = context.renew_lease(&alice.caller, proof).unwrap();
        assert_ne!(renewed.lease_nonce, grant.lease_nonce);
        assert!(matches!(
            context.renew_lease(&alice.caller, proof),
            Err(LeaseRequestError::Policy(LeaseError::Invalid))
        ));
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[test]
    fn platform_lease_lapse_keeps_the_tunnel() {
        let alice = identity("alice", 1);
        let state = ServiceState::recovered_running(crate::state::Owner {
            principal_id: alice.caller.principal_id.clone(),
            session_id: alice.caller.session_id,
        });
        let fake = FakeLifecycle::successful();
        let context = ServiceContext::with_lifecycle(state, fake.clone(), true);
        for tick in 1..crate::lease::LEASE_REATTACH_GRACE_TICKS {
            assert_eq!(
                context.apply_lease_tick(&format!("lease-{tick}")).unwrap(),
                LeaseDecision::Held
            );
        }
        assert_eq!(
            context.apply_lease_tick("lease-expired").unwrap(),
            LeaseDecision::Lapsed
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.stop_reason(), None);
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    #[test]
    fn every_lifecycle_generation_invalidates_same_owner_lease_state() {
        let alice = identity("alice", 1);
        let context = ServiceContext::with_lifecycle(
            ServiceState::default(),
            FakeLifecycle::successful(),
            true,
        );
        response_for(
            &request(Command::Start { profile: profile() }),
            &alice,
            &context,
        )
        .unwrap();
        let grant = context.acquire_lease(&alice.caller).unwrap();

        response_for(&request(Command::Stop), &alice, &context).unwrap();
        response_for(
            &request(Command::Start { profile: profile() }),
            &alice,
            &context,
        )
        .unwrap();
        let old_proof = LeaseProof {
            lease_id: grant.lease_id,
            lease_nonce: grant.lease_nonce,
            seq: grant.next_seq,
        };
        assert!(matches!(
            context.renew_lease(&alice.caller, old_proof),
            Err(LeaseRequestError::Policy(LeaseError::Invalid))
        ));
    }

    #[cfg(feature = "acceptance-m2b5")]
    #[test]
    fn platform_telemetry_converges_only_at_same_target_threshold() {
        use crate::telemetry::{
            FailureClass, FailureEvent, TargetDigest, TelemetryBatch, TelemetryDecision,
            TelemetryPolicy, STORM_FAILURE_THRESHOLD, STORM_SCHEMA_VERSION,
        };

        let alice = identity("alice", 1);
        let state = ServiceState::recovered_running(crate::state::Owner {
            principal_id: alice.caller.principal_id.clone(),
            session_id: alice.caller.session_id,
        });
        let fake = FakeLifecycle::successful();
        let context = ServiceContext::with_lifecycle(state, fake.clone(), true);
        let generation = context.m2b5_generation().unwrap().unwrap();
        let events = (1..=u64::from(STORM_FAILURE_THRESHOLD))
            .map(|event_seq| FailureEvent {
                schema_version: STORM_SCHEMA_VERSION,
                engine_generation: generation,
                event_seq,
                monotonic_tick: 1,
                target_digest: TargetDigest::from_bytes([7; 32]),
                class: FailureClass::ConnectFailure,
            })
            .collect::<Vec<_>>();
        let mut policy = TelemetryPolicy::default();
        assert_eq!(
            context
                .apply_telemetry_batch(
                    &mut policy,
                    1,
                    generation,
                    TelemetryBatch::Events(&events[..events.len() - 1]),
                    "telemetry-hold",
                )
                .unwrap(),
            TelemetryDecision::Hold
        );
        assert_eq!(
            context
                .apply_telemetry_batch(
                    &mut policy,
                    1,
                    generation,
                    TelemetryBatch::Events(&events[events.len() - 1..]),
                    "telemetry-converge",
                )
                .unwrap(),
            TelemetryDecision::Converge(crate::state::WatchdogReason::ConnectionStorm)
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "acceptance-m2b5")]
    #[test]
    fn platform_telemetry_unknown_faults_without_cleanup() {
        use crate::telemetry::{TelemetryBatch, TelemetryDecision, TelemetryPolicy};

        let alice = identity("alice", 1);
        let state = ServiceState::recovered_running(crate::state::Owner {
            principal_id: alice.caller.principal_id.clone(),
            session_id: alice.caller.session_id,
        });
        let fake = FakeLifecycle::successful();
        let context = ServiceContext::with_lifecycle(state, fake.clone(), true);
        let generation = context.m2b5_generation().unwrap().unwrap();
        let mut policy = TelemetryPolicy::default();
        for tick in 1..=3 {
            let decision = context
                .apply_telemetry_batch(
                    &mut policy,
                    tick,
                    generation,
                    TelemetryBatch::Unknown,
                    &format!("telemetry-unknown-{tick}"),
                )
                .unwrap();
            if tick < 3 {
                assert!(matches!(decision, TelemetryDecision::HoldUnknown { .. }));
            } else {
                assert!(matches!(decision, TelemetryDecision::FaultClosed(_)));
            }
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
        assert_eq!(context.state.lock().unwrap().phase, Phase::Faulted);
    }
}
