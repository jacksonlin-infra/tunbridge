use crate::{
    lifecycle::{RestartedUpstream, RuntimeSample},
    observability::LinuxObservability,
    LifecycleFailure, LinuxLifecycle, UnixServiceConnection, UnixServiceTransport,
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ServiceTransport};
use tunbridge_service::{
    frame,
    lease::{
        LeaseContext, LeaseDecision, LeaseError, LeaseOwner, LeasePolicy, LeaseProof, LeaseSecrets,
        Secret256,
    },
    mihomo_logs::MihomoLogMonitor,
    protocol::{
        ActiveStartProfile, Capability, Command, ErrorCode, Hello, HelloOk, Request, RequestKind,
        Response, ResponseData, SessionGuard, MAX_FRAME_BYTES, PROTOCOL_VERSION,
    },
    state::{Action, Caller, Owner, Phase, ServiceState, StateError, WatchdogReason},
    telemetry::GenerationId,
    watchdog::{HealthSignal, RuntimeObservation, WakeHold, WatchdogDecision, WatchdogPolicy},
};

const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(40);
/// Minimum spacing of restarted-client adoption probes (procfs scan and, at
/// most, one scope move) while the recorded local upstream is gone.
const ADOPTION_PROBE_INTERVAL: Duration = Duration::from_secs(3);
/// Engine restarts are spaced out and bounded; after that the session is
/// reported and left to the user.
const ENGINE_RESTART_SPACING: Duration = Duration::from_secs(5);
const ENGINE_RESTART_ATTEMPTS: u8 = 3;

pub struct LinuxServiceContext {
    state: Mutex<ServiceState>,
    lifecycle: LinuxLifecycle,
    lease: Mutex<Option<LeaseRuntime>>,
    observability: Mutex<LinuxObservability>,
    mihomo_logs: MihomoLogMonitor,
    clock_started: Instant,
    watchdog: Mutex<RuntimeWatchdog>,
    /// What the user started, kept in memory so the service can restart a
    /// dead engine for the same session without the App.
    restart: Mutex<Option<EngineRestart>>,
}

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

#[derive(Default)]
struct RuntimeWatchdog {
    policy: WatchdogPolicy,
    wake_hold: WakeHold,
    sleep_detector: SleepDetector,
    last_detail: Option<&'static str>,
    last_adoption_probe: Option<Instant>,
}

/// Result of one restarted-client adoption probe. It never feeds the
/// watchdog: the session stays degraded until the listener returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdoptionOutcome {
    RateLimited,
    NoCandidate,
    Busy,
    Adopted,
    Failed,
}

struct LeaseRuntime {
    policy: LeasePolicy,
    owner: LeaseOwner,
}

impl LinuxServiceContext {
    pub fn system() -> Result<Self, LifecycleFailure> {
        let lifecycle = LinuxLifecycle::system();
        // The lock outlived the previous service process. Reinstall it so its
        // engine rule matches this service's cgroup again.
        let locked = lifecycle.traffic_lock_present()?;
        if locked {
            lifecycle.install_traffic_lock()?;
        }
        let state = match lifecycle.initial_record()? {
            Some(record) if lifecycle.record_is_running(&record)? => {
                ServiceState::recovered_running(Owner {
                    principal_id: format!("uid:{}", LinuxLifecycle::owner_uid(&record)),
                    session_id: 0,
                })
            }
            // The engine died with the previous service process. Clean up
            // what is left and say so. A locked session stays locked, so
            // traffic is blocked until the user decides.
            Some(_) => {
                lifecycle.recover()?;
                lost_session_state(locked)
            }
            None if locked => lost_session_state(true),
            None => ServiceState::default(),
        };
        let lease = if state.phase == Phase::Running {
            let owner = state.owner.as_ref().ok_or_else(lease_internal)?;
            let owner = LeaseOwner {
                principal_id: owner.principal_id.clone(),
                session_id: owner.session_id,
                generation: GenerationId::from_bytes(
                    random_bytes_32().map_err(|_| lease_internal())?,
                ),
            };
            Some(LeaseRuntime {
                policy: LeasePolicy::recovered_running(
                    Secret256::from_bytes(random_bytes_32().map_err(|_| lease_internal())?),
                    owner.clone(),
                    0,
                )
                .map_err(|_| lease_internal())?,
                owner,
            })
        } else {
            None
        };
        Ok(Self {
            state: Mutex::new(state),
            lifecycle,
            lease: Mutex::new(lease),
            observability: Mutex::new(LinuxObservability::default()),
            mihomo_logs: MihomoLogMonitor::default(),
            clock_started: Instant::now(),
            watchdog: Mutex::new(RuntimeWatchdog::default()),
            restart: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn status_only() -> Self {
        Self {
            state: Mutex::new(ServiceState::default()),
            lifecycle: LinuxLifecycle::system(),
            lease: Mutex::new(None),
            observability: Mutex::new(LinuxObservability::default()),
            mihomo_logs: MihomoLogMonitor::default(),
            clock_started: Instant::now(),
            watchdog: Mutex::new(RuntimeWatchdog::default()),
            restart: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn running_for_test() -> Self {
        let context = Self::status_only();
        {
            let mut state = context.state.lock().unwrap();
            let owner = Caller {
                principal_id: "uid:1000".into(),
                session_id: 0,
                is_admin: false,
            };
            state.begin(Action::Start, &owner, "start-test").unwrap();
            state.finish_success(Action::Start).unwrap();
        }
        context
    }

    pub fn tick(&self) -> Result<(), LifecycleFailure> {
        self.sync_mihomo_logs();
        let pending = self
            .restart
            .lock()
            .map_err(|_| state_internal())?
            .as_ref()
            .and_then(|restart| restart.pending);
        if let Some(reason) = pending {
            return self.restart_engine_for_session(reason);
        }
        let phase = self.state.lock().map_err(|_| state_internal())?.phase;
        let observation = if phase == Phase::Running {
            let sample = self.lifecycle.sample_runtime();
            self.log_runtime_detail(sample.detail)?;
            let probe_restarted_client = sample.probe_restarted_client;
            let observation = self.apply_upstream_rebind(sample, |restarted| {
                let prepared = self.lifecycle.prepare_upstream_rebind(restarted)?;
                Ok(move || self.lifecycle.commit_upstream_rebind(&prepared))
            })?;
            if probe_restarted_client {
                self.apply_upstream_adoption(Instant::now(), || {
                    Ok(self
                        .lifecycle
                        .prepare_upstream_adoption()?
                        .map(|prepared| move || self.lifecycle.commit_upstream_adoption(&prepared)))
                })?;
            }
            observation
        } else {
            // Evaluating outside Running resets every streak.
            RuntimeObservation::engine_only(HealthSignal::NotSampled)
        };
        let observation = self.apply_wake_hold(observation)?;
        let decision = self.apply_watchdog_observation(observation, |reason| {
            self.restart_engine_for_session(reason)
        })?;
        if matches!(
            decision,
            WatchdogDecision::RestartEngine(_) | WatchdogDecision::FaultClosed(_)
        ) {
            return Ok(());
        }
        let snapshot = self.state.lock().map_err(|_| state_internal())?.clone();
        let decision = {
            let mut lease = self.lease.lock().map_err(|_| lease_internal())?;
            let Some(runtime) = lease.as_mut() else {
                return Ok(());
            };
            let context = lease_context(&snapshot, &runtime.owner);
            runtime.policy.evaluate(&context, self.now_tick())
        };
        // The lease only says whether the App is present; it never stops the
        // tunnel. A relaunched App re-acquires it.
        if decision == LeaseDecision::Lapsed {
            eprintln!("TunBridge Linux App lease lapsed; keeping the tunnel");
        }
        Ok(())
    }

    /// After a suspend the TUN, its routes and the engine controller can take
    /// a few seconds to return; do not restart the engine for that.
    fn apply_wake_hold(
        &self,
        observation: RuntimeObservation,
    ) -> Result<RuntimeObservation, LifecycleFailure> {
        let mut watchdog = self.watchdog.lock().map_err(|_| state_internal())?;
        let woke = system_clocks().is_some_and(|(boottime, monotonic)| {
            watchdog.sleep_detector.observe(boottime, monotonic)
        });
        if woke {
            eprintln!("TunBridge Linux system resume detected");
        }
        Ok(watchdog.wake_hold.apply(false, woke, observation))
    }

    fn log_runtime_detail(&self, detail: Option<&'static str>) -> Result<(), LifecycleFailure> {
        let mut watchdog = self.watchdog.lock().map_err(|_| state_internal())?;
        if watchdog.last_detail != detail {
            match detail {
                Some(detail) => eprintln!("TunBridge Linux runtime signal: {detail}"),
                None => eprintln!("TunBridge Linux runtime signal: healthy"),
            }
            watchdog.last_detail = detail;
        }
        Ok(())
    }

    /// Rebinds a restarted local upstream. Preparation (process verification
    /// and the bounded systemd scope attach) runs without the state lock so
    /// Status and Stop stay responsive; the commit runs under the state lock
    /// and only while Running with no operation in progress, so it cannot
    /// race Stop, Recover or a new Start. A failed rebind reports `Unknown`:
    /// the tunnel stays in place and repeated failures fault closed.
    fn apply_upstream_rebind<C>(
        &self,
        sample: RuntimeSample,
        prepare: impl FnOnce(&RestartedUpstream) -> Result<C, LifecycleFailure>,
    ) -> Result<RuntimeObservation, LifecycleFailure>
    where
        C: FnOnce() -> Result<(), LifecycleFailure>,
    {
        let Some(restarted) = sample.restarted_upstream else {
            return Ok(sample.observation);
        };
        let upstream = match prepare(&restarted) {
            Ok(commit) => {
                let state = self.state.lock().map_err(|_| state_internal())?;
                if state.phase != Phase::Running || state.operation_id.is_some() {
                    HealthSignal::NotSampled
                } else {
                    let result = commit();
                    drop(state);
                    match result {
                        Ok(()) => {
                            eprintln!("TunBridge Linux restarted upstream rebound");
                            HealthSignal::Healthy
                        }
                        Err(_) => {
                            eprintln!("TunBridge Linux restarted upstream rebind failed");
                            HealthSignal::Unknown
                        }
                    }
                }
            }
            Err(_) => {
                eprintln!("TunBridge Linux restarted upstream could not be prepared");
                HealthSignal::Unknown
            }
        };
        Ok(RuntimeObservation {
            upstream,
            ..sample.observation
        })
    }

    /// Pre-adopts a restarted client family while the recorded upstream is
    /// gone, rate limited to one probe per `ADOPTION_PROBE_INTERVAL`. The
    /// scope attach runs without the state lock; the nftables/journal/record
    /// commit runs under it, only while Running with no operation in
    /// progress. The outcome never changes the upstream health signal.
    fn apply_upstream_adoption<C>(
        &self,
        now: Instant,
        prepare: impl FnOnce() -> Result<Option<C>, LifecycleFailure>,
    ) -> Result<AdoptionOutcome, LifecycleFailure>
    where
        C: FnOnce() -> Result<(), LifecycleFailure>,
    {
        {
            let mut watchdog = self.watchdog.lock().map_err(|_| state_internal())?;
            if watchdog
                .last_adoption_probe
                .is_some_and(|last| now.saturating_duration_since(last) < ADOPTION_PROBE_INTERVAL)
            {
                return Ok(AdoptionOutcome::RateLimited);
            }
            watchdog.last_adoption_probe = Some(now);
        }
        let commit = match prepare() {
            Ok(Some(commit)) => commit,
            Ok(None) => return Ok(AdoptionOutcome::NoCandidate),
            Err(_) => {
                eprintln!("TunBridge Linux restarted upstream client could not be adopted");
                return Ok(AdoptionOutcome::Failed);
            }
        };
        let state = self.state.lock().map_err(|_| state_internal())?;
        if state.phase != Phase::Running || state.operation_id.is_some() {
            return Ok(AdoptionOutcome::Busy);
        }
        let result = commit();
        drop(state);
        Ok(match result {
            Ok(()) => {
                eprintln!("TunBridge Linux restarted upstream client adopted");
                AdoptionOutcome::Adopted
            }
            Err(_) => {
                eprintln!("TunBridge Linux restarted upstream client adoption failed");
                AdoptionOutcome::Failed
            }
        })
    }

    /// Applies the shared watchdog policy. Nothing here tears the session
    /// down: a dead engine or adapter is restarted, an unavailable upstream or
    /// controller is reported as degraded while the TUN keeps traffic failing
    /// closed, and an unproven identity faults closed in place.
    fn apply_watchdog_observation(
        &self,
        observation: RuntimeObservation,
        restart: impl FnOnce(WatchdogReason) -> Result<(), LifecycleFailure>,
    ) -> Result<WatchdogDecision, LifecycleFailure> {
        let phase = self.state.lock().map_err(|_| state_internal())?.phase;
        let decision = self
            .watchdog
            .lock()
            .map_err(|_| state_internal())?
            .policy
            .evaluate(phase, observation);
        match decision {
            WatchdogDecision::RestartEngine(reason) => restart(reason)?,
            WatchdogDecision::FaultClosed(reason) => self.fault_closed(reason)?,
            WatchdogDecision::Degraded(reason) => {
                let mut state = self.state.lock().map_err(|_| state_internal())?;
                match state.mark_degraded(reason) {
                    Ok(true) => eprintln!("TunBridge Linux session degraded: {reason:?}"),
                    Ok(false) => {}
                    Err(error) if expected_watchdog_race(error) => {}
                    Err(_) => return Err(state_internal()),
                }
            }
            WatchdogDecision::Healthy => {
                if self
                    .state
                    .lock()
                    .map_err(|_| state_internal())?
                    .clear_degraded()
                {
                    eprintln!("TunBridge Linux session resumed");
                }
            }
            WatchdogDecision::Dormant | WatchdogDecision::Hold { .. } => {}
        }
        Ok(decision)
    }

    /// Leaves the owned engine, TUN and route escape in place: their identity
    /// is unproven, so removing them could cross the ownership boundary or
    /// restore direct routes. An explicit Recover remains available.
    fn fault_closed(&self, reason: WatchdogReason) -> Result<(), LifecycleFailure> {
        {
            let mut state = self.state.lock().map_err(|_| state_internal())?;
            match state.record_automatic_fault(reason, ErrorCode::OwnedProcessMismatch) {
                Ok(()) => eprintln!("TunBridge Linux session faulted closed: {reason:?}"),
                Err(error) if expected_watchdog_race(error) => return Ok(()),
                Err(_) => return Err(state_internal()),
            }
        }
        *self.lease.lock().map_err(|_| lease_internal())? = None;
        self.observability
            .lock()
            .map_err(|_| lease_internal())?
            .reset();
        self.sync_mihomo_logs();
        Ok(())
    }

    fn restart_engine_for_session(&self, reason: WatchdogReason) -> Result<(), LifecycleFailure> {
        self.restart_engine(
            reason,
            Instant::now(),
            || self.lifecycle.recover(),
            |profile, caller| {
                self.lifecycle
                    .start(profile, caller)
                    .and_then(|()| self.lifecycle.install_traffic_lock())
            },
            || self.lifecycle.traffic_lock_present().unwrap_or(true),
        )
    }

    /// Restarts the engine of the running session from the material the user
    /// started it with. The session stays Running and owned, reported as
    /// degraded, while attempts are spaced out. A service that restarted has
    /// no material, and repeated failures give up; either way the session is
    /// reported as stopped by an engine exit so the user decides what next.
    fn restart_engine(
        &self,
        reason: WatchdogReason,
        now: Instant,
        recover: impl FnOnce() -> Result<(), LifecycleFailure>,
        start: impl FnOnce(&ActiveStartProfile, &Caller) -> Result<(), LifecycleFailure>,
        locked: impl FnOnce() -> bool,
    ) -> Result<(), LifecycleFailure> {
        let mut restart = self.restart.lock().map_err(|_| state_internal())?;
        let attempt = match restart.as_mut() {
            Some(pending) if pending.failures >= ENGINE_RESTART_ATTEMPTS => None,
            Some(pending) if pending.next_attempt.is_some_and(|next| now < next) => {
                return Ok(());
            }
            Some(pending) => Some((pending.profile.clone(), pending.caller.clone())),
            None => None,
        };
        let Some((profile, caller)) = attempt else {
            *restart = None;
            drop(restart);
            eprintln!("TunBridge Linux engine restart abandoned: {reason:?}");
            return self.stop_after_engine_loss(reason, recover, locked);
        };
        {
            let mut state = self.state.lock().map_err(|_| state_internal())?;
            match state.mark_degraded(reason) {
                Ok(_) => {}
                Err(error) if expected_watchdog_race(error) => return Ok(()),
                Err(_) => return Err(state_internal()),
            }
        }
        let result = recover().and_then(|()| start(&profile, &caller));
        let pending = restart.as_mut().ok_or_else(state_internal)?;
        match result {
            Ok(()) => {
                eprintln!("TunBridge Linux engine restarted after {reason:?}");
                pending.failures = 0;
                pending.next_attempt = None;
                pending.pending = None;
                drop(restart);
                self.watchdog
                    .lock()
                    .map_err(|_| state_internal())?
                    .policy
                    .reset();
                self.observability
                    .lock()
                    .map_err(|_| state_internal())?
                    .reset();
                self.state
                    .lock()
                    .map_err(|_| state_internal())?
                    .clear_degraded();
                self.sync_mihomo_logs();
            }
            Err(error) => {
                eprintln!(
                    "TunBridge Linux engine restart failed after {reason:?}: {:?}",
                    error.code
                );
                pending.failures = pending.failures.saturating_add(1);
                pending.next_attempt = Some(now + ENGINE_RESTART_SPACING);
                pending.pending = Some(reason);
            }
        }
        Ok(())
    }

    /// The engine is gone and cannot be brought back: clean up what is left
    /// and report the stop with its reason.
    fn stop_after_engine_loss(
        &self,
        reason: WatchdogReason,
        recover: impl FnOnce() -> Result<(), LifecycleFailure>,
        locked: impl FnOnce() -> bool,
    ) -> Result<(), LifecycleFailure> {
        {
            let mut state = self.state.lock().map_err(|_| lease_internal())?;
            match state
                .begin_automatic_recovery(reason, random_hex::<16>().map_err(|_| lease_internal())?)
            {
                Ok(()) => eprintln!("TunBridge Linux session stopped by engine loss: {reason:?}"),
                Err(error) if expected_watchdog_race(error) => return Ok(()),
                Err(_) => return Err(lease_internal()),
            }
        }
        let result = recover();
        // The traffic lock stays: without an engine, traffic is blocked
        // instead of sent directly until the user decides.
        let locked = locked();
        let mut state = self.state.lock().map_err(|_| lease_internal())?;
        match result {
            Ok(()) if locked => state
                .finish_failure(ErrorCode::RecoveryRequired)
                .map_err(|_| lease_internal())?,
            Ok(()) => state
                .finish_success(Action::Recover)
                .map_err(|_| lease_internal())?,
            Err(error) => {
                state
                    .finish_failure(error.code)
                    .map_err(|_| lease_internal())?;
                return Err(error);
            }
        }
        drop(state);
        *self.lease.lock().map_err(|_| lease_internal())? = None;
        self.observability
            .lock()
            .map_err(|_| lease_internal())?
            .reset();
        self.sync_mihomo_logs();
        Ok(())
    }

    fn sync_mihomo_logs(&self) {
        let running = self
            .state
            .lock()
            .ok()
            .is_some_and(|state| state.phase == Phase::Running);
        if !running {
            let _ = self.mihomo_logs.stop();
            return;
        }
        match self.lifecycle.mihomo_log_session() {
            Ok(session) => {
                let _ = self.mihomo_logs.sync(Some(session));
            }
            Err(_) => {
                let _ = self.mihomo_logs.stop();
            }
        }
    }

    fn now_tick(&self) -> u64 {
        self.clock_started.elapsed().as_secs()
    }

    fn lease_response(&self, request: &Request, caller: &Caller) -> Result<Response, AdapterError> {
        let snapshot = self.state.lock().map_err(|_| unavailable())?.clone();
        if snapshot.phase != Phase::Running || !snapshot.is_owner(caller) {
            return Ok(lease_error_response(
                request,
                if snapshot.phase != Phase::Running {
                    LeaseError::NotRunning
                } else {
                    LeaseError::NotOwner
                },
            ));
        }
        let mut slot = self.lease.lock().map_err(|_| unavailable())?;
        if slot.is_none() {
            let owner = LeaseOwner {
                principal_id: caller.principal_id.clone(),
                session_id: caller.session_id,
                generation: GenerationId::from_bytes(random_bytes_32()?),
            };
            *slot = Some(LeaseRuntime {
                policy: LeasePolicy::new(Secret256::from_bytes(random_bytes_32()?)),
                owner,
            });
        }
        let runtime = slot.as_mut().expect("lease runtime is initialized");
        let context = lease_context(&snapshot, &runtime.owner);
        let result = match &request.command {
            Command::AcquireLease {} => runtime
                .policy
                .acquire(
                    &context,
                    caller,
                    self.now_tick(),
                    LeaseSecrets {
                        lease_id: Secret256::from_bytes(random_bytes_32()?),
                        lease_nonce: Secret256::from_bytes(random_bytes_32()?),
                    },
                )
                .map(|grant| ResponseData::Lease {
                    lease_id: grant.lease_id.to_lower_hex(),
                    lease_nonce: grant.lease_nonce.to_lower_hex(),
                    next_seq: grant.next_seq,
                    ttl_ticks: grant.ttl_ticks,
                    renew_after_ticks: grant.renew_after_ticks,
                }),
            Command::RenewLease {
                lease_id,
                lease_nonce,
                lease_seq,
            } => lease_proof(lease_id, lease_nonce, *lease_seq)
                .and_then(|proof| {
                    runtime.policy.renew(
                        &context,
                        caller,
                        self.now_tick(),
                        proof,
                        Secret256::from_bytes(random_bytes_32().map_err(|_| LeaseError::Invalid)?),
                    )
                })
                .map(|grant| ResponseData::Lease {
                    lease_id: grant.lease_id.to_lower_hex(),
                    lease_nonce: grant.lease_nonce.to_lower_hex(),
                    next_seq: grant.next_seq,
                    ttl_ticks: grant.ttl_ticks,
                    renew_after_ticks: grant.renew_after_ticks,
                }),
            Command::ReleaseLease {
                lease_id,
                lease_nonce,
                lease_seq,
            } => lease_proof(lease_id, lease_nonce, *lease_seq)
                .and_then(|proof| {
                    runtime
                        .policy
                        .release(&context, caller, self.now_tick(), proof)
                })
                .map(|()| ResponseData::LeaseReleased { released: true }),
            _ => unreachable!(),
        };
        Ok(match result {
            Ok(data) => Response::success(request, data),
            Err(error) => lease_error_response(request, error),
        })
    }
}

pub fn serve_connection(
    mut connection: UnixServiceConnection,
    context: Arc<LinuxServiceContext>,
    maximum_requests: u64,
) -> Result<(), AdapterError> {
    if maximum_requests == 0 {
        return Err(invalid_data());
    }
    let peer = connection.peer_credentials();
    let caller = Caller {
        principal_id: format!("uid:{}", peer.user_id),
        session_id: 0,
        is_admin: peer.user_id == 0,
    };
    let hello: Hello = decode(&connection.receive_frame()?)?;
    hello.validate().map_err(|_| invalid_data())?;
    let nonce = random_hex::<32>()?;
    let hello_ok = HelloOk::with_capabilities(
        SERVICE_VERSION,
        nonce.clone(),
        vec![
            Capability::Status,
            Capability::Start,
            Capability::Stop,
            Capability::Recover,
            Capability::Lease,
            Capability::ObserveLocalTraffic,
            Capability::CloseOwnedConnections,
            Capability::RemoteUpstream,
            Capability::ObserveMihomoLogs,
        ],
    );
    connection.send_frame(&encode(&hello_ok)?)?;
    let mut guard = SessionGuard::new(nonce).map_err(|_| invalid_data())?;
    for _ in 0..maximum_requests {
        let request: Request = decode(&connection.receive_frame()?)?;
        guard.accept(&request).map_err(|_| invalid_data())?;
        let response = response_for(&request, &caller, &context)?;
        connection.send_frame(&encode(&response)?)?;
    }
    Ok(())
}

fn response_for(
    request: &Request,
    caller: &Caller,
    context: &LinuxServiceContext,
) -> Result<Response, AdapterError> {
    #[allow(unreachable_patterns)]
    match &request.command {
        Command::Status => {
            let state = context.state.lock().map_err(|_| unavailable())?;
            Ok(status_response(request, &state, caller))
        }
        Command::Start { .. } | Command::Stop | Command::Recover => {
            execute_lifecycle(request, caller, context)
        }
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            context.lease_response(request, caller)
        }
        Command::ObserveTraffic {}
        | Command::ListConnections { .. }
        | Command::CloseConnection { .. }
        | Command::CloseAllConnections {} => execute_observability(request, caller, context),
        Command::ListMihomoLogs { .. } => execute_mihomo_logs(request, caller, context),
        _ => Ok(Response::error(
            request,
            ErrorCode::CapabilityUnavailable,
            "This capability is unavailable on Linux.",
            false,
        )),
    }
}

fn execute_lifecycle(
    request: &Request,
    caller: &Caller,
    context: &LinuxServiceContext,
) -> Result<Response, AdapterError> {
    let action = match request.command {
        Command::Start { .. } => Action::Start,
        Command::Stop => Action::Stop,
        Command::Recover => Action::Recover,
        _ => unreachable!(),
    };
    {
        let mut state = context.state.lock().map_err(|_| unavailable())?;
        if let Err(error) = state.begin(action, caller, &request.request_id) {
            return Ok(state_error_response(request, error));
        }
    }
    // The traffic lock belongs to the user's start and stop only. It goes up
    // once the tunnel and the client's escape exist: earlier it would cut the
    // proxy client's open connections before they are marked as escaped, and
    // before the tunnel is up traffic was going directly anyway. A start that
    // cannot be locked is rolled back.
    let result = match &request.command {
        Command::Start { profile } => context
            .lifecycle
            .start(profile, caller)
            .and_then(|()| context.lifecycle.install_traffic_lock())
            .inspect_err(|_| {
                let _ = context.lifecycle.recover();
                let _ = context.lifecycle.remove_traffic_lock();
            }),
        Command::Stop => context
            .lifecycle
            .stop()
            .and_then(|()| context.lifecycle.remove_traffic_lock()),
        Command::Recover => context
            .lifecycle
            .recover()
            .and_then(|()| context.lifecycle.remove_traffic_lock()),
        _ => unreachable!(),
    };
    *context.restart.lock().map_err(|_| unavailable())? = match (&request.command, &result) {
        (Command::Start { profile }, Ok(())) => Some(EngineRestart {
            profile: profile.clone(),
            caller: caller.clone(),
            failures: 0,
            next_attempt: None,
            pending: None,
        }),
        _ => None,
    };
    if let Err(failure) = &result {
        eprintln!(
            "TunBridge Linux {action:?} failed: {:?} ({})",
            failure.code, failure.safe_message
        );
    }
    let mut state = context.state.lock().map_err(|_| unavailable())?;
    let response = match result {
        Ok(()) => {
            state.finish_success(action).map_err(|_| unavailable())?;
            status_response(request, &state, caller)
        }
        Err(failure) => {
            state
                .finish_failure(failure.code)
                .map_err(|_| unavailable())?;
            Response::error(
                request,
                failure.code,
                failure.safe_message,
                failure.retryable,
            )
        }
    };
    drop(state);
    *context.lease.lock().map_err(|_| unavailable())? = None;
    context
        .observability
        .lock()
        .map_err(|_| unavailable())?
        .reset();
    context.sync_mihomo_logs();
    Ok(response)
}

fn execute_mihomo_logs(
    request: &Request,
    caller: &Caller,
    context: &LinuxServiceContext,
) -> Result<Response, AdapterError> {
    let state = context.state.lock().map_err(|_| unavailable())?;
    if state.phase != Phase::Running {
        return Ok(Response::error(
            request,
            ErrorCode::NotRunning,
            "TunBridge is not running.",
            true,
        ));
    }
    if !state.is_owner(caller) {
        return Ok(Response::error(
            request,
            ErrorCode::NotOwner,
            "The caller does not own the running session.",
            false,
        ));
    }
    drop(state);
    context.sync_mihomo_logs();
    let Command::ListMihomoLogs {
        after_sequence,
        limit,
    } = &request.command
    else {
        return Err(invalid_data());
    };
    Ok(match context.mihomo_logs.page(*after_sequence, *limit) {
        Ok(page) => Response::success(request, ResponseData::MihomoLogPage { page }),
        Err(_) => Response::error(
            request,
            ErrorCode::ObservabilityUnavailable,
            "Mihomo logs are temporarily unavailable.",
            true,
        ),
    })
}

fn execute_observability(
    request: &Request,
    caller: &Caller,
    context: &LinuxServiceContext,
) -> Result<Response, AdapterError> {
    let state = context.state.lock().map_err(|_| unavailable())?;
    if state.phase != Phase::Running {
        return Ok(Response::error(
            request,
            ErrorCode::NotRunning,
            "TunBridge is not running.",
            true,
        ));
    }
    if !state.is_owner(caller) {
        return Ok(Response::error(
            request,
            ErrorCode::NotOwner,
            "The caller does not own the running session.",
            false,
        ));
    }
    drop(state);
    let mut observability = context.observability.lock().map_err(|_| unavailable())?;
    let result = match &request.command {
        Command::ObserveTraffic {} => observability
            .sample(&context.lifecycle)
            .map(|snapshot| ResponseData::TrafficSnapshot { snapshot }),
        Command::ListConnections {
            state,
            offset,
            limit,
        } => observability
            .page(&context.lifecycle, *state, *offset, *limit)
            .map(|page| ResponseData::ConnectionPage { page }),
        Command::CloseConnection { connection_id } => observability
            .close(&context.lifecycle, Some(connection_id))
            .map(|closed| ResponseData::ConnectionsClosed { closed }),
        Command::CloseAllConnections {} => observability
            .close(&context.lifecycle, None)
            .map(|closed| ResponseData::ConnectionsClosed { closed }),
        _ => unreachable!(),
    };
    Ok(match result {
        Ok(data) => Response::success(request, data),
        Err(error) => Response::error(request, error.code, error.safe_message, error.retryable),
    })
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

pub struct LinuxServiceClient {
    transport: UnixServiceTransport,
    nonce: String,
    next_sequence: u64,
    capabilities: Vec<Capability>,
}

pub type LinuxStatusClient = LinuxServiceClient;

#[derive(Debug)]
pub enum LinuxClientError {
    Adapter(AdapterError),
    Service { code: ErrorCode, retryable: bool },
}

impl LinuxServiceClient {
    pub fn connect_system() -> Result<Self, AdapterError> {
        Self::handshake(UnixServiceTransport::connect_system()?)
    }

    pub fn connect(path: &Path, expected_server_uid: u32) -> Result<Self, AdapterError> {
        Self::handshake(UnixServiceTransport::connect(path, expected_server_uid)?)
    }

    fn handshake(mut transport: UnixServiceTransport) -> Result<Self, AdapterError> {
        let response =
            transport.transact(&encode(&Hello::new(SERVICE_VERSION))?, REQUEST_TIMEOUT)?;
        let hello: HelloOk = decode(&response)?;
        if hello.protocol != PROTOCOL_VERSION
            || hello.max_frame_bytes != MAX_FRAME_BYTES
            || hello.service_version.is_empty()
            || !hello.capabilities.contains(&Capability::Status)
        {
            return Err(identity_rejected());
        }
        SessionGuard::new(hello.session_nonce.clone()).map_err(|_| identity_rejected())?;
        Ok(Self {
            transport,
            nonce: hello.session_nonce,
            next_sequence: 1,
            capabilities: hello.capabilities,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn status(&mut self) -> Result<ResponseData, AdapterError> {
        self.send(Command::Status, REQUEST_TIMEOUT)
    }

    pub fn start(&mut self, profile: ActiveStartProfile) -> Result<ResponseData, AdapterError> {
        self.send_detailed(Command::Start { profile }, LIFECYCLE_TIMEOUT)
            .map_err(map_detailed)
    }

    pub fn stop(&mut self) -> Result<ResponseData, AdapterError> {
        self.send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
            .map_err(map_detailed)
    }

    pub fn recover(&mut self) -> Result<ResponseData, AdapterError> {
        self.send_detailed(Command::Recover, LIFECYCLE_TIMEOUT)
            .map_err(map_detailed)
    }

    pub fn send(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<ResponseData, AdapterError> {
        self.send_detailed(command, timeout).map_err(map_detailed)
    }

    pub fn send_detailed(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<ResponseData, LinuxClientError> {
        command
            .validate()
            .map_err(|_| LinuxClientError::Adapter(invalid_data()))?;
        let required = required_capability(&command);
        if !self.capabilities.contains(&required) {
            return Err(LinuxClientError::Adapter(unavailable()));
        }
        let request = Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: self.nonce.clone(),
            seq: self.next_sequence,
            request_id: random_hex::<16>().map_err(LinuxClientError::Adapter)?,
            command,
        };
        let frame = encode(&request).map_err(LinuxClientError::Adapter)?;
        let response_frame = self
            .transport
            .transact(&frame, timeout)
            .map_err(LinuxClientError::Adapter)?;
        let response: Response = decode(&response_frame).map_err(LinuxClientError::Adapter)?;
        if response.protocol != PROTOCOL_VERSION
            || response.seq != request.seq
            || response.request_id != request.request_id
        {
            return Err(LinuxClientError::Adapter(identity_rejected()));
        }
        self.next_sequence += 1;
        if response.result.ok {
            response
                .result
                .data
                .ok_or_else(|| LinuxClientError::Adapter(invalid_data()))
        } else {
            let error = response
                .result
                .error
                .ok_or_else(|| LinuxClientError::Adapter(invalid_data()))?;
            Err(LinuxClientError::Service {
                code: error.code,
                retryable: error.retryable,
            })
        }
    }
}

fn map_detailed(error: LinuxClientError) -> AdapterError {
    match error {
        LinuxClientError::Adapter(error) => error,
        LinuxClientError::Service { retryable, .. } => service_error(retryable),
    }
}

fn required_capability(command: &Command) -> Capability {
    #[allow(unreachable_patterns)]
    match command {
        Command::Status => Capability::Status,
        Command::Start { .. } => Capability::Start,
        Command::Stop => Capability::Stop,
        Command::Recover => Capability::Recover,
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            Capability::Lease
        }
        Command::ObserveTraffic {} | Command::ListConnections { .. } => {
            Capability::ObserveLocalTraffic
        }
        Command::CloseConnection { .. } | Command::CloseAllConnections {} => {
            Capability::CloseOwnedConnections
        }
        Command::ListMihomoLogs { .. } => Capability::ObserveMihomoLogs,
        _ => Capability::Status,
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AdapterError> {
    frame::encode(value).map_err(|_| invalid_data())
}

fn decode<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T, AdapterError> {
    frame::decode(value).map_err(|_| invalid_data())
}

fn random_hex<const BYTES: usize>() -> Result<String, AdapterError> {
    let bytes = random_bytes::<BYTES>()?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn random_bytes_32() -> Result<[u8; 32], AdapterError> {
    random_bytes::<32>()
}

fn random_bytes<const BYTES: usize>() -> Result<[u8; BYTES], AdapterError> {
    let mut bytes = [0_u8; BYTES];
    let mut filled = 0;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result <= 0 {
            return Err(unavailable());
        }
        filled += result as usize;
    }
    Ok(bytes)
}

const fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "The Linux service protocol data is invalid.",
        retryable: false,
    }
}

const fn identity_rejected() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::IdentityRejected,
        safe_message: "The Linux service response identity could not be verified.",
        retryable: false,
    }
}

const fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "The Linux service is unavailable.",
        retryable: true,
    }
}

const fn service_error(retryable: bool) -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "The Linux service rejected the operation safely.",
        retryable,
    }
}

fn expected_watchdog_race(error: StateError) -> bool {
    matches!(
        error,
        StateError::OperationInProgress | StateError::NotRunning | StateError::RecoveryRequired
    )
}

const fn state_internal() -> LifecycleFailure {
    LifecycleFailure {
        code: ErrorCode::InternalError,
        safe_message: "The Linux service state is unavailable.",
        retryable: false,
    }
}

/// How a session that disappeared is reported: with the lock still in place
/// it is a fault the user must resolve (traffic is blocked), otherwise a stop.
fn lost_session_state(locked: bool) -> ServiceState {
    ServiceState {
        phase: if locked {
            Phase::Faulted
        } else {
            Phase::Stopped
        },
        last_error: locked.then_some(ErrorCode::RecoveryRequired),
        last_watchdog_reason: Some(WatchdogReason::EngineExited),
        ..ServiceState::default()
    }
}

const fn lease_internal() -> LifecycleFailure {
    LifecycleFailure {
        code: ErrorCode::InternalError,
        safe_message: "The Linux App lease state is unavailable.",
        retryable: false,
    }
}

/// A CLOCK_BOOTTIME advance this much larger than the CLOCK_MONOTONIC
/// advance between two ticks means the system was suspended in between.
const MIN_DETECTED_SUSPEND_SECONDS: u64 = 2;

#[derive(Debug, Default)]
struct SleepDetector {
    previous: Option<(u64, u64)>,
}

impl SleepDetector {
    fn observe(&mut self, boottime: u64, monotonic: u64) -> bool {
        let suspended = self
            .previous
            .is_some_and(|(previous_boottime, previous_monotonic)| {
                boottime.saturating_sub(previous_boottime)
                    > monotonic
                        .saturating_sub(previous_monotonic)
                        .saturating_add(MIN_DETECTED_SUSPEND_SECONDS)
            });
        self.previous = Some((boottime, monotonic));
        suspended
    }
}

/// (CLOCK_BOOTTIME, CLOCK_MONOTONIC) in seconds. BOOTTIME keeps counting
/// during suspend; MONOTONIC does not.
fn system_clocks() -> Option<(u64, u64)> {
    fn seconds(clock: libc::clockid_t) -> Option<u64> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: value is a valid, writable timespec for the call.
        (unsafe { libc::clock_gettime(clock, &mut value) } == 0)
            .then(|| u64::try_from(value.tv_sec).ok())
            .flatten()
    }
    Some((
        seconds(libc::CLOCK_BOOTTIME)?,
        seconds(libc::CLOCK_MONOTONIC)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnixServiceListener;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tunbridge_core::upstream::{SecretMaterialV2, StandardProtocol};
    use tunbridge_service::protocol::{StartProfileV3, StartUpstreamV3};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    fn local_profile(
        port: u16,
        protocol: StandardProtocol,
        process_id: u32,
        credentials: Option<SecretMaterialV2>,
        bypass_process_names: Vec<String>,
    ) -> StartProfileV3 {
        StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port,
                protocol,
                credentials,
                expected_process_id: process_id,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: bypass_process_names,
        }
    }

    fn endpoint(name: &str) -> (PathBuf, PathBuf, u32) {
        let directory = std::env::temp_dir().join(format!(
            "tunbridge-linux-service-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("service.sock");
        (directory, path, unsafe { libc::geteuid() })
    }

    #[test]
    fn service_publishes_full_protocol_and_kernel_owned_status() {
        let (directory, path, uid) = endpoint("status");
        let listener = UnixServiceListener::bind(path.clone(), uid).unwrap();
        let server = std::thread::spawn(move || {
            let connection = listener.accept(Some(uid), Duration::from_secs(2)).unwrap();
            serve_connection(connection, Arc::new(LinuxServiceContext::status_only()), 1).unwrap();
        });
        let mut client = LinuxServiceClient::connect(&path, uid).unwrap();
        assert_eq!(
            client.capabilities(),
            [
                Capability::Status,
                Capability::Start,
                Capability::Stop,
                Capability::Recover,
                Capability::Lease,
                Capability::ObserveLocalTraffic,
                Capability::CloseOwnedConnections,
                Capability::RemoteUpstream,
                Capability::ObserveMihomoLogs,
            ]
        );
        assert!(matches!(
            client.status().unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                engine_running: false,
                ..
            }
        ));
        server.join().unwrap();
        fs::remove_dir(directory).unwrap();
    }

    fn observation(
        engine: HealthSignal,
        upstream: HealthSignal,
        controller: HealthSignal,
        adapter: HealthSignal,
    ) -> RuntimeObservation {
        RuntimeObservation {
            engine,
            upstream,
            controller,
            adapter,
        }
    }

    fn upstream_down() -> RuntimeObservation {
        observation(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        )
    }

    fn no_recovery(_reason: WatchdogReason) -> Result<(), LifecycleFailure> {
        panic!("an upstream-only failure must never touch the engine")
    }

    fn degraded_reason(context: &LinuxServiceContext) -> Option<WatchdogReason> {
        match status_response(
            &Request {
                kind: RequestKind::Request,
                protocol: PROTOCOL_VERSION,
                session_nonce: "0".repeat(64),
                seq: 1,
                request_id: "status".into(),
                command: Command::Status,
            },
            &context.state.lock().unwrap(),
            &Caller {
                principal_id: "uid:1000".into(),
                session_id: 0,
                is_admin: false,
            },
        )
        .result
        .data
        {
            Some(ResponseData::Status {
                service_phase: Phase::Running,
                degraded_reason,
                stop_reason: None,
                ..
            }) => degraded_reason,
            other => panic!("unexpected status: {other:?}"),
        }
    }

    #[test]
    fn unavailable_upstream_degrades_and_resumes_without_recovery() {
        let context = LinuxServiceContext::running_for_test();
        for _ in 1..tunbridge_service::watchdog::UPSTREAM_FAILURE_THRESHOLD {
            assert!(matches!(
                context
                    .apply_watchdog_observation(upstream_down(), no_recovery)
                    .unwrap(),
                WatchdogDecision::Hold { .. }
            ));
            assert_eq!(degraded_reason(&context), None);
        }
        for _ in 0..10 {
            assert_eq!(
                context
                    .apply_watchdog_observation(upstream_down(), no_recovery)
                    .unwrap(),
                WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
            );
            assert_eq!(
                degraded_reason(&context),
                Some(WatchdogReason::UpstreamUnavailable)
            );
        }

        assert_eq!(
            context
                .apply_watchdog_observation(RuntimeObservation::healthy(), no_recovery)
                .unwrap(),
            WatchdogDecision::Healthy
        );
        assert_eq!(degraded_reason(&context), None);
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    #[test]
    fn engine_exit_and_lost_adapter_ask_for_a_restart_never_a_teardown() {
        let context = LinuxServiceContext::running_for_test();
        for _ in 0..tunbridge_service::watchdog::UPSTREAM_FAILURE_THRESHOLD {
            context
                .apply_watchdog_observation(upstream_down(), no_recovery)
                .unwrap();
        }
        let restarts = std::cell::Cell::new(None);
        assert_eq!(
            context
                .apply_watchdog_observation(
                    observation(
                        HealthSignal::Unhealthy,
                        HealthSignal::Unhealthy,
                        HealthSignal::Unhealthy,
                        HealthSignal::Unhealthy,
                    ),
                    |reason| {
                        restarts.set(Some(reason));
                        Ok(())
                    },
                )
                .unwrap(),
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
        assert_eq!(restarts.get(), Some(WatchdogReason::EngineExited));

        let context = LinuxServiceContext::running_for_test();
        let adapter_missing = observation(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
        );
        assert!(matches!(
            context
                .apply_watchdog_observation(adapter_missing, no_recovery)
                .unwrap(),
            WatchdogDecision::Hold { .. }
        ));
        assert_eq!(
            context
                .apply_watchdog_observation(adapter_missing, |_| Ok(()))
                .unwrap(),
            WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing)
        );
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    #[test]
    fn unresponsive_controller_degrades_and_keeps_the_engine() {
        let context = LinuxServiceContext::running_for_test();
        let controller_down = observation(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
        );
        for _ in 0..tunbridge_service::watchdog::CONTROLLER_FAILURE_THRESHOLD {
            context
                .apply_watchdog_observation(controller_down, no_recovery)
                .unwrap();
        }
        assert_eq!(
            degraded_reason(&context),
            Some(WatchdogReason::ControllerUnavailable)
        );
    }

    #[test]
    fn engine_restart_keeps_the_session_and_gives_up_after_spaced_failures() {
        let context = LinuxServiceContext::running_for_test();
        let owner = Caller {
            principal_id: "uid:1000".into(),
            session_id: 0,
            is_admin: false,
        };
        *context.restart.lock().unwrap() = Some(EngineRestart {
            profile: local_profile(7890, StandardProtocol::Http, 4242, None, Vec::new()),
            caller: owner.clone(),
            failures: 0,
            next_attempt: None,
            pending: None,
        });
        let now = Instant::now();
        let starts = std::cell::Cell::new(0);
        context
            .restart_engine(
                WatchdogReason::EngineExited,
                now,
                || Ok(()),
                |_, caller| {
                    assert_eq!(caller, &owner);
                    starts.set(starts.get() + 1);
                    Ok(())
                },
                || true,
            )
            .unwrap();
        let state = context.state.lock().unwrap().clone();
        assert_eq!((state.phase, state.degraded_reason), (Phase::Running, None));

        let failing = |_: &ActiveStartProfile, _: &Caller| -> Result<(), LifecycleFailure> {
            starts.set(starts.get() + 1);
            Err(state_internal())
        };
        context
            .restart_engine(
                WatchdogReason::EngineExited,
                now,
                || Ok(()),
                failing,
                || true,
            )
            .unwrap();
        assert_eq!(
            context.state.lock().unwrap().degraded_reason,
            Some(WatchdogReason::EngineExited)
        );
        // Spaced: an immediate retry does nothing.
        context
            .restart_engine(
                WatchdogReason::EngineExited,
                now,
                || Ok(()),
                failing,
                || true,
            )
            .unwrap();
        assert_eq!(starts.get(), 2);
        for attempt in 1..ENGINE_RESTART_ATTEMPTS {
            context
                .restart_engine(
                    WatchdogReason::EngineExited,
                    now + ENGINE_RESTART_SPACING * u32::from(attempt),
                    || Ok(()),
                    failing,
                    || true,
                )
                .unwrap();
        }
        assert_eq!(starts.get(), 1 + usize::from(ENGINE_RESTART_ATTEMPTS));
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
        context
            .restart_engine(
                WatchdogReason::EngineExited,
                now + ENGINE_RESTART_SPACING * 10,
                || Ok(()),
                failing,
                || true,
            )
            .unwrap();
        // The lock stays, so the session is a fault the user resolves; traffic
        // stays blocked rather than direct.
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert_eq!(state.stop_reason(), Some(WatchdogReason::EngineExited));
    }

    #[test]
    fn lost_session_is_a_fault_while_locked_and_a_stop_otherwise() {
        let locked = lost_session_state(true);
        assert_eq!(locked.phase, Phase::Faulted);
        assert_eq!(locked.stop_reason(), Some(WatchdogReason::EngineExited));
        let unlocked = lost_session_state(false);
        assert_eq!(unlocked.phase, Phase::Stopped);
        assert_eq!(unlocked.stop_reason(), Some(WatchdogReason::EngineExited));
    }

    #[test]
    fn unprovable_identity_faults_closed_without_restoring_the_network() {
        let context = LinuxServiceContext::running_for_test();
        let unknown = observation(
            HealthSignal::Healthy,
            HealthSignal::Unknown,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        for _ in 1..tunbridge_service::watchdog::UNKNOWN_FAILURE_THRESHOLD {
            context
                .apply_watchdog_observation(unknown, no_recovery)
                .unwrap();
        }
        assert_eq!(
            context
                .apply_watchdog_observation(unknown, no_recovery)
                .unwrap(),
            WatchdogDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
        );
        let state = context.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert_eq!(
            state.stop_reason(),
            Some(WatchdogReason::RuntimeIdentityMismatch)
        );
    }

    fn restarted_sample() -> RuntimeSample {
        RuntimeSample {
            observation: observation(
                HealthSignal::Healthy,
                HealthSignal::NotSampled,
                HealthSignal::Healthy,
                HealthSignal::Healthy,
            ),
            restarted_upstream: Some(RestartedUpstream {
                previous_pid: 100,
                previous_start_time: 10,
                pid: 200,
                start_time: 20,
            }),
            probe_restarted_client: false,
            detail: Some("upstream_restarted"),
        }
    }

    #[test]
    fn restarted_upstream_is_rebound_while_running_and_clears_degradation() {
        let context = LinuxServiceContext::running_for_test();
        for _ in 0..tunbridge_service::watchdog::UPSTREAM_FAILURE_THRESHOLD {
            context
                .apply_watchdog_observation(upstream_down(), no_recovery)
                .unwrap();
        }
        let commits = std::cell::Cell::new(0);
        let observation = context
            .apply_upstream_rebind(restarted_sample(), |restarted| {
                assert_eq!(restarted.pid, 200);
                Ok(|| {
                    assert!(
                        context.state.try_lock().is_err(),
                        "the commit must hold the state lock"
                    );
                    commits.set(commits.get() + 1);
                    Ok(())
                })
            })
            .unwrap();
        assert_eq!(commits.get(), 1);
        assert_eq!(observation.upstream, HealthSignal::Healthy);
        assert_eq!(
            context
                .apply_watchdog_observation(observation, no_recovery)
                .unwrap(),
            WatchdogDecision::Healthy
        );
        assert_eq!(degraded_reason(&context), None);
    }

    #[test]
    fn rebind_never_races_a_lifecycle_operation() {
        let context = LinuxServiceContext::running_for_test();
        context
            .state
            .lock()
            .unwrap()
            .begin(
                Action::Stop,
                &Caller {
                    principal_id: "uid:1000".into(),
                    session_id: 0,
                    is_admin: false,
                },
                "stop-1",
            )
            .unwrap();
        let observation = context
            .apply_upstream_rebind(restarted_sample(), |_| {
                Ok(|| -> Result<(), LifecycleFailure> {
                    panic!("a rebind must not commit while Stop is in progress")
                })
            })
            .unwrap();
        assert_eq!(observation.upstream, HealthSignal::NotSampled);
    }

    #[test]
    fn failed_rebind_keeps_the_tunnel_and_reports_unknown() {
        let context = LinuxServiceContext::running_for_test();
        let prepare_failed = context
            .apply_upstream_rebind(restarted_sample(), |_| {
                Err::<fn() -> Result<(), LifecycleFailure>, _>(LifecycleFailure {
                    code: ErrorCode::OwnedProcessMismatch,
                    safe_message: "test",
                    retryable: false,
                })
            })
            .unwrap();
        assert_eq!(prepare_failed.upstream, HealthSignal::Unknown);
        let commit_failed = context
            .apply_upstream_rebind(restarted_sample(), |_| {
                Ok(|| {
                    Err(LifecycleFailure {
                        code: ErrorCode::InternalError,
                        safe_message: "test",
                        retryable: false,
                    })
                })
            })
            .unwrap();
        assert_eq!(commit_failed.upstream, HealthSignal::Unknown);
        assert_eq!(
            context
                .apply_watchdog_observation(commit_failed, no_recovery)
                .unwrap(),
            WatchdogDecision::Hold {
                reason: WatchdogReason::RuntimeIdentityMismatch,
                consecutive: 1,
                threshold: tunbridge_service::watchdog::UNKNOWN_FAILURE_THRESHOLD,
            }
        );
        assert_eq!(context.state.lock().unwrap().phase, Phase::Running);
    }

    type NoAdoption = Option<fn() -> Result<(), LifecycleFailure>>;

    #[test]
    fn suspend_is_detected_from_the_boottime_gap() {
        let mut detector = SleepDetector::default();
        assert!(!detector.observe(1_000, 900));
        assert!(!detector.observe(1_001, 901));
        assert!(!detector.observe(1_004, 902));
        // Suspended for 30 minutes: BOOTTIME advanced, MONOTONIC one tick.
        assert!(detector.observe(2_804, 903));
        assert!(!detector.observe(2_805, 904));
        assert!(system_clocks().is_some());
    }

    #[test]
    fn restarted_client_adoption_is_rate_limited_and_keeps_degradation() {
        let context = LinuxServiceContext::running_for_test();
        for _ in 0..tunbridge_service::watchdog::UPSTREAM_FAILURE_THRESHOLD {
            context
                .apply_watchdog_observation(upstream_down(), no_recovery)
                .unwrap();
        }
        let commits = std::cell::Cell::new(0);
        let start = Instant::now();
        assert_eq!(
            context
                .apply_upstream_adoption(start, || {
                    Ok(Some(|| {
                        assert!(
                            context.state.try_lock().is_err(),
                            "the adoption commit must hold the state lock"
                        );
                        commits.set(commits.get() + 1);
                        Ok(())
                    }))
                })
                .unwrap(),
            AdoptionOutcome::Adopted
        );
        assert_eq!(commits.get(), 1);
        assert_eq!(
            context
                .apply_upstream_adoption(
                    start + Duration::from_secs(1),
                    || -> Result<NoAdoption, LifecycleFailure> {
                        panic!("a probe inside the interval must not scan")
                    }
                )
                .unwrap(),
            AdoptionOutcome::RateLimited
        );
        assert_eq!(
            context
                .apply_upstream_adoption(start + ADOPTION_PROBE_INTERVAL, || Ok(None::<
                    fn() -> Result<(), LifecycleFailure>,
                >))
                .unwrap(),
            AdoptionOutcome::NoCandidate
        );
        // Adoption never feeds the watchdog: the upstream stays degraded.
        assert_eq!(
            context
                .apply_watchdog_observation(upstream_down(), no_recovery)
                .unwrap(),
            WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
        );
        assert_eq!(
            degraded_reason(&context),
            Some(WatchdogReason::UpstreamUnavailable)
        );
    }

    #[test]
    fn restarted_client_adoption_never_races_a_lifecycle_operation() {
        let context = LinuxServiceContext::running_for_test();
        context
            .state
            .lock()
            .unwrap()
            .begin(
                Action::Stop,
                &Caller {
                    principal_id: "uid:1000".into(),
                    session_id: 0,
                    is_admin: false,
                },
                "stop-1",
            )
            .unwrap();
        assert_eq!(
            context
                .apply_upstream_adoption(Instant::now(), || {
                    Ok(Some(|| -> Result<(), LifecycleFailure> {
                        panic!("an adoption must not commit while Stop is in progress")
                    }))
                })
                .unwrap(),
            AdoptionOutcome::Busy
        );
        let failed = LinuxServiceContext::running_for_test();
        assert_eq!(
            failed
                .apply_upstream_adoption(Instant::now(), || {
                    Err::<NoAdoption, _>(LifecycleFailure {
                        code: ErrorCode::OwnedProcessMismatch,
                        safe_message: "test",
                        retryable: false,
                    })
                })
                .unwrap(),
            AdoptionOutcome::Failed
        );
        assert_eq!(failed.state.lock().unwrap().phase, Phase::Running);
    }

    #[test]
    #[ignore = "requires the installed fixed engine, root service, and an isolated network namespace"]
    fn real_system_service_runs_owned_engine_lease_observability_and_stop() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let fixture_shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fixture_worker_shutdown = Arc::clone(&fixture_shutdown);
        let keep_listener = std::thread::spawn(move || {
            while !fixture_worker_shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = listener.accept();
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let mut client = LinuxServiceClient::connect_system().unwrap();
        let profile = local_profile(
            port,
            StandardProtocol::Socks5,
            std::process::id(),
            None,
            Vec::new(),
        );
        assert!(matches!(
            client
                .send_detailed(Command::Start { profile }, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Running,
                caller_is_owner: true,
                engine_running: true,
                ..
            }
        ));
        assert!(matches!(
            client
                .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
                .unwrap(),
            ResponseData::Lease { .. }
        ));
        assert!(matches!(
            client
                .send_detailed(Command::ObserveTraffic {}, REQUEST_TIMEOUT)
                .unwrap(),
            ResponseData::TrafficSnapshot { .. }
        ));
        assert!(matches!(
            client
                .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                engine_running: false,
                ..
            }
        ));
        fixture_shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        keep_listener.join().unwrap();
    }

    #[test]
    #[ignore = "requires an external acceptance driver to terminate the owned engine"]
    fn real_system_watchdog_converges_an_exact_engine_exit() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = LinuxServiceClient::connect_system().unwrap();
        let profile = local_profile(
            port,
            StandardProtocol::Socks5,
            std::process::id(),
            None,
            Vec::new(),
        );
        assert!(matches!(
            client
                .send_detailed(Command::Start { profile }, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Running,
                ..
            }
        ));
        let _listener = listener;
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            std::thread::sleep(Duration::from_millis(250));
            if matches!(
                LinuxServiceClient::connect_system()
                    .unwrap()
                    .send_detailed(Command::Status, REQUEST_TIMEOUT)
                    .unwrap(),
                ResponseData::Status {
                    service_phase: Phase::Stopped,
                    engine_running: false,
                    ..
                }
            ) {
                break;
            }
            assert!(Instant::now() < deadline, "watchdog did not converge");
        }
    }

    fn acceptance_profile() -> StartProfileV3 {
        let protocol = match std::env::var("TUNBRIDGE_ACCEPTANCE_PROTOCOL")
            .unwrap()
            .as_str()
        {
            "socks5" => StandardProtocol::Socks5,
            "http" => StandardProtocol::Http,
            _ => panic!("invalid acceptance protocol"),
        };
        let username = std::env::var("TUNBRIDGE_ACCEPTANCE_USERNAME")
            .ok()
            .filter(|value| !value.is_empty());
        let password = std::env::var("TUNBRIDGE_ACCEPTANCE_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty());
        let bypass_process_names = std::env::var("TUNBRIDGE_ACCEPTANCE_BYPASS_PROCESS")
            .ok()
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect();
        let credentials = match (username, password) {
            (Some(username), Some(password)) => {
                Some(SecretMaterialV2::basic_auth(username, password))
            }
            (None, None) => None,
            _ => panic!("acceptance credentials must provide both username and password"),
        };
        local_profile(
            std::env::var("TUNBRIDGE_ACCEPTANCE_UPSTREAM_PORT")
                .unwrap()
                .parse()
                .unwrap(),
            protocol,
            std::env::var("TUNBRIDGE_ACCEPTANCE_UPSTREAM_PID")
                .unwrap()
                .parse()
                .unwrap(),
            credentials,
            bypass_process_names,
        )
    }

    #[test]
    #[ignore = "requires the netns acceptance driver and a controlled upstream fixture"]
    fn real_system_external_traffic_connections_lease_and_stop() {
        use std::process::{Command as ProcessCommand, Stdio};
        use tunbridge_service::protocol::ConnectionState;

        let mut client = LinuxServiceClient::connect_system().unwrap();
        assert!(matches!(
            client
                .send_detailed(
                    Command::Start {
                        profile: acceptance_profile(),
                    },
                    LIFECYCLE_TIMEOUT,
                )
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Running,
                caller_is_owner: true,
                engine_running: true,
                ..
            }
        ));

        let curl_status = ProcessCommand::new("/usr/bin/curl")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--noproxy",
                "*",
                "--max-time",
                "15",
                "--output",
                "/dev/null",
                "https://1.0.0.1/cdn-cgi/trace",
            ])
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(curl_status.success(), "transparent HTTPS request failed");

        let mut tls = ProcessCommand::new("/usr/bin/openssl");
        tls.args([
            "s_client",
            "-connect",
            "1.0.0.1:443",
            "-servername",
            "cloudflare-dns.com",
            "-quiet",
        ])
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        let mut tls = tls.spawn().unwrap();
        let _tls_input = tls.stdin.take().unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        let page = loop {
            if let Some(status) = tls.try_wait().unwrap() {
                panic!("held TLS connection exited early: {status}");
            }
            if let ResponseData::ConnectionPage { page } = client
                .send_detailed(
                    Command::ListConnections {
                        state: ConnectionState::Active,
                        offset: 0,
                        limit: tunbridge_service::protocol::MAX_CONNECTION_PAGE_SIZE,
                    },
                    REQUEST_TIMEOUT,
                )
                .unwrap()
            {
                if page.total > 0 {
                    break page;
                }
            }
            assert!(
                Instant::now() < deadline,
                "no real active connection observed"
            );
            std::thread::sleep(Duration::from_millis(250));
        };
        assert!(matches!(
            client
                .send_detailed(Command::ObserveTraffic {}, REQUEST_TIMEOUT)
                .unwrap(),
            ResponseData::TrafficSnapshot { snapshot } if snapshot.active_connections > 0
        ));
        let connection_id = page.items.first().unwrap().id.clone();
        assert!(matches!(
            client
                .send_detailed(Command::CloseConnection { connection_id }, REQUEST_TIMEOUT,)
                .unwrap(),
            ResponseData::ConnectionsClosed { closed: 1 }
        ));
        assert!(matches!(
            client
                .send_detailed(
                    Command::ListConnections {
                        state: ConnectionState::Closed,
                        offset: 0,
                        limit: tunbridge_service::protocol::MAX_CONNECTION_PAGE_SIZE,
                    },
                    REQUEST_TIMEOUT,
                )
                .unwrap(),
            ResponseData::ConnectionPage { page } if page.total > 0
        ));
        let _ = tls.wait();

        // The active-connection polling loop is intentionally bounded by the
        // per-connection request limit. Use a fresh authenticated transport
        // for the independent lease/stop phase.
        let mut client = LinuxServiceClient::connect_system().unwrap();
        let (lease_id, lease_nonce, next_seq) = match client
            .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
            .unwrap()
        {
            ResponseData::Lease {
                lease_id,
                lease_nonce,
                next_seq,
                ..
            } => (lease_id, lease_nonce, next_seq),
            other => panic!("unexpected lease response: {other:?}"),
        };
        let (lease_nonce, next_seq) = match client
            .send_detailed(
                Command::RenewLease {
                    lease_id: lease_id.clone(),
                    lease_nonce,
                    lease_seq: next_seq,
                },
                REQUEST_TIMEOUT,
            )
            .unwrap()
        {
            ResponseData::Lease {
                lease_nonce,
                next_seq,
                ..
            } => (lease_nonce, next_seq),
            other => panic!("unexpected renew response: {other:?}"),
        };
        assert!(matches!(
            client
                .send_detailed(
                    Command::ReleaseLease {
                        lease_id,
                        lease_nonce,
                        lease_seq: next_seq,
                    },
                    REQUEST_TIMEOUT,
                )
                .unwrap(),
            ResponseData::LeaseReleased { released: true }
        ));
        assert!(matches!(
            client
                .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                engine_running: false,
                ..
            }
        ));
    }

    #[test]
    #[ignore = "requires the netns acceptance driver and a second UID"]
    fn real_system_owner_holds_for_non_owner_denial() {
        let ready = PathBuf::from(std::env::var("TUNBRIDGE_ACCEPTANCE_READY").unwrap());
        let release = PathBuf::from(std::env::var("TUNBRIDGE_ACCEPTANCE_RELEASE").unwrap());
        assert!(ready.starts_with("/tmp/") && release.starts_with("/tmp/"));
        let mut client = LinuxServiceClient::connect_system().unwrap();
        client
            .send_detailed(
                Command::Start {
                    profile: acceptance_profile(),
                },
                LIFECYCLE_TIMEOUT,
            )
            .unwrap();
        fs::write(&ready, b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !release.is_file() {
            assert!(
                Instant::now() < deadline,
                "denial driver did not release owner"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        client
            .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
            .unwrap();
        fs::remove_file(ready).unwrap();
        fs::remove_file(release).unwrap();
    }

    #[test]
    #[ignore = "requires a running session owned by another UID"]
    fn real_system_non_owner_is_denied() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        assert!(matches!(
            client.status().unwrap(),
            ResponseData::Status {
                service_phase: Phase::Running,
                caller_is_owner: false,
                engine_running: true,
                ..
            }
        ));
        assert!(matches!(
            client.send_detailed(Command::Stop, LIFECYCLE_TIMEOUT),
            Err(LinuxClientError::Service {
                code: ErrorCode::NotOwner,
                retryable: false,
            })
        ));
        assert!(matches!(
            client.send_detailed(Command::ObserveTraffic {}, REQUEST_TIMEOUT),
            Err(LinuxClientError::Service {
                code: ErrorCode::NotOwner,
                retryable: false,
            })
        ));
    }

    #[test]
    #[ignore = "acceptance-only cleanup for an existing session owned by the current UID"]
    fn real_system_owner_stops_existing() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        assert!(matches!(
            client
                .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                caller_is_owner: false,
                engine_running: false,
                ..
            }
        ));
    }

    #[test]
    #[ignore = "requires the netns acceptance driver and a controlled upstream fixture"]
    fn real_system_external_recover() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        client
            .send_detailed(
                Command::Start {
                    profile: acceptance_profile(),
                },
                LIFECYCLE_TIMEOUT,
            )
            .unwrap();
        assert!(matches!(
            client
                .send_detailed(Command::Recover, LIFECYCLE_TIMEOUT)
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                engine_running: false,
                ..
            }
        ));
    }

    #[test]
    #[ignore = "requires the netns acceptance driver and a controlled upstream fixture"]
    fn real_system_starts_external_and_exits() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        assert!(matches!(
            client
                .send_detailed(
                    Command::Start {
                        profile: acceptance_profile(),
                    },
                    LIFECYCLE_TIMEOUT,
                )
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Running,
                caller_is_owner: true,
                engine_running: true,
                ..
            }
        ));
    }

    #[test]
    #[ignore = "requires the netns acceptance driver and a controlled upstream fixture"]
    fn real_system_starts_external_lease_and_exits() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        client
            .send_detailed(
                Command::Start {
                    profile: acceptance_profile(),
                },
                LIFECYCLE_TIMEOUT,
            )
            .unwrap();
        assert!(matches!(
            client
                .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
                .unwrap(),
            ResponseData::Lease { .. }
        ));
    }

    #[test]
    #[ignore = "requires an external acceptance fault after the owned record appears"]
    fn real_system_waits_for_external_watchdog_fault() {
        let mut client = LinuxServiceClient::connect_system().unwrap();
        client
            .send_detailed(
                Command::Start {
                    profile: acceptance_profile(),
                },
                LIFECYCLE_TIMEOUT,
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            std::thread::sleep(Duration::from_millis(250));
            if matches!(
                LinuxServiceClient::connect_system()
                    .unwrap()
                    .send_detailed(Command::Status, REQUEST_TIMEOUT)
                    .unwrap(),
                ResponseData::Status {
                    service_phase: Phase::Stopped,
                    engine_running: false,
                    ..
                }
            ) {
                break;
            }
            assert!(Instant::now() < deadline, "external fault did not converge");
        }
    }
}
