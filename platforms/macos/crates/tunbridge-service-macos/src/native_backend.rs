//! Full feature-isolated native lifecycle backend composition.

use crate::{
    baseline::native_network_baseline,
    controller::TcpControllerTransport,
    controller_owner::NativeControllerOwnerVerifier,
    engine_process::{remove_system_config, terminate_system_engine},
    journal::MacosOwnedJournal,
    lifecycle_host::{HostError, LifecycleBackend, MacosLifecycleHost},
    lifecycle_plan::{
        DeltaFact, DnsBaseline, IdentityFact, NetworkBaseline, OwnedRunRecord, ProcessIdentity,
        RecoveryEffect, RecoveryFacts, RouteDelta, TunIdentity,
    },
    native::{interface_snapshot, process_identity},
    native_engine::NativeEngineLifecycle,
    native_network_effects::NativeNetworkEffects,
    native_start::verify_native_upstream,
    native_tun::{NativeTunError, NativeTunVerifier, SystemInterfaceInventorySource},
    observer::{NativeDarwinObservationSource, RecoveryObserver},
    upstream_owner::{UpstreamWatch, VerifiedUpstream},
    upstream_route_probe::discover_upstream_bypass_cidrs,
};
use std::{
    net::IpAddr,
    thread,
    time::{Duration, Instant},
};
use tunbridge_core::remote::{preflight_pinned_tcp, resolve_endpoint_system};
use tunbridge_service::{
    protocol::{StartProfileV3, StartUpstreamV3},
    state::Caller,
    watchdog::HealthSignal,
};

const TUN_REMOVAL_TIMEOUT: Duration = Duration::from_secs(3);
const TUN_REMOVAL_POLL: Duration = Duration::from_millis(20);
const TUN_READY_TIMEOUT: Duration = Duration::from_secs(15);
const TUN_READY_POLL: Duration = Duration::from_millis(100);

fn verify_tun_until_ready<F, E, S>(
    mut verify: F,
    mut elapsed: E,
    mut sleep: S,
) -> Result<TunIdentity, NativeTunError>
where
    F: FnMut() -> Result<TunIdentity, NativeTunError>,
    E: FnMut() -> Duration,
    S: FnMut(Duration),
{
    loop {
        match verify() {
            Ok(tun) => return Ok(tun),
            Err(error) => {
                let remaining = TUN_READY_TIMEOUT.saturating_sub(elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                sleep(TUN_READY_POLL.min(remaining));
            }
        }
    }
}

pub trait NativeLifecycleRuntime {
    fn sample_upstream(&mut self, _watch: &UpstreamWatch) -> HealthSignal {
        HealthSignal::NotSampled
    }
    fn engine_alive(&mut self, _engine: &ProcessIdentity) -> Option<bool> {
        None
    }
    fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError>;
    fn verify_upstream(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
    ) -> Result<(VerifiedUpstream, Option<IpAddr>), HostError>;
    #[allow(clippy::too_many_arguments)]
    fn spawn_suspended(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
        baseline: &NetworkBaseline,
        expected_upstream: &VerifiedUpstream,
        pinned_remote: Option<IpAddr>,
        run_id: &str,
        controller_secret: &str,
    ) -> Result<ProcessIdentity, HostError>;
    fn abort_suspended(&mut self, engine: &ProcessIdentity) -> Result<(), HostError>;
    fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError>;
    fn configured_device(&self) -> Option<&str>;
    fn verify_tun(
        &mut self,
        baseline: &NetworkBaseline,
        engine: &ProcessIdentity,
        controller_secret: &str,
        configured_device: &str,
    ) -> Result<TunIdentity, HostError>;
    fn plan_routes(
        &mut self,
        baseline: &NetworkBaseline,
        tun: &TunIdentity,
        bypass_cidrs: &[String],
    ) -> Result<Vec<RouteDelta>, HostError>;
    fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError>;
    fn plan_dns(&mut self, baseline: &DnsBaseline, tun: &TunIdentity) -> Result<String, HostError>;
    fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError>;
    fn verify_structural_path(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn observe_recovery(&mut self, record: &OwnedRunRecord) -> Result<RecoveryFacts, HostError>;
    fn restore_dns(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn remove_routes(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn terminate_engine(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn remove_engine_config(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn wait_for_tun_removal(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
}

pub struct NativeLifecycleBackend<R: NativeLifecycleRuntime> {
    runtime: R,
    baseline: Option<NetworkBaseline>,
    caller: Option<Caller>,
    upstream: Option<VerifiedUpstream>,
    upstream_watch: Option<UpstreamWatch>,
    pinned_remote: Option<IpAddr>,
    bypass_cidrs: Option<Vec<String>>,
}

impl<R: NativeLifecycleRuntime> NativeLifecycleBackend<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            baseline: None,
            caller: None,
            upstream: None,
            upstream_watch: None,
            pinned_remote: None,
            bypass_cidrs: None,
        }
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }
}

impl<R: NativeLifecycleRuntime> LifecycleBackend for NativeLifecycleBackend<R> {
    fn sample_upstream(&mut self) -> HealthSignal {
        match &self.upstream_watch {
            Some(watch) => self.runtime.sample_upstream(watch),
            None => HealthSignal::NotSampled,
        }
    }

    fn engine_alive(&mut self, engine: &ProcessIdentity) -> Option<bool> {
        self.runtime.engine_alive(engine)
    }

    fn install_traffic_lock(&mut self, allowed: &[(IpAddr, u8)]) -> Result<(), HostError> {
        crate::traffic_lock::install(crate::engine_process::ENGINE_GID, allowed).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("traffic-lock install error={error:?}"));
            let _ = error;
            HostError::BackendUnavailable
        })
    }

    fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
        crate::traffic_lock::remove().map_err(|_| HostError::BackendUnavailable)
    }

    fn traffic_lock_present(&mut self) -> bool {
        crate::traffic_lock::present().unwrap_or(true)
    }

    fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError> {
        self.baseline = None;
        self.caller = None;
        self.upstream = None;
        self.upstream_watch = None;
        self.pinned_remote = None;
        self.bypass_cidrs = None;
        let baseline = self.runtime.capture_network_baseline()?;
        self.baseline = Some(baseline.clone());
        Ok(baseline)
    }

    fn verify_upstream(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
    ) -> Result<ProcessIdentity, HostError> {
        if self.upstream.is_some() || self.caller.is_some() {
            return Err(HostError::RecoveryRequired);
        }
        let (upstream, pinned_remote) = self.runtime.verify_upstream(profile, caller)?;
        let identity = upstream.identity.clone();
        let mut bypass_cidrs = profile.traffic_bypass_cidrs.clone();
        bypass_cidrs.extend(upstream.auto_bypass_cidrs.iter().cloned());
        bypass_cidrs.sort();
        bypass_cidrs.dedup();
        self.upstream_watch = profile.legacy_local_profile().and_then(|legacy| {
            let caller_uid = crate::native_start::authenticated_caller_uid(caller).ok()?;
            UpstreamWatch::for_profile(&legacy, &upstream, caller_uid)
        });
        self.caller = Some(caller.clone());
        self.upstream = Some(upstream);
        self.pinned_remote = pinned_remote;
        self.bypass_cidrs = Some(bypass_cidrs);
        Ok(identity)
    }

    fn spawn_suspended_engine(
        &mut self,
        profile: &StartProfileV3,
        controller_secret: &str,
        run_id: &str,
    ) -> Result<ProcessIdentity, HostError> {
        let baseline = self.baseline.as_ref().ok_or(HostError::InvalidInput)?;
        let caller = self.caller.as_ref().ok_or(HostError::InvalidInput)?;
        let upstream = self.upstream.as_ref().ok_or(HostError::InvalidInput)?;
        self.runtime.spawn_suspended(
            profile,
            caller,
            baseline,
            upstream,
            self.pinned_remote,
            run_id,
            controller_secret,
        )
    }

    fn terminate_suspended_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
        self.runtime.abort_suspended(engine)
    }

    fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
        self.runtime.resume_engine(engine)
    }

    fn verify_tun(
        &mut self,
        engine: &ProcessIdentity,
        controller_secret: &str,
    ) -> Result<TunIdentity, HostError> {
        let baseline = self.baseline.as_ref().ok_or(HostError::InvalidInput)?;
        let device = self
            .runtime
            .configured_device()
            .ok_or(HostError::InvalidInput)?
            .to_owned();
        self.runtime
            .verify_tun(baseline, engine, controller_secret, &device)
    }

    fn plan_routes(
        &mut self,
        baseline: &NetworkBaseline,
        upstream: &ProcessIdentity,
        tun: &TunIdentity,
    ) -> Result<Vec<RouteDelta>, HostError> {
        if self.baseline.as_ref() != Some(baseline)
            || self.upstream.as_ref().map(|value| &value.identity) != Some(upstream)
        {
            return Err(HostError::InvalidInput);
        }
        self.runtime
            .plan_routes(baseline, tun, self.bypass_cidrs.as_deref().unwrap_or(&[]))
    }

    fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError> {
        self.runtime.apply_routes(routes)
    }

    fn plan_dns(&mut self, baseline: &DnsBaseline, tun: &TunIdentity) -> Result<String, HostError> {
        if self.baseline.as_ref().map(|value| &value.dns) != Some(baseline) {
            return Err(HostError::InvalidInput);
        }
        self.runtime.plan_dns(baseline, tun)
    }

    fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError> {
        self.runtime.apply_dns(planned_dns_sha256)
    }

    fn verify_transparent_path(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        self.runtime.verify_structural_path(record)
    }

    fn observe_recovery(&mut self, record: &OwnedRunRecord) -> Result<RecoveryFacts, HostError> {
        self.runtime.observe_recovery(record)
    }

    fn apply_recovery_effect(
        &mut self,
        record: &OwnedRunRecord,
        effect: RecoveryEffect,
    ) -> Result<(), HostError> {
        match effect {
            RecoveryEffect::RestoreExactDnsBaseline => self.runtime.restore_dns(record),
            RecoveryEffect::RemoveExactOwnedRoutes => self.runtime.remove_routes(record),
            RecoveryEffect::TerminateExactEngine => self.runtime.terminate_engine(record),
            RecoveryEffect::RemoveExactEngineConfig => self.runtime.remove_engine_config(record),
            RecoveryEffect::WaitForExactTunRemoval => self.runtime.wait_for_tun_removal(record),
            RecoveryEffect::ClearOwnedRecord => Err(HostError::InvalidInput),
        }
    }
}

type SystemTunVerifier = NativeTunVerifier<
    TcpControllerTransport,
    NativeControllerOwnerVerifier,
    SystemInterfaceInventorySource,
>;

pub struct SystemNativeLifecycleRuntime {
    engine: NativeEngineLifecycle,
    tun: SystemTunVerifier,
    network: NativeNetworkEffects,
    observer: RecoveryObserver<NativeDarwinObservationSource>,
}

pub type SystemNativeLifecycleHost =
    MacosLifecycleHost<NativeLifecycleBackend<SystemNativeLifecycleRuntime>, MacosOwnedJournal>;

pub fn open_system_native_lifecycle() -> Result<SystemNativeLifecycleHost, HostError> {
    let journal = MacosOwnedJournal::open_system()?;
    let backend = NativeLifecycleBackend::new(SystemNativeLifecycleRuntime::default());
    Ok(MacosLifecycleHost::new(backend, journal))
}

impl Default for SystemNativeLifecycleRuntime {
    fn default() -> Self {
        Self {
            engine: NativeEngineLifecycle::default(),
            tun: NativeTunVerifier::default(),
            network: NativeNetworkEffects::default(),
            observer: RecoveryObserver::new(NativeDarwinObservationSource::default()),
        }
    }
}

impl NativeLifecycleRuntime for SystemNativeLifecycleRuntime {
    fn sample_upstream(&mut self, watch: &UpstreamWatch) -> HealthSignal {
        crate::upstream_owner::sample_upstream_watch(watch)
    }

    fn engine_alive(&mut self, engine: &ProcessIdentity) -> Option<bool> {
        let pid = libc::pid_t::try_from(engine.pid).ok()?;
        // Reap the engine if it is our child and has exited; a zombie would
        // otherwise still report credentials. An adopted engine is not our
        // child and waitpid fails harmlessly.
        let mut status = 0;
        let alive = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != pid
            && crate::native::process_credentials(engine.pid)
                .is_ok_and(|credentials| credentials.start_time_ns == engine.start_time_ns);
        if !alive {
            // Free the slot, or the restart refuses to spawn a replacement.
            self.engine.forget_exited(engine);
        }
        Some(alive)
    }

    fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError> {
        self.network.preflight_split_routes().map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!(
                "native-stage=preflight-routes error={error:?}"
            ));
            #[cfg(not(feature = "macos-development-bootstrap"))]
            let _ = error;
            HostError::BackendUnavailable
        })?;
        native_network_baseline().map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!(
                "native-stage=capture-baseline error={error:?}"
            ));
            HostError::BackendUnavailable
        })
    }

    fn verify_upstream(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
    ) -> Result<(VerifiedUpstream, Option<IpAddr>), HostError> {
        if let Some(legacy) = profile.legacy_local_profile() {
            return verify_native_upstream(&legacy, caller)
                .and_then(|(_, mut upstream)| {
                    upstream.auto_bypass_cidrs = discover_upstream_bypass_cidrs(&legacy, &upstream)
                        .map_err(|_| crate::native_start::NativeStartError::UpstreamUnavailable)?;
                    #[cfg(feature = "macos-development-bootstrap")]
                    crate::xpc_listener::debug_log(&format!(
                        "native-stage=upstream-route-probe bypass-count={}",
                        upstream.auto_bypass_cidrs.len()
                    ));
                    Ok((upstream, None))
                })
                .map_err(|error| {
                    #[cfg(feature = "macos-development-bootstrap")]
                    crate::xpc_listener::debug_log(&format!(
                        "native-stage=verify-upstream error={error:?}"
                    ));
                    HostError::BackendUnavailable
                });
        }
        let StartUpstreamV3::RemoteServer { endpoint, .. } = &profile.upstream else {
            return Err(HostError::InvalidInput);
        };
        let pinned = resolve_endpoint_system(endpoint)
            .map_err(|_| HostError::BackendUnavailable)?
            .into_iter()
            .find(IpAddr::is_ipv4)
            .ok_or(HostError::BackendUnavailable)?;
        preflight_pinned_tcp(pinned, endpoint.port, Duration::from_secs(4))
            .map_err(|_| HostError::BackendUnavailable)?;
        let identity =
            process_identity(std::process::id()).map_err(|_| HostError::BackendUnavailable)?;
        Ok((
            VerifiedUpstream {
                identity,
                process_name: "tunbridge-helper-macos".into(),
                auto_bypass_cidrs: vec![format!("{pinned}/32")],
            },
            Some(pinned),
        ))
    }

    fn spawn_suspended(
        &mut self,
        profile: &StartProfileV3,
        caller: &Caller,
        baseline: &NetworkBaseline,
        expected_upstream: &VerifiedUpstream,
        pinned_remote: Option<IpAddr>,
        run_id: &str,
        controller_secret: &str,
    ) -> Result<ProcessIdentity, HostError> {
        self.engine
            .spawn_verified_v3(
                profile,
                caller,
                baseline,
                expected_upstream,
                pinned_remote,
                run_id,
                controller_secret,
            )
            .map_err(|error| {
                #[cfg(feature = "macos-development-bootstrap")]
                crate::xpc_listener::debug_log(&format!(
                    "native-stage=spawn-engine error={error:?}"
                ));
                HostError::BackendUnavailable
            })
    }

    fn abort_suspended(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
        self.engine.abort_suspended(engine).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=abort-engine error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
        self.engine.resume(engine).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=resume-engine error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn configured_device(&self) -> Option<&str> {
        self.engine.configured_device()
    }

    fn verify_tun(
        &mut self,
        baseline: &NetworkBaseline,
        engine: &ProcessIdentity,
        controller_secret: &str,
        configured_device: &str,
    ) -> Result<TunIdentity, HostError> {
        let started = Instant::now();
        verify_tun_until_ready(
            || {
                self.tun
                    .verify(baseline, engine, controller_secret, configured_device)
            },
            || started.elapsed(),
            thread::sleep,
        )
        .map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=verify-tun error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn plan_routes(
        &mut self,
        baseline: &NetworkBaseline,
        tun: &TunIdentity,
        bypass_cidrs: &[String],
    ) -> Result<Vec<RouteDelta>, HostError> {
        self.network
            .plan_routes_with_bypass(baseline, tun, bypass_cidrs)
            .map_err(|error| {
                #[cfg(feature = "macos-development-bootstrap")]
                crate::xpc_listener::debug_log(&format!(
                    "native-stage=plan-routes error={error:?}"
                ));
                HostError::BackendUnavailable
            })
    }

    fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError> {
        self.network.apply_routes(routes).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=apply-routes error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn plan_dns(&mut self, baseline: &DnsBaseline, tun: &TunIdentity) -> Result<String, HostError> {
        self.network.plan_dns(baseline, tun).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=plan-dns error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError> {
        self.network.apply_dns(planned_dns_sha256).map_err(|error| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log(&format!("native-stage=apply-dns error={error:?}"));
            HostError::BackendUnavailable
        })
    }

    fn verify_structural_path(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        let facts = self.observe_recovery(record)?;
        if facts.engine == IdentityFact::Exact
            && facts.tun == IdentityFact::Exact
            && facts.routes == DeltaFact::AppliedExact
            && facts.dns == DeltaFact::AppliedExact
        {
            Ok(())
        } else {
            Err(HostError::BackendUnavailable)
        }
    }

    fn observe_recovery(&mut self, record: &OwnedRunRecord) -> Result<RecoveryFacts, HostError> {
        let mut facts = self.observer.observe(record)?;
        if facts.engine == IdentityFact::Exact && facts.tun == IdentityFact::Unknown {
            let engine = record.engine.as_ref().ok_or(HostError::InvalidInput)?;
            let expected_tun = record.tun.as_ref().ok_or(HostError::InvalidInput)?;
            let verified = self
                .tun
                .verify_recorded(
                    &record.baseline,
                    engine,
                    &record.controller_secret,
                    expected_tun,
                )
                .map_err(|error| {
                    #[cfg(feature = "macos-development-bootstrap")]
                    crate::xpc_listener::debug_log(&format!(
                        "native-stage=recovery-tun error={error:?}"
                    ));
                    #[cfg(not(feature = "macos-development-bootstrap"))]
                    let _ = error;
                    HostError::BackendUnavailable
                })?;
            facts.tun = if verified == *expected_tun {
                IdentityFact::Exact
            } else {
                IdentityFact::Mismatch
            };
        }
        Ok(facts)
    }

    fn restore_dns(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        self.network
            .restore_dns(
                &record.baseline.dns,
                record
                    .planned_dns_sha256
                    .as_deref()
                    .ok_or(HostError::InvalidInput)?,
            )
            .map_err(|_| HostError::BackendUnavailable)
    }

    fn remove_routes(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        self.network
            .remove_routes(&record.route_deltas)
            .map_err(|_| HostError::BackendUnavailable)
    }

    fn terminate_engine(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        let engine = record.engine.as_ref().ok_or(HostError::InvalidInput)?;
        if self.engine.terminate_running(engine).is_ok() {
            Ok(())
        } else {
            terminate_system_engine(engine).map_err(|_| HostError::BackendUnavailable)
        }
    }

    fn remove_engine_config(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        remove_system_config(&record.run_id).map_err(|_| HostError::BackendUnavailable)
    }

    fn wait_for_tun_removal(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        let expected = record.tun.as_ref().ok_or(HostError::InvalidInput)?;
        let deadline = Instant::now() + TUN_REMOVAL_TIMEOUT;
        loop {
            let snapshot = interface_snapshot().map_err(|_| HostError::BackendUnavailable)?;
            match crate::darwin_state::classify_tun(expected, &snapshot)
                .map_err(|_| HostError::BackendUnavailable)?
            {
                IdentityFact::Absent => return Ok(()),
                IdentityFact::Exact if Instant::now() < deadline => {
                    thread::sleep(TUN_REMOVAL_POLL);
                }
                _ => return Err(HostError::RecoveryRequired),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lifecycle_host::{MacosLifecycleHost, OwnedJournal, StartMaterial},
        lifecycle_plan::{DnsConfigurationMode, InterfaceIdentity, OwnedStage},
    };
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr},
    };

    #[derive(Default)]
    struct MemoryJournal {
        record: Option<OwnedRunRecord>,
    }

    impl OwnedJournal for MemoryJournal {
        fn load(&self) -> Result<Option<OwnedRunRecord>, HostError> {
            Ok(self.record.clone())
        }

        fn persist(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
            self.record = Some(record.clone());
            Ok(())
        }

        fn clear_exact(&mut self, run_id: &str) -> Result<(), HostError> {
            if self.record.as_ref().map(|record| record.run_id.as_str()) != Some(run_id) {
                return Err(HostError::RecoveryRequired);
            }
            self.record = None;
            Ok(())
        }
    }

    #[test]
    fn tun_readiness_retries_transient_verification_failures() {
        let outcomes = RefCell::new(VecDeque::from([
            Err(NativeTunError::ControllerUnavailable),
            Err(NativeTunError::InterfaceUnavailable),
            Err(NativeTunError::AttributionUnavailable),
            Ok(tun()),
        ]));
        let elapsed = Cell::new(Duration::ZERO);
        let sleeps = RefCell::new(Vec::new());

        let verified = verify_tun_until_ready(
            || outcomes.borrow_mut().pop_front().unwrap(),
            || elapsed.get(),
            |duration| {
                sleeps.borrow_mut().push(duration);
                elapsed.set(elapsed.get() + duration);
            },
        )
        .unwrap();

        assert_eq!(verified, tun());
        assert_eq!(*sleeps.borrow(), vec![TUN_READY_POLL; 3]);
        assert_eq!(elapsed.get(), TUN_READY_POLL * 3);
    }

    #[test]
    fn tun_readiness_stops_at_the_fail_closed_deadline() {
        let attempts = Cell::new(0_u32);
        let elapsed = Cell::new(Duration::ZERO);

        let result = verify_tun_until_ready(
            || {
                attempts.set(attempts.get() + 1);
                Err(NativeTunError::ControllerUnavailable)
            },
            || elapsed.get(),
            |duration| elapsed.set(elapsed.get() + duration),
        );

        assert_eq!(result, Err(NativeTunError::ControllerUnavailable));
        assert_eq!(elapsed.get(), TUN_READY_TIMEOUT);
        assert_eq!(attempts.get(), 151);
    }

    #[derive(Default)]
    struct FakeRuntime {
        effects: Vec<&'static str>,
        engine_live: bool,
        tun_live: bool,
        routes_live: bool,
        dns_live: bool,
        fail_structural: bool,
    }

    impl NativeLifecycleRuntime for FakeRuntime {
        fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError> {
            self.effects.push("capture_baseline");
            Ok(baseline())
        }

        fn verify_upstream(
            &mut self,
            profile: &StartProfileV3,
            caller: &Caller,
        ) -> Result<(VerifiedUpstream, Option<IpAddr>), HostError> {
            assert_eq!(
                profile.legacy_local_profile().unwrap().upstream_process_id,
                600
            );
            assert_eq!(caller, &test_caller());
            self.effects.push("verify_upstream");
            Ok((
                VerifiedUpstream {
                    identity: process(600, 'b'),
                    process_name: "proxy".into(),
                    auto_bypass_cidrs: vec!["198.51.100.8/32".into()],
                },
                None,
            ))
        }

        fn spawn_suspended(
            &mut self,
            _profile: &StartProfileV3,
            caller: &Caller,
            baseline: &NetworkBaseline,
            expected_upstream: &VerifiedUpstream,
            pinned_remote: Option<IpAddr>,
            run_id: &str,
            controller_secret: &str,
        ) -> Result<ProcessIdentity, HostError> {
            assert_eq!(caller, &test_caller());
            assert_eq!(baseline, &self::baseline());
            assert_eq!(expected_upstream.identity, process(600, 'b'));
            assert_eq!(pinned_remote, None);
            assert_eq!(run_id, "e".repeat(32));
            assert_eq!(controller_secret, "f".repeat(64));
            self.engine_live = true;
            self.effects.push("spawn_suspended");
            Ok(process(700, 'c'))
        }

        fn abort_suspended(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
            assert_eq!(engine, &process(700, 'c'));
            self.engine_live = false;
            self.effects.push("abort_suspended");
            Ok(())
        }

        fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
            assert_eq!(engine, &process(700, 'c'));
            self.effects.push("resume");
            Ok(())
        }

        fn configured_device(&self) -> Option<&str> {
            Some("utun7")
        }

        fn verify_tun(
            &mut self,
            baseline: &NetworkBaseline,
            engine: &ProcessIdentity,
            controller_secret: &str,
            configured_device: &str,
        ) -> Result<TunIdentity, HostError> {
            assert_eq!(baseline, &self::baseline());
            assert_eq!(engine, &process(700, 'c'));
            assert_eq!(controller_secret, "f".repeat(64));
            assert_eq!(configured_device, "utun7");
            self.tun_live = true;
            self.effects.push("verify_tun");
            Ok(tun())
        }

        fn plan_routes(
            &mut self,
            baseline: &NetworkBaseline,
            tun: &TunIdentity,
            bypass_cidrs: &[String],
        ) -> Result<Vec<RouteDelta>, HostError> {
            assert_eq!(baseline, &self::baseline());
            assert_eq!(tun, &self::tun());
            assert_eq!(bypass_cidrs, &["198.51.100.8/32"]);
            self.effects.push("plan_routes");
            Ok(routes())
        }

        fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError> {
            assert_eq!(routes, self::routes());
            self.routes_live = true;
            self.effects.push("apply_routes");
            Ok(())
        }

        fn plan_dns(
            &mut self,
            baseline: &DnsBaseline,
            tun: &TunIdentity,
        ) -> Result<String, HostError> {
            assert_eq!(baseline, &self::baseline().dns);
            assert_eq!(tun, &self::tun());
            self.effects.push("plan_dns");
            Ok("d".repeat(64))
        }

        fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError> {
            assert_eq!(planned_dns_sha256, "d".repeat(64));
            self.dns_live = true;
            self.effects.push("apply_dns");
            Ok(())
        }

        fn verify_structural_path(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
            assert_eq!(record.stage, OwnedStage::DnsApplied);
            self.effects.push("verify_structural");
            if self.fail_structural {
                Err(HostError::BackendUnavailable)
            } else {
                Ok(())
            }
        }

        fn observe_recovery(
            &mut self,
            record: &OwnedRunRecord,
        ) -> Result<RecoveryFacts, HostError> {
            self.effects.push("observe");
            Ok(RecoveryFacts {
                engine: if self.engine_live {
                    IdentityFact::Exact
                } else {
                    IdentityFact::Absent
                },
                tun: if self.tun_live && record.tun.is_some() {
                    IdentityFact::Exact
                } else {
                    IdentityFact::Absent
                },
                routes: if self.routes_live {
                    DeltaFact::AppliedExact
                } else {
                    DeltaFact::Restored
                },
                dns: if self.dns_live {
                    DeltaFact::AppliedExact
                } else {
                    DeltaFact::Restored
                },
            })
        }

        fn restore_dns(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            self.dns_live = false;
            self.effects.push("restore_dns");
            Ok(())
        }

        fn remove_routes(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            self.routes_live = false;
            self.effects.push("remove_routes");
            Ok(())
        }

        fn terminate_engine(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            self.engine_live = false;
            self.effects.push("terminate_engine");
            Ok(())
        }

        fn remove_engine_config(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            self.effects.push("remove_config");
            Ok(())
        }

        fn wait_for_tun_removal(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            self.tun_live = false;
            self.effects.push("wait_tun");
            Ok(())
        }
    }

    fn ip(last: u8) -> IpAddr {
        Ipv4Addr::new(192, 0, 2, last).into()
    }

    fn process(pid: u32, hash: char) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: pid as u64 * 100,
            executable_file_id: pid as u64 * 10,
            executable_sha256: hash.to_string().repeat(64),
        }
    }

    fn baseline() -> NetworkBaseline {
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: ip(1),
            routes_sha256: "a".repeat(64),
            preexisting_utuns: vec![InterfaceIdentity {
                interface_name: "utun3".into(),
                interface_index: 13,
            }],
            dns: DnsBaseline {
                network_service_id: "fixture-service".into(),
                mode: DnsConfigurationMode::Manual,
                servers: vec![ip(53)],
                search_domains: vec!["example.test".into()],
            },
        }
    }

    fn tun() -> TunIdentity {
        TunIdentity {
            interface_name: "utun7".into(),
            interface_index: 17,
            engine_pid: 700,
        }
    }

    fn routes() -> Vec<RouteDelta> {
        vec![
            RouteDelta {
                destination: Ipv4Addr::UNSPECIFIED.into(),
                prefix_length: 1,
                gateway: None,
                interface_index: 17,
                interface_scoped: false,
            },
            RouteDelta {
                destination: Ipv4Addr::new(128, 0, 0, 0).into(),
                prefix_length: 1,
                gateway: None,
                interface_index: 17,
                interface_scoped: false,
            },
        ]
    }

    fn profile() -> StartProfileV3 {
        StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
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

    fn test_caller() -> Caller {
        Caller {
            principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            session_id: 42,
            is_admin: false,
        }
    }

    fn material() -> StartMaterial {
        StartMaterial {
            run_id: "e".repeat(32),
            controller_secret: "f".repeat(64),
        }
    }

    #[test]
    fn full_backend_composition_starts_and_recovers_in_exact_reverse_order() {
        let backend = NativeLifecycleBackend::new(FakeRuntime::default());
        let mut host = MacosLifecycleHost::new(backend, MemoryJournal::default());

        host.start(&profile(), &test_caller(), material()).unwrap();
        host.recover().unwrap();

        let (backend, journal) = host.into_parts();
        assert!(journal.record.is_none());
        assert_eq!(
            backend.runtime().effects,
            vec![
                "capture_baseline",
                "verify_upstream",
                "spawn_suspended",
                "resume",
                "verify_tun",
                "plan_routes",
                "apply_routes",
                "plan_dns",
                "apply_dns",
                "verify_structural",
                "observe",
                "restore_dns",
                "remove_routes",
                "terminate_engine",
                "remove_config",
                "wait_tun",
            ]
        );
    }

    #[test]
    fn structural_failure_rolls_back_all_exact_effects_and_preserves_original_error() {
        let runtime = FakeRuntime {
            fail_structural: true,
            ..FakeRuntime::default()
        };
        let backend = NativeLifecycleBackend::new(runtime);
        let mut host = MacosLifecycleHost::new(backend, MemoryJournal::default());

        assert_eq!(
            host.start(&profile(), &test_caller(), material()),
            Err(HostError::BackendUnavailable)
        );
        let (backend, journal) = host.into_parts();
        assert!(journal.record.is_none());
        assert!(!backend.runtime().engine_live);
        assert!(!backend.runtime().tun_live);
        assert!(!backend.runtime().routes_live);
        assert!(!backend.runtime().dns_live);
    }

    #[test]
    fn recovered_backend_can_start_a_new_generation() {
        let backend = NativeLifecycleBackend::new(FakeRuntime::default());
        let mut host = MacosLifecycleHost::new(backend, MemoryJournal::default());

        host.start(&profile(), &test_caller(), material()).unwrap();
        host.recover().unwrap();
        host.start(&profile(), &test_caller(), material()).unwrap();

        let (backend, journal) = host.into_parts();
        assert_eq!(journal.record.unwrap().stage, OwnedStage::Running);
        assert!(backend.runtime().engine_live);
        assert!(backend.runtime().tun_live);
        assert!(backend.runtime().routes_live);
        assert!(backend.runtime().dns_live);
    }

    #[test]
    fn backend_rejects_out_of_order_and_stale_start_material() {
        let mut backend = NativeLifecycleBackend::new(FakeRuntime::default());
        assert_eq!(
            backend.verify_tun(&process(700, 'c'), &"f".repeat(64)),
            Err(HostError::InvalidInput)
        );
        backend.capture_network_baseline().unwrap();
        backend.verify_upstream(&profile(), &test_caller()).unwrap();
        assert_eq!(
            backend.verify_upstream(&profile(), &test_caller()),
            Err(HostError::RecoveryRequired)
        );
        backend.capture_network_baseline().unwrap();
        assert_eq!(
            backend.spawn_suspended_engine(&profile(), &"f".repeat(64), &"e".repeat(32)),
            Err(HostError::InvalidInput)
        );
    }
}
