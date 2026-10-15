use crate::lifecycle_plan::{
    plan_recovery, DnsBaseline, NetworkBaseline, OwnedRunRecord, OwnedStage, ProcessIdentity,
    RecoveryEffect, RecoveryFacts, RouteDelta, TunIdentity,
};
use std::net::IpAddr;
use tunbridge_service::{protocol::ActiveStartProfile, state::Caller};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    InvalidInput,
    JournalUnavailable,
    BackendUnavailable,
    RecoveryRequired,
}

pub trait OwnedJournal {
    fn load(&self) -> Result<Option<OwnedRunRecord>, HostError>;
    fn persist(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn clear_exact(&mut self, run_id: &str) -> Result<(), HostError>;
}

pub trait LifecycleBackend {
    /// Runtime health of the running session's local upstream. Backends that
    /// cannot observe it, and remote upstreams, report NotSampled.
    fn sample_upstream(&mut self) -> tunbridge_service::watchdog::HealthSignal {
        tunbridge_service::watchdog::HealthSignal::NotSampled
    }
    /// Whether the recorded engine is still the process that was started.
    /// Backends that cannot tell return None.
    fn engine_alive(&mut self, _engine: &ProcessIdentity) -> Option<bool> {
        None
    }
    /// Installs or replaces the traffic lock, letting `allowed` destinations
    /// through. Backends without one succeed without effect.
    fn install_traffic_lock(&mut self, _allowed: &[(IpAddr, u8)]) -> Result<(), HostError> {
        Ok(())
    }
    fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
        Ok(())
    }
    /// Whether a lock is in force. An unreadable lock counts as present so
    /// nothing reports traffic as free when it may not be.
    fn traffic_lock_present(&mut self) -> bool {
        false
    }
    fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError>;
    fn verify_upstream(
        &mut self,
        profile: &ActiveStartProfile,
        caller: &Caller,
    ) -> Result<ProcessIdentity, HostError>;
    fn spawn_suspended_engine(
        &mut self,
        profile: &ActiveStartProfile,
        controller_secret: &str,
        run_id: &str,
    ) -> Result<ProcessIdentity, HostError>;
    fn terminate_suspended_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError>;
    fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError>;
    fn verify_tun(
        &mut self,
        engine: &ProcessIdentity,
        controller_secret: &str,
    ) -> Result<TunIdentity, HostError>;
    fn plan_routes(
        &mut self,
        baseline: &NetworkBaseline,
        upstream: &ProcessIdentity,
        tun: &TunIdentity,
    ) -> Result<Vec<RouteDelta>, HostError>;
    fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError>;
    fn plan_dns(&mut self, baseline: &DnsBaseline, tun: &TunIdentity) -> Result<String, HostError>;
    fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError>;
    fn verify_transparent_path(&mut self, record: &OwnedRunRecord) -> Result<(), HostError>;
    fn observe_recovery(&mut self, record: &OwnedRunRecord) -> Result<RecoveryFacts, HostError>;
    fn apply_recovery_effect(
        &mut self,
        record: &OwnedRunRecord,
        effect: RecoveryEffect,
    ) -> Result<(), HostError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartMaterial {
    pub run_id: String,
    pub controller_secret: String,
}

pub struct MacosLifecycleHost<B, J> {
    backend: B,
    journal: J,
}

impl<B, J> MacosLifecycleHost<B, J>
where
    B: LifecycleBackend,
    J: OwnedJournal,
{
    pub fn sample_upstream(&mut self) -> tunbridge_service::watchdog::HealthSignal {
        self.backend.sample_upstream()
    }

    /// Liveness of the running session's engine. Sessions that are not fully
    /// running are not sampled.
    pub fn sample_engine(&mut self) -> tunbridge_service::watchdog::HealthSignal {
        use tunbridge_service::watchdog::HealthSignal;
        let Ok(Some(record)) = self.journal.load() else {
            return HealthSignal::NotSampled;
        };
        let Some(engine) = record.engine.as_ref() else {
            return HealthSignal::NotSampled;
        };
        if record.stage != OwnedStage::Running {
            return HealthSignal::NotSampled;
        }
        match self.backend.engine_alive(engine) {
            Some(true) => HealthSignal::Healthy,
            Some(false) => HealthSignal::Unhealthy,
            None => HealthSignal::NotSampled,
        }
    }

    /// Installs or refreshes the traffic lock for the current session. The
    /// session's own physical routes (pinned upstream, profile bypasses) stay
    /// usable; everything else is closed.
    pub fn install_traffic_lock(&mut self) -> Result<(), HostError> {
        let allowed: Vec<(IpAddr, u8)> = self
            .journal
            .load()?
            .map(|record| {
                record
                    .route_deltas
                    .iter()
                    .filter(|route| {
                        route.gateway.is_some()
                            && !route.interface_scoped
                            && route.prefix_length > 0
                    })
                    .map(|route| (route.destination, route.prefix_length))
                    .collect()
            })
            .unwrap_or_default();
        self.backend.install_traffic_lock(&allowed)
    }

    pub fn remove_traffic_lock(&mut self) -> Result<(), HostError> {
        self.backend.remove_traffic_lock()
    }

    pub fn traffic_lock_present(&mut self) -> bool {
        self.backend.traffic_lock_present()
    }

    /// The owner of a journaled session that is still exactly in place, so a
    /// restarted helper keeps serving it instead of tearing it down.
    pub fn adopt_running(&mut self) -> Result<Option<(String, u32)>, HostError> {
        let Some(record) = self.journal.load()? else {
            return Ok(None);
        };
        if record.stage != OwnedStage::Running
            || self.backend.verify_transparent_path(&record).is_err()
        {
            return Ok(None);
        }
        Ok(Some((
            record.owner_principal_id.clone(),
            record.owner_session_id,
        )))
    }

    pub fn new(backend: B, journal: J) -> Self {
        Self { backend, journal }
    }

    pub fn into_parts(self) -> (B, J) {
        (self.backend, self.journal)
    }

    pub fn owned_record(&self) -> Result<Option<OwnedRunRecord>, HostError> {
        self.journal.load()
    }

    pub fn start(
        &mut self,
        profile: &ActiveStartProfile,
        caller: &Caller,
        material: StartMaterial,
    ) -> Result<(), HostError> {
        profile.validate().map_err(|_| HostError::InvalidInput)?;
        if caller.is_admin || caller.session_id == 0 || !caller.principal_id.starts_with("macos:") {
            return Err(HostError::InvalidInput);
        }
        if self.journal.load()?.is_some() {
            return Err(HostError::RecoveryRequired);
        }

        let baseline = self
            .backend
            .capture_network_baseline()
            .map_err(|error| self.rollback_after(error))?;
        let upstream = self
            .backend
            .verify_upstream(profile, caller)
            .map_err(|error| self.rollback_after(error))?;
        let mut record = OwnedRunRecord {
            schema_version: 2,
            run_id: material.run_id,
            stage: OwnedStage::Prepared,
            owner_principal_id: caller.principal_id.clone(),
            owner_session_id: caller.session_id,
            upstream,
            engine: None,
            tun: None,
            baseline,
            route_deltas: Vec::new(),
            planned_dns_sha256: None,
            controller_secret: material.controller_secret,
        };
        record.validate().map_err(|_| HostError::InvalidInput)?;
        self.journal.persist(&record)?;

        let engine = match self.backend.spawn_suspended_engine(
            profile,
            &record.controller_secret,
            &record.run_id,
        ) {
            Ok(engine) => engine,
            Err(error) => return Err(self.rollback_after(error)),
        };
        record.engine = Some(engine.clone());
        record.stage = OwnedStage::EnginePrepared;
        if record.validate().is_err() {
            return self.abort_unjournaled_suspended(
                &engine,
                &record.run_id,
                HostError::InvalidInput,
            );
        }
        if let Err(error) = self.journal.persist(&record) {
            return self.abort_unjournaled_suspended(&engine, &record.run_id, error);
        }

        self.backend
            .resume_engine(&engine)
            .map_err(|error| self.rollback_after(error))?;
        record.stage = OwnedStage::EngineStarted;
        self.persist_or_rollback(&record)?;

        let tun = self
            .backend
            .verify_tun(&engine, &record.controller_secret)
            .map_err(|error| self.rollback_after(error))?;
        record.tun = Some(tun.clone());
        record.stage = OwnedStage::TunVerified;
        self.persist_or_rollback(&record)?;

        record.route_deltas = self
            .backend
            .plan_routes(&record.baseline, &record.upstream, &tun)
            .map_err(|error| self.rollback_after(error))?;
        record.stage = OwnedStage::RoutesPlanned;
        self.persist_or_rollback(&record)?;
        self.backend
            .apply_routes(&record.route_deltas)
            .map_err(|error| self.rollback_after(error))?;
        record.stage = OwnedStage::RoutesApplied;
        self.persist_or_rollback(&record)?;

        record.planned_dns_sha256 = Some(
            self.backend
                .plan_dns(&record.baseline.dns, &tun)
                .map_err(|error| self.rollback_after(error))?,
        );
        record.stage = OwnedStage::DnsPlanned;
        self.persist_or_rollback(&record)?;
        self.backend
            .apply_dns(
                record
                    .planned_dns_sha256
                    .as_deref()
                    .ok_or(HostError::InvalidInput)?,
            )
            .map_err(|error| self.rollback_after(error))?;
        record.stage = OwnedStage::DnsApplied;
        self.persist_or_rollback(&record)?;

        self.backend
            .verify_transparent_path(&record)
            .map_err(|error| self.rollback_after(error))?;
        record.stage = OwnedStage::Running;
        self.persist_or_rollback(&record)
    }

    pub fn recover(&mut self) -> Result<(), HostError> {
        let Some(record) = self.journal.load()? else {
            return Ok(());
        };
        self.recover_record(&record)
    }

    fn recover_record(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        let facts = self.backend.observe_recovery(record)?;
        let plan = plan_recovery(record, facts).map_err(|_| HostError::RecoveryRequired)?;
        for effect in plan.effects {
            if effect == RecoveryEffect::ClearOwnedRecord {
                self.journal.clear_exact(&record.run_id)?;
            } else {
                self.backend.apply_recovery_effect(record, effect)?;
            }
        }
        Ok(())
    }

    fn persist_or_rollback(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        record.validate().map_err(|_| HostError::InvalidInput)?;
        match self.journal.persist(record) {
            Ok(()) => Ok(()),
            Err(original) => match self.recover_record(record) {
                Ok(()) => Err(original),
                Err(_) => Err(HostError::RecoveryRequired),
            },
        }
    }

    fn abort_unjournaled_suspended(
        &mut self,
        engine: &ProcessIdentity,
        run_id: &str,
        original: HostError,
    ) -> Result<(), HostError> {
        if self.backend.terminate_suspended_engine(engine).is_err()
            || self.journal.clear_exact(run_id).is_err()
        {
            Err(HostError::RecoveryRequired)
        } else {
            Err(original)
        }
    }

    fn rollback_after(&mut self, original: HostError) -> HostError {
        match self.recover() {
            Ok(()) => original,
            Err(_) => HostError::RecoveryRequired,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle_plan::{DeltaFact, DnsConfigurationMode, IdentityFact};
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Debug, Default)]
    struct MemoryJournal {
        record: Option<OwnedRunRecord>,
        writes: usize,
        fail_write: Option<usize>,
    }

    impl OwnedJournal for MemoryJournal {
        fn load(&self) -> Result<Option<OwnedRunRecord>, HostError> {
            Ok(self.record.clone())
        }

        fn persist(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
            self.writes += 1;
            if self.fail_write == Some(self.writes) {
                return Err(HostError::JournalUnavailable);
            }
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailurePoint {
        Resume,
        PlanRoutes,
        ApplyRoutes,
        ApplyDns,
        VerifyPath,
    }

    #[derive(Debug, Default)]
    struct MemoryBackend {
        failure: Option<FailurePoint>,
        engine: bool,
        suspended: bool,
        tun: bool,
        routes: bool,
        dns: bool,
        effects: Vec<&'static str>,
        verified_caller: Option<Caller>,
        spawn_run_id: Option<String>,
    }

    impl LifecycleBackend for MemoryBackend {
        fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError> {
            Ok(NetworkBaseline {
                default_interface_index: 9,
                default_gateway: ip(1),
                routes_sha256: "a".repeat(64),
                preexisting_utuns: Vec::new(),
                dns: DnsBaseline {
                    network_service_id: "fixture-service".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: vec![ip(53)],
                    search_domains: vec!["example.test".into()],
                },
            })
        }

        fn verify_upstream(
            &mut self,
            _profile: &ActiveStartProfile,
            caller: &Caller,
        ) -> Result<ProcessIdentity, HostError> {
            self.verified_caller = Some(caller.clone());
            Ok(process(600, 'b'))
        }

        fn spawn_suspended_engine(
            &mut self,
            _profile: &ActiveStartProfile,
            _controller_secret: &str,
            run_id: &str,
        ) -> Result<ProcessIdentity, HostError> {
            self.spawn_run_id = Some(run_id.to_owned());
            self.engine = true;
            self.suspended = true;
            self.effects.push("spawn_suspended");
            Ok(process(700, 'c'))
        }

        fn terminate_suspended_engine(
            &mut self,
            _engine: &ProcessIdentity,
        ) -> Result<(), HostError> {
            self.engine = false;
            self.suspended = false;
            self.effects.push("abort_suspended");
            Ok(())
        }

        fn resume_engine(&mut self, _engine: &ProcessIdentity) -> Result<(), HostError> {
            if self.failure == Some(FailurePoint::Resume) {
                return Err(HostError::BackendUnavailable);
            }
            self.suspended = false;
            self.effects.push("resume");
            Ok(())
        }

        fn verify_tun(
            &mut self,
            engine: &ProcessIdentity,
            _controller_secret: &str,
        ) -> Result<TunIdentity, HostError> {
            self.tun = true;
            Ok(TunIdentity {
                interface_name: "utun7".into(),
                interface_index: 17,
                engine_pid: engine.pid,
            })
        }

        fn plan_routes(
            &mut self,
            _baseline: &NetworkBaseline,
            _upstream: &ProcessIdentity,
            tun: &TunIdentity,
        ) -> Result<Vec<RouteDelta>, HostError> {
            if self.failure == Some(FailurePoint::PlanRoutes) {
                return Err(HostError::BackendUnavailable);
            }
            Ok(vec![RouteDelta {
                destination: Ipv4Addr::UNSPECIFIED.into(),
                prefix_length: 1,
                gateway: None,
                interface_index: tun.interface_index,
                interface_scoped: false,
            }])
        }

        fn apply_routes(&mut self, _routes: &[RouteDelta]) -> Result<(), HostError> {
            if self.failure == Some(FailurePoint::ApplyRoutes) {
                return Err(HostError::BackendUnavailable);
            }
            self.routes = true;
            self.effects.push("apply_routes");
            Ok(())
        }

        fn plan_dns(
            &mut self,
            _baseline: &DnsBaseline,
            _tun: &TunIdentity,
        ) -> Result<String, HostError> {
            Ok("d".repeat(64))
        }

        fn apply_dns(&mut self, _planned_dns_sha256: &str) -> Result<(), HostError> {
            if self.failure == Some(FailurePoint::ApplyDns) {
                return Err(HostError::BackendUnavailable);
            }
            self.dns = true;
            self.effects.push("apply_dns");
            Ok(())
        }

        fn verify_transparent_path(&mut self, _record: &OwnedRunRecord) -> Result<(), HostError> {
            if self.failure == Some(FailurePoint::VerifyPath) {
                Err(HostError::BackendUnavailable)
            } else {
                Ok(())
            }
        }

        fn observe_recovery(
            &mut self,
            record: &OwnedRunRecord,
        ) -> Result<RecoveryFacts, HostError> {
            Ok(RecoveryFacts {
                engine: if self.engine {
                    IdentityFact::Exact
                } else {
                    IdentityFact::Absent
                },
                tun: if record.tun.is_some() && self.tun {
                    IdentityFact::Exact
                } else {
                    IdentityFact::Absent
                },
                routes: if self.routes {
                    DeltaFact::AppliedExact
                } else {
                    DeltaFact::Restored
                },
                dns: if self.dns {
                    DeltaFact::AppliedExact
                } else {
                    DeltaFact::Restored
                },
            })
        }

        fn apply_recovery_effect(
            &mut self,
            _record: &OwnedRunRecord,
            effect: RecoveryEffect,
        ) -> Result<(), HostError> {
            match effect {
                RecoveryEffect::RestoreExactDnsBaseline => {
                    self.dns = false;
                    self.effects.push("restore_dns");
                }
                RecoveryEffect::RemoveExactOwnedRoutes => {
                    self.routes = false;
                    self.effects.push("remove_routes");
                }
                RecoveryEffect::TerminateExactEngine => {
                    self.engine = false;
                    self.suspended = false;
                    self.effects.push("terminate_engine");
                }
                RecoveryEffect::RemoveExactEngineConfig => {
                    self.effects.push("remove_engine_config");
                }
                RecoveryEffect::WaitForExactTunRemoval => {
                    self.tun = false;
                    self.effects.push("wait_tun");
                }
                RecoveryEffect::ClearOwnedRecord => unreachable!(),
            }
            Ok(())
        }
    }

    fn ip(last: u8) -> IpAddr {
        Ipv4Addr::new(192, 0, 2, last).into()
    }

    fn process(pid: u32, hash: char) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: hash.to_string().repeat(64),
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

    fn caller() -> Caller {
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

    macro_rules! delegate_backend_methods {
        () => {
            fn capture_network_baseline(&mut self) -> Result<NetworkBaseline, HostError> {
                self.0.capture_network_baseline()
            }
            fn verify_upstream(
                &mut self,
                profile: &ActiveStartProfile,
                caller: &Caller,
            ) -> Result<ProcessIdentity, HostError> {
                self.0.verify_upstream(profile, caller)
            }
            fn spawn_suspended_engine(
                &mut self,
                profile: &ActiveStartProfile,
                controller_secret: &str,
                run_id: &str,
            ) -> Result<ProcessIdentity, HostError> {
                self.0
                    .spawn_suspended_engine(profile, controller_secret, run_id)
            }
            fn terminate_suspended_engine(
                &mut self,
                engine: &ProcessIdentity,
            ) -> Result<(), HostError> {
                self.0.terminate_suspended_engine(engine)
            }
            fn resume_engine(&mut self, engine: &ProcessIdentity) -> Result<(), HostError> {
                self.0.resume_engine(engine)
            }
            fn verify_tun(
                &mut self,
                engine: &ProcessIdentity,
                controller_secret: &str,
            ) -> Result<TunIdentity, HostError> {
                self.0.verify_tun(engine, controller_secret)
            }
            fn plan_routes(
                &mut self,
                baseline: &NetworkBaseline,
                upstream: &ProcessIdentity,
                tun: &TunIdentity,
            ) -> Result<Vec<RouteDelta>, HostError> {
                self.0.plan_routes(baseline, upstream, tun)
            }
            fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), HostError> {
                self.0.apply_routes(routes)
            }
            fn plan_dns(
                &mut self,
                baseline: &DnsBaseline,
                tun: &TunIdentity,
            ) -> Result<String, HostError> {
                self.0.plan_dns(baseline, tun)
            }
            fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), HostError> {
                self.0.apply_dns(planned_dns_sha256)
            }
            fn verify_transparent_path(
                &mut self,
                record: &OwnedRunRecord,
            ) -> Result<(), HostError> {
                self.0.verify_transparent_path(record)
            }
            fn apply_recovery_effect(
                &mut self,
                record: &OwnedRunRecord,
                effect: RecoveryEffect,
            ) -> Result<(), HostError> {
                self.0.apply_recovery_effect(record, effect)
            }
        };
    }

    #[test]
    fn happy_path_commits_running_without_recovery_effects() {
        let mut host = MacosLifecycleHost::new(MemoryBackend::default(), MemoryJournal::default());
        host.start(&profile(), &caller(), material()).unwrap();
        let (backend, journal) = host.into_parts();
        assert!(backend.engine && backend.tun && backend.routes && backend.dns);
        assert_eq!(backend.verified_caller, Some(caller()));
        assert_eq!(backend.spawn_run_id, Some(material().run_id));
        assert_eq!(journal.record.unwrap().stage, OwnedStage::Running);
        assert_eq!(
            backend.effects,
            vec!["spawn_suspended", "resume", "apply_routes", "apply_dns"]
        );
    }

    #[test]
    fn every_post_journal_failure_recovers_only_exact_effects() {
        for failure in [
            FailurePoint::Resume,
            FailurePoint::PlanRoutes,
            FailurePoint::ApplyRoutes,
            FailurePoint::ApplyDns,
            FailurePoint::VerifyPath,
        ] {
            let backend = MemoryBackend {
                failure: Some(failure),
                ..MemoryBackend::default()
            };
            let mut host = MacosLifecycleHost::new(backend, MemoryJournal::default());
            assert_eq!(
                host.start(&profile(), &caller(), material()),
                Err(HostError::BackendUnavailable)
            );
            let (backend, journal) = host.into_parts();
            assert!(!backend.engine);
            assert!(!backend.tun);
            assert!(!backend.routes);
            assert!(!backend.dns);
            assert!(journal.record.is_none());
        }
    }

    #[test]
    fn suspended_engine_is_exactly_aborted_if_identity_cannot_be_journaled() {
        let journal = MemoryJournal {
            fail_write: Some(2),
            ..MemoryJournal::default()
        };
        let mut host = MacosLifecycleHost::new(MemoryBackend::default(), journal);
        assert_eq!(
            host.start(&profile(), &caller(), material()),
            Err(HostError::JournalUnavailable)
        );
        let (backend, journal) = host.into_parts();
        assert!(!backend.engine);
        assert_eq!(backend.effects, vec!["spawn_suspended", "abort_suspended"]);
        assert!(journal.record.is_none());
    }

    #[test]
    fn every_stage_commit_failure_uses_the_newest_in_memory_identity_to_recover() {
        for failed_write in 3..=9 {
            let journal = MemoryJournal {
                fail_write: Some(failed_write),
                ..MemoryJournal::default()
            };
            let mut host = MacosLifecycleHost::new(MemoryBackend::default(), journal);
            assert_eq!(
                host.start(&profile(), &caller(), material()),
                Err(HostError::JournalUnavailable),
                "failed write {failed_write}"
            );
            let (backend, journal) = host.into_parts();
            assert!(!backend.engine, "failed write {failed_write}");
            assert!(!backend.tun, "failed write {failed_write}");
            assert!(!backend.routes, "failed write {failed_write}");
            assert!(!backend.dns, "failed write {failed_write}");
            assert!(journal.record.is_none(), "failed write {failed_write}");
        }
    }

    #[test]
    fn unknown_observation_preserves_journal_and_produces_no_effects() {
        struct UnknownBackend(MemoryBackend);
        impl LifecycleBackend for UnknownBackend {
            fn observe_recovery(
                &mut self,
                _record: &OwnedRunRecord,
            ) -> Result<RecoveryFacts, HostError> {
                Ok(RecoveryFacts {
                    engine: IdentityFact::Unknown,
                    tun: IdentityFact::Unknown,
                    routes: DeltaFact::Unknown,
                    dns: DeltaFact::Unknown,
                })
            }

            delegate_backend_methods!();
        }

        let mut running =
            MacosLifecycleHost::new(MemoryBackend::default(), MemoryJournal::default());
        running.start(&profile(), &caller(), material()).unwrap();
        let (backend, journal) = running.into_parts();
        let mut host = MacosLifecycleHost::new(UnknownBackend(backend), journal);
        assert_eq!(host.recover(), Err(HostError::RecoveryRequired));
        let (backend, journal) = host.into_parts();
        assert!(journal.record.is_some());
        assert!(!backend.0.effects.contains(&"restore_dns"));
        assert!(!backend.0.effects.contains(&"remove_routes"));
        assert!(!backend.0.effects.contains(&"terminate_engine"));
    }
}
