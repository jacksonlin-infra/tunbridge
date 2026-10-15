//! Read-only recovery observation boundary.
//!
//! A production source must collect one coherent batch using native Darwin
//! APIs. This layer never shells out and folds incomplete or malformed evidence
//! to `Unknown`, so no cleanup effect can be authorized from partial reads.

use crate::{
    darwin_state::{
        classify_dns, classify_routes, classify_tun, dns_baseline_sha256, dns_snapshot_sha256,
        route_snapshot_sha256, DnsSnapshot, InterfaceSnapshot, RouteSnapshot,
    },
    lifecycle_host::HostError,
    lifecycle_plan::{
        DeltaFact, IdentityFact, OwnedRunRecord, OwnedStage, ProcessIdentity, RecoveryFacts,
    },
};
#[cfg(target_os = "macos")]
use crate::{
    dns_store::native_dns_snapshot,
    native::{interface_snapshot, native_route_snapshot, process_identity},
};

const MAX_PROCESSES: usize = 1024;
#[cfg(target_os = "macos")]
const NATIVE_SNAPSHOT_RETRIES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverError {
    Unavailable,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub complete: bool,
    pub processes: Vec<ProcessIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DarwinObservationBatch {
    pub generation: u64,
    pub processes: ProcessSnapshot,
    pub interfaces: InterfaceSnapshot,
    pub routes: RouteSnapshot,
    pub dns: DnsSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinObservationRequest<'a> {
    pub network_service_id: &'a str,
    pub process_id: Option<u32>,
}

pub trait DarwinObservationSource {
    /// Collect all fields as one logical generation. A source must not return a
    /// mixture of cached and fresh network state under the same generation.
    fn snapshot(
        &mut self,
        request: DarwinObservationRequest<'_>,
    ) -> Result<DarwinObservationBatch, ObserverError>;
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct NativeDarwinObservationSource {
    generation: u64,
}

#[cfg(target_os = "macos")]
impl DarwinObservationSource for NativeDarwinObservationSource {
    fn snapshot(
        &mut self,
        request: DarwinObservationRequest<'_>,
    ) -> Result<DarwinObservationBatch, ObserverError> {
        for _ in 0..NATIVE_SNAPSHOT_RETRIES {
            let first = native_observation_sample(request)?;
            let second = native_observation_sample(request)?;
            if first == second {
                self.generation = self
                    .generation
                    .checked_add(1)
                    .ok_or(ObserverError::Invalid)?;
                return Ok(DarwinObservationBatch {
                    generation: self.generation,
                    ..second
                });
            }
        }
        Err(ObserverError::Incomplete)
    }
}

#[cfg(target_os = "macos")]
fn native_observation_sample(
    request: DarwinObservationRequest<'_>,
) -> Result<DarwinObservationBatch, ObserverError> {
    Ok(DarwinObservationBatch {
        generation: 0,
        processes: native_process_snapshot(request.process_id)?,
        interfaces: interface_snapshot().map_err(|_| ObserverError::Unavailable)?,
        routes: native_route_snapshot().map_err(|_| ObserverError::Unavailable)?,
        dns: native_dns_snapshot(request.network_service_id)
            .map_err(|_| ObserverError::Unavailable)?,
    })
}

#[cfg(target_os = "macos")]
fn native_process_snapshot(process_id: Option<u32>) -> Result<ProcessSnapshot, ObserverError> {
    let Some(process_id) = process_id else {
        return Ok(ProcessSnapshot {
            complete: true,
            processes: Vec::new(),
        });
    };
    if process_id <= 1 || process_id > i32::MAX as u32 {
        return Err(ObserverError::Invalid);
    }
    match process_identity(process_id) {
        Ok(process) => Ok(ProcessSnapshot {
            complete: true,
            processes: vec![process],
        }),
        Err(_) => {
            let status = unsafe { libc::kill(process_id as i32, 0) };
            let error = std::io::Error::last_os_error().raw_os_error();
            if status == -1 && error == Some(libc::ESRCH) {
                Ok(ProcessSnapshot {
                    complete: true,
                    processes: Vec::new(),
                })
            } else {
                Err(ObserverError::Unavailable)
            }
        }
    }
}

pub struct RecoveryObserver<S> {
    source: S,
    last_generation: u64,
}

impl<S> RecoveryObserver<S>
where
    S: DarwinObservationSource,
{
    pub fn new(source: S) -> Self {
        Self {
            source,
            last_generation: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.source
    }

    pub fn observe(&mut self, record: &OwnedRunRecord) -> Result<RecoveryFacts, HostError> {
        record.validate().map_err(|_| HostError::InvalidInput)?;
        let batch = match self.source.snapshot(DarwinObservationRequest {
            network_service_id: &record.baseline.dns.network_service_id,
            process_id: record.engine.as_ref().map(|engine| engine.pid),
        }) {
            Ok(batch) if batch.generation > self.last_generation => batch,
            _ => return Ok(unavailable_facts(record)),
        };
        self.last_generation = batch.generation;

        Ok(RecoveryFacts {
            engine: record
                .engine
                .as_ref()
                .map_or(IdentityFact::Absent, |engine| {
                    classify_process(engine, &batch.processes)
                }),
            tun: record.tun.as_ref().map_or(IdentityFact::Absent, |tun| {
                classify_tun(tun, &batch.interfaces).unwrap_or(IdentityFact::Unknown)
            }),
            routes: classify_recorded_routes(record, &batch.routes),
            dns: classify_recorded_dns(record, &batch.dns),
        })
    }
}

pub fn classify_process(expected: &ProcessIdentity, snapshot: &ProcessSnapshot) -> IdentityFact {
    if !snapshot.complete || snapshot.processes.len() > MAX_PROCESSES {
        return IdentityFact::Unknown;
    }
    let mut matching_pid = snapshot
        .processes
        .iter()
        .filter(|process| process.pid == expected.pid);
    match (matching_pid.next(), matching_pid.next()) {
        (Some(actual), None) if actual == expected => IdentityFact::Exact,
        (Some(_), None) => IdentityFact::Mismatch,
        (None, None) => IdentityFact::Absent,
        _ => IdentityFact::Unknown,
    }
}

fn classify_recorded_routes(record: &OwnedRunRecord, snapshot: &RouteSnapshot) -> DeltaFact {
    if record.stage < OwnedStage::RoutesPlanned {
        return baseline_route_fact(&record.baseline.routes_sha256, snapshot);
    }
    classify_routes(
        &record.baseline.routes_sha256,
        &record.route_deltas,
        snapshot,
    )
    .unwrap_or(DeltaFact::Unknown)
}

fn baseline_route_fact(baseline_sha256: &str, snapshot: &RouteSnapshot) -> DeltaFact {
    if !snapshot.complete {
        return DeltaFact::Unknown;
    }
    match route_snapshot_sha256(snapshot) {
        Ok(current) if current == baseline_sha256 => DeltaFact::Restored,
        Ok(_) => DeltaFact::Drifted,
        Err(_) => DeltaFact::Unknown,
    }
}

fn classify_recorded_dns(record: &OwnedRunRecord, snapshot: &DnsSnapshot) -> DeltaFact {
    let Some(planned) = record.planned_dns_sha256.as_deref() else {
        return baseline_dns_fact(record, snapshot);
    };
    classify_dns(&record.baseline.dns, planned, snapshot).unwrap_or(DeltaFact::Unknown)
}

fn baseline_dns_fact(record: &OwnedRunRecord, snapshot: &DnsSnapshot) -> DeltaFact {
    if !snapshot.complete {
        return DeltaFact::Unknown;
    }
    if snapshot.network_service_id != record.baseline.dns.network_service_id {
        return DeltaFact::Drifted;
    }
    match (
        dns_baseline_sha256(&record.baseline.dns),
        dns_snapshot_sha256(snapshot),
    ) {
        (Ok(baseline), Ok(current)) if baseline == current => DeltaFact::Restored,
        (Ok(_), Ok(_)) => DeltaFact::Drifted,
        _ => DeltaFact::Unknown,
    }
}

fn unavailable_facts(record: &OwnedRunRecord) -> RecoveryFacts {
    RecoveryFacts {
        engine: if record.engine.is_some() {
            IdentityFact::Unknown
        } else {
            IdentityFact::Absent
        },
        tun: if record.tun.is_some() {
            IdentityFact::Unknown
        } else {
            IdentityFact::Absent
        },
        routes: DeltaFact::Unknown,
        dns: DeltaFact::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        darwin_state::{DarwinInterface, DnsSnapshot},
        lifecycle_plan::{
            DnsBaseline, DnsConfigurationMode, NetworkBaseline, OwnedStage, RouteDelta, TunIdentity,
        },
    };
    use std::net::Ipv4Addr;

    struct FixtureSource {
        batch: Result<DarwinObservationBatch, ObserverError>,
        calls: usize,
        requested_service: Option<String>,
        requested_process: Option<Option<u32>>,
    }

    impl DarwinObservationSource for FixtureSource {
        fn snapshot(
            &mut self,
            request: DarwinObservationRequest<'_>,
        ) -> Result<DarwinObservationBatch, ObserverError> {
            self.calls += 1;
            self.requested_service = Some(request.network_service_id.into());
            self.requested_process = Some(request.process_id);
            self.batch.clone()
        }
    }

    fn process(pid: u32, marker: char) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: marker.to_string().repeat(64),
        }
    }

    fn route(destination: Ipv4Addr, prefix: u8) -> RouteDelta {
        RouteDelta {
            destination: destination.into(),
            prefix_length: prefix,
            gateway: None,
            interface_index: 17,
            interface_scoped: false,
        }
    }

    fn baseline_dns() -> DnsBaseline {
        DnsBaseline {
            network_service_id: "wifi-service-id".into(),
            mode: DnsConfigurationMode::Manual,
            servers: vec!["192.0.2.53".parse().unwrap()],
            search_domains: vec!["example.test".into()],
        }
    }

    fn baseline_route_snapshot() -> RouteSnapshot {
        RouteSnapshot {
            complete: true,
            routes: vec![RouteDelta {
                destination: "192.0.2.0".parse().unwrap(),
                prefix_length: 24,
                gateway: None,
                interface_index: 9,
                interface_scoped: false,
            }],
        }
    }

    fn record(stage: OwnedStage) -> OwnedRunRecord {
        let routes = vec![
            route(Ipv4Addr::UNSPECIFIED, 1),
            route(Ipv4Addr::new(128, 0, 0, 0), 1),
        ];
        let dns = baseline_dns();
        OwnedRunRecord {
            schema_version: 2,
            run_id: "a".repeat(32),
            stage,
            owner_principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            owner_session_id: 42,
            upstream: process(600, 'b'),
            engine: (stage >= OwnedStage::EnginePrepared).then(|| process(700, 'c')),
            tun: (stage >= OwnedStage::TunVerified).then(|| TunIdentity {
                interface_name: "utun7".into(),
                interface_index: 17,
                engine_pid: 700,
            }),
            baseline: NetworkBaseline {
                default_interface_index: 9,
                default_gateway: "192.0.2.1".parse().unwrap(),
                routes_sha256: route_snapshot_sha256(&baseline_route_snapshot()).unwrap(),
                preexisting_utuns: Vec::new(),
                dns,
            },
            route_deltas: if stage >= OwnedStage::RoutesPlanned {
                routes
            } else {
                Vec::new()
            },
            planned_dns_sha256: (stage >= OwnedStage::DnsPlanned).then(|| {
                dns_snapshot_sha256(&DnsSnapshot {
                    complete: true,
                    network_service_id: "wifi-service-id".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: vec!["198.18.0.1".parse().unwrap()],
                    search_domains: Vec::new(),
                })
                .unwrap()
            }),
            controller_secret: "d".repeat(64),
        }
    }

    fn batch(record: &OwnedRunRecord) -> DarwinObservationBatch {
        DarwinObservationBatch {
            generation: 1,
            processes: ProcessSnapshot {
                complete: true,
                processes: record.engine.clone().into_iter().collect(),
            },
            interfaces: InterfaceSnapshot {
                complete: true,
                interfaces: record
                    .tun
                    .as_ref()
                    .map(|tun| DarwinInterface {
                        name: tun.interface_name.clone(),
                        index: tun.interface_index,
                        owner_pid: Some(tun.engine_pid),
                    })
                    .into_iter()
                    .collect(),
            },
            routes: if record.route_deltas.is_empty() {
                baseline_route_snapshot()
            } else {
                RouteSnapshot {
                    complete: true,
                    routes: record.route_deltas.clone(),
                }
            },
            dns: if record.planned_dns_sha256.is_some() {
                DnsSnapshot {
                    complete: true,
                    network_service_id: "wifi-service-id".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: vec!["198.18.0.1".parse().unwrap()],
                    search_domains: Vec::new(),
                }
            } else {
                DnsSnapshot {
                    complete: true,
                    network_service_id: "wifi-service-id".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: baseline_dns().servers,
                    search_domains: baseline_dns().search_domains,
                }
            },
        }
    }

    #[test]
    fn one_coherent_batch_yields_exact_running_recovery_facts() {
        let record = record(OwnedStage::Running);
        let source = FixtureSource {
            batch: Ok(batch(&record)),
            calls: 0,
            requested_service: None,
            requested_process: None,
        };
        let mut observer = RecoveryObserver::new(source);
        assert_eq!(
            observer.observe(&record).unwrap(),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::AppliedExact,
                dns: DeltaFact::AppliedExact,
            }
        );
        let source = observer.into_inner();
        assert_eq!(source.calls, 1);
        assert_eq!(source.requested_service.as_deref(), Some("wifi-service-id"));
        assert_eq!(source.requested_process, Some(Some(700)));
    }

    #[test]
    fn prepared_record_requires_exact_baselines_but_no_process_or_tun() {
        let record = record(OwnedStage::Prepared);
        let mut observer = RecoveryObserver::new(FixtureSource {
            batch: Ok(batch(&record)),
            calls: 0,
            requested_service: None,
            requested_process: None,
        });
        assert_eq!(
            observer.observe(&record).unwrap(),
            RecoveryFacts {
                engine: IdentityFact::Absent,
                tun: IdentityFact::Absent,
                routes: DeltaFact::Restored,
                dns: DeltaFact::Restored,
            }
        );
    }

    #[test]
    fn source_failure_or_zero_generation_authorizes_no_cleanup() {
        let record = record(OwnedStage::Running);
        for batch in [
            Err(ObserverError::Unavailable),
            Ok(DarwinObservationBatch {
                generation: 0,
                ..batch(&record)
            }),
        ] {
            let mut observer = RecoveryObserver::new(FixtureSource {
                batch,
                calls: 0,
                requested_service: None,
                requested_process: None,
            });
            assert_eq!(
                observer.observe(&record).unwrap(),
                RecoveryFacts {
                    engine: IdentityFact::Unknown,
                    tun: IdentityFact::Unknown,
                    routes: DeltaFact::Unknown,
                    dns: DeltaFact::Unknown,
                }
            );
        }
    }

    #[test]
    fn replayed_generation_is_rejected_as_stale_evidence() {
        let record = record(OwnedStage::Running);
        let mut observer = RecoveryObserver::new(FixtureSource {
            batch: Ok(batch(&record)),
            calls: 0,
            requested_service: None,
            requested_process: None,
        });
        assert_eq!(
            observer.observe(&record).unwrap().engine,
            IdentityFact::Exact
        );
        assert_eq!(
            observer.observe(&record).unwrap(),
            RecoveryFacts {
                engine: IdentityFact::Unknown,
                tun: IdentityFact::Unknown,
                routes: DeltaFact::Unknown,
                dns: DeltaFact::Unknown,
            }
        );
    }

    #[test]
    fn pid_reuse_and_duplicate_pid_evidence_fail_closed() {
        let expected = process(700, 'c');
        assert_eq!(
            classify_process(
                &expected,
                &ProcessSnapshot {
                    complete: true,
                    processes: vec![process(700, 'e')],
                }
            ),
            IdentityFact::Mismatch
        );
        assert_eq!(
            classify_process(
                &expected,
                &ProcessSnapshot {
                    complete: true,
                    processes: vec![expected.clone(), expected.clone()],
                }
            ),
            IdentityFact::Unknown
        );
    }

    #[test]
    fn one_incomplete_dimension_does_not_poison_exact_independent_evidence() {
        let record = record(OwnedStage::Running);
        let mut observed = batch(&record);
        observed.routes.complete = false;
        let mut observer = RecoveryObserver::new(FixtureSource {
            batch: Ok(observed),
            calls: 0,
            requested_service: None,
            requested_process: None,
        });
        assert_eq!(
            observer.observe(&record).unwrap(),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::Unknown,
                dns: DeltaFact::AppliedExact,
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_source_targets_one_process_and_advances_only_stable_generations() {
        let service_id = crate::dns_store::configured_network_service_ids()
            .unwrap()
            .into_iter()
            .find(|service_id| crate::dns_store::native_dns_snapshot(service_id).is_ok())
            .expect("at least one supported configured network service");
        let request = DarwinObservationRequest {
            network_service_id: &service_id,
            process_id: Some(std::process::id()),
        };
        let mut source = NativeDarwinObservationSource::default();
        let first = source.snapshot(request).unwrap();
        let second = source.snapshot(request).unwrap();
        assert_eq!(first.generation, 1);
        assert_eq!(second.generation, 2);
        assert_eq!(first.processes.processes.len(), 1);
        assert_eq!(first.processes.processes[0].pid, std::process::id());
        assert!(first.interfaces.complete);
        assert!(first.routes.complete);
        assert!(first.dns.complete);
        assert_eq!(first.dns.network_service_id, service_id);
    }
}
