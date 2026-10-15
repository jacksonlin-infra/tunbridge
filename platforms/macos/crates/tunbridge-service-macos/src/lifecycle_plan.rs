use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use zeroize::Zeroize;

const MAX_ROUTES: usize = 32;
const MAX_DNS_SERVERS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 16;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_BASELINE_UTUNS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedStage {
    Prepared,
    EnginePrepared,
    EngineStarted,
    TunVerified,
    RoutesPlanned,
    RoutesApplied,
    DnsPlanned,
    DnsApplied,
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ns: u64,
    pub executable_file_id: u64,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunIdentity {
    pub interface_name: String,
    pub interface_index: u32,
    pub engine_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfaceIdentity {
    pub interface_name: String,
    pub interface_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteDelta {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface_index: u32,
    /// RTF_IFSCOPE route: only sockets bound to `interface_index`
    /// (IP_BOUND_IF) resolve through it; unscoped traffic never does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interface_scoped: bool,
}

impl RouteDelta {
    /// Whether both routes occupy the same kernel routing key. A scoped route
    /// is keyed by its interface as well, so it never shadows the unscoped
    /// system route for the same destination.
    pub fn same_key(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.prefix_length == other.prefix_length
            && self.interface_scoped == other.interface_scoped
            && (!self.interface_scoped || self.interface_index == other.interface_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DnsConfigurationMode {
    Automatic,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsBaseline {
    pub network_service_id: String,
    pub mode: DnsConfigurationMode,
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkBaseline {
    pub default_interface_index: u32,
    pub default_gateway: IpAddr,
    pub routes_sha256: String,
    pub preexisting_utuns: Vec<InterfaceIdentity>,
    pub dns: DnsBaseline,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedRunRecord {
    pub schema_version: u16,
    pub run_id: String,
    pub stage: OwnedStage,
    pub owner_principal_id: String,
    pub owner_session_id: u32,
    pub upstream: ProcessIdentity,
    pub engine: Option<ProcessIdentity>,
    pub tun: Option<TunIdentity>,
    pub baseline: NetworkBaseline,
    pub route_deltas: Vec<RouteDelta>,
    pub planned_dns_sha256: Option<String>,
    pub controller_secret: String,
}

impl fmt::Debug for OwnedRunRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRunRecord")
            .field("schema_version", &self.schema_version)
            .field("run_id", &self.run_id)
            .field("stage", &self.stage)
            .field("owner_principal_id", &self.owner_principal_id)
            .field("owner_session_id", &self.owner_session_id)
            .field("upstream", &self.upstream)
            .field("engine", &self.engine)
            .field("tun", &self.tun)
            .field("baseline", &self.baseline)
            .field("route_deltas", &self.route_deltas)
            .field("planned_dns_sha256", &self.planned_dns_sha256)
            .field("controller_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OwnedRunRecord {
    fn drop(&mut self) {
        self.controller_secret.zeroize();
    }
}

impl OwnedRunRecord {
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.schema_version != 2
            || !valid_hex(&self.run_id, 32)
            || !valid_principal(&self.owner_principal_id)
            || self.owner_session_id == 0
            || !valid_process(&self.upstream)
            || !valid_hex(&self.controller_secret, 64)
            || !valid_baseline(&self.baseline)
            || self.route_deltas.len() > MAX_ROUTES
            || !self.route_deltas.iter().all(valid_route)
            || self
                .engine
                .as_ref()
                .is_some_and(|value| !valid_process(value))
            || self.tun.as_ref().is_some_and(|value| !valid_tun(value))
            || self
                .planned_dns_sha256
                .as_ref()
                .is_some_and(|value| !valid_hex(value, 64))
        {
            return Err(PlanError::InvalidRecord);
        }

        let has_engine = self.engine.is_some();
        let has_tun = self.tun.is_some();
        let has_routes = !self.route_deltas.is_empty();
        let has_dns = self.planned_dns_sha256.is_some();
        let exact_shape = match self.stage {
            OwnedStage::Prepared => !has_engine && !has_tun && !has_routes && !has_dns,
            OwnedStage::EnginePrepared | OwnedStage::EngineStarted => {
                has_engine && !has_tun && !has_routes && !has_dns
            }
            OwnedStage::TunVerified => has_engine && has_tun && !has_routes && !has_dns,
            OwnedStage::RoutesPlanned | OwnedStage::RoutesApplied => {
                has_engine && has_tun && has_routes && !has_dns
            }
            OwnedStage::DnsPlanned | OwnedStage::DnsApplied | OwnedStage::Running => {
                has_engine && has_tun && has_routes && has_dns
            }
        };
        if !exact_shape {
            return Err(PlanError::InvalidRecord);
        }
        if let (Some(engine), Some(tun)) = (&self.engine, &self.tun) {
            if tun.engine_pid != engine.pid {
                return Err(PlanError::InvalidRecord);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartEffect {
    CaptureNetworkBaseline,
    VerifyUpstreamIdentity,
    WritePreparedRecord,
    SpawnSuspendedExactEngine,
    PersistSuspendedEngineIdentity,
    ResumeExactEngine,
    CommitEngineStarted,
    VerifyAndPersistTunIdentity,
    PlanAndPersistRoutes,
    ApplyPersistedRoutes,
    PlanAndPersistDns,
    ApplyPersistedDns,
    VerifyTransparentPath,
    CommitRunning,
}

pub const START_EFFECTS: [StartEffect; 14] = [
    StartEffect::CaptureNetworkBaseline,
    StartEffect::VerifyUpstreamIdentity,
    StartEffect::WritePreparedRecord,
    StartEffect::SpawnSuspendedExactEngine,
    StartEffect::PersistSuspendedEngineIdentity,
    StartEffect::ResumeExactEngine,
    StartEffect::CommitEngineStarted,
    StartEffect::VerifyAndPersistTunIdentity,
    StartEffect::PlanAndPersistRoutes,
    StartEffect::ApplyPersistedRoutes,
    StartEffect::PlanAndPersistDns,
    StartEffect::ApplyPersistedDns,
    StartEffect::VerifyTransparentPath,
    StartEffect::CommitRunning,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFact {
    Exact,
    Absent,
    Mismatch,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaFact {
    AppliedExact,
    AppliedSubset,
    Restored,
    Drifted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryFacts {
    pub engine: IdentityFact,
    pub tun: IdentityFact,
    pub routes: DeltaFact,
    pub dns: DeltaFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEffect {
    RestoreExactDnsBaseline,
    RemoveExactOwnedRoutes,
    TerminateExactEngine,
    RemoveExactEngineConfig,
    WaitForExactTunRemoval,
    ClearOwnedRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub effects: Vec<RecoveryEffect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    InvalidRecord,
    IdentityUnknown,
    IdentityMismatch,
    NetworkStateUnknown,
    NetworkStateDrifted,
    OrphanedTun,
    FactContradiction,
}

pub fn plan_recovery(
    record: &OwnedRunRecord,
    facts: RecoveryFacts,
) -> Result<RecoveryPlan, PlanError> {
    record.validate()?;
    if matches!(facts.engine, IdentityFact::Unknown) || matches!(facts.tun, IdentityFact::Unknown) {
        return Err(PlanError::IdentityUnknown);
    }
    if matches!(facts.engine, IdentityFact::Mismatch) || matches!(facts.tun, IdentityFact::Mismatch)
    {
        return Err(PlanError::IdentityMismatch);
    }
    if matches!(facts.routes, DeltaFact::Unknown) || matches!(facts.dns, DeltaFact::Unknown) {
        return Err(PlanError::NetworkStateUnknown);
    }
    if matches!(facts.routes, DeltaFact::Drifted) || matches!(facts.dns, DeltaFact::Drifted) {
        return Err(PlanError::NetworkStateDrifted);
    }
    if facts.engine == IdentityFact::Absent && facts.tun == IdentityFact::Exact {
        return Err(PlanError::OrphanedTun);
    }

    require_stage_fact(record.stage >= OwnedStage::RoutesPlanned, facts.routes)?;
    require_stage_fact(record.stage >= OwnedStage::DnsPlanned, facts.dns)?;
    if record.stage < OwnedStage::EnginePrepared && facts.engine != IdentityFact::Absent {
        return Err(PlanError::FactContradiction);
    }
    if record.stage < OwnedStage::TunVerified && facts.tun != IdentityFact::Absent {
        return Err(PlanError::FactContradiction);
    }

    let mut effects = Vec::new();
    if facts.dns == DeltaFact::AppliedExact {
        effects.push(RecoveryEffect::RestoreExactDnsBaseline);
    }
    if matches!(
        facts.routes,
        DeltaFact::AppliedExact | DeltaFact::AppliedSubset
    ) {
        effects.push(RecoveryEffect::RemoveExactOwnedRoutes);
    }
    if facts.engine == IdentityFact::Exact {
        effects.push(RecoveryEffect::TerminateExactEngine);
    }
    if record.engine.is_some() {
        effects.push(RecoveryEffect::RemoveExactEngineConfig);
    }
    if facts.tun == IdentityFact::Exact {
        effects.push(RecoveryEffect::WaitForExactTunRemoval);
    }
    effects.push(RecoveryEffect::ClearOwnedRecord);
    Ok(RecoveryPlan { effects })
}

fn require_stage_fact(stage_has_effect: bool, fact: DeltaFact) -> Result<(), PlanError> {
    if (stage_has_effect
        && matches!(
            fact,
            DeltaFact::AppliedExact | DeltaFact::AppliedSubset | DeltaFact::Restored
        ))
        || (!stage_has_effect && fact == DeltaFact::Restored)
    {
        Ok(())
    } else {
        Err(PlanError::FactContradiction)
    }
}

fn valid_process(value: &ProcessIdentity) -> bool {
    value.pid > 1
        && value.start_time_ns > 0
        && value.executable_file_id > 0
        && valid_hex(&value.executable_sha256, 64)
}

fn valid_tun(value: &TunIdentity) -> bool {
    value.interface_index > 0
        && value.engine_pid > 1
        && value
            .interface_name
            .strip_prefix("utun")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.len() <= 4
                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn valid_interface(value: &InterfaceIdentity) -> bool {
    value.interface_index > 0 && valid_utun_name(&value.interface_name)
}

fn valid_utun_name(value: &str) -> bool {
    value.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_route(value: &RouteDelta) -> bool {
    value.interface_index > 0
        && match value.destination {
            IpAddr::V4(address) => {
                value.prefix_length <= 32
                    && if value.prefix_length == 0 {
                        u32::from(address) == 0
                    } else {
                        u32::from(address) & (u32::MAX << (32 - value.prefix_length))
                            == u32::from(address)
                    }
            }
            IpAddr::V6(address) => {
                value.prefix_length <= 128
                    && if value.prefix_length == 0 {
                        u128::from(address) == 0
                    } else {
                        u128::from(address) & (u128::MAX << (128 - value.prefix_length))
                            == u128::from(address)
                    }
            }
        }
        && value
            .gateway
            .is_none_or(|gateway| gateway.is_ipv4() == value.destination.is_ipv4())
}

fn valid_baseline(value: &NetworkBaseline) -> bool {
    value.default_interface_index > 0
        && valid_hex(&value.routes_sha256, 64)
        && value.preexisting_utuns.len() <= MAX_BASELINE_UTUNS
        && value.preexisting_utuns.iter().all(valid_interface)
        && !value
            .preexisting_utuns
            .iter()
            .enumerate()
            .any(|(index, item)| {
                value.preexisting_utuns[..index].iter().any(|prior| {
                    prior.interface_name == item.interface_name
                        || prior.interface_index == item.interface_index
                })
            })
        && valid_identifier(&value.dns.network_service_id, 128)
        && value.dns.servers.len() <= MAX_DNS_SERVERS
        && value.dns.search_domains.len() <= MAX_SEARCH_DOMAINS
        && value
            .dns
            .servers
            .iter()
            .all(|server| !server.is_unspecified() && !server.is_multicast())
        && match value.dns.mode {
            DnsConfigurationMode::Automatic => {
                value.dns.servers.is_empty() && value.dns.search_domains.is_empty()
            }
            DnsConfigurationMode::Manual => {
                !value.dns.servers.is_empty() || !value.dns.search_domains.is_empty()
            }
        }
        && value
            .dns
            .search_domains
            .iter()
            .all(|domain| valid_domain(domain))
}

fn valid_principal(value: &str) -> bool {
    valid_identifier(value, 256) && value.starts_with("macos:")
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DOMAIN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn process(pid: u32, byte: char) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: byte.to_string().repeat(64),
        }
    }

    fn record(stage: OwnedStage) -> OwnedRunRecord {
        let engine = (stage >= OwnedStage::EnginePrepared).then(|| process(700, 'b'));
        let tun = (stage >= OwnedStage::TunVerified).then(|| TunIdentity {
            interface_name: "utun7".into(),
            interface_index: 17,
            engine_pid: 700,
        });
        let route_deltas = if stage >= OwnedStage::RoutesPlanned {
            vec![
                RouteDelta {
                    destination: Ipv4Addr::UNSPECIFIED.into(),
                    prefix_length: 1,
                    gateway: None,
                    interface_index: 17,
                    interface_scoped: false,
                },
                RouteDelta {
                    destination: Ipv6Addr::UNSPECIFIED.into(),
                    prefix_length: 1,
                    gateway: None,
                    interface_index: 17,
                    interface_scoped: false,
                },
            ]
        } else {
            Vec::new()
        };
        OwnedRunRecord {
            schema_version: 2,
            run_id: "a".repeat(32),
            stage,
            owner_principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            owner_session_id: 42,
            upstream: process(600, 'c'),
            engine,
            tun,
            baseline: NetworkBaseline {
                default_interface_index: 9,
                default_gateway: Ipv4Addr::new(192, 0, 2, 1).into(),
                routes_sha256: "d".repeat(64),
                preexisting_utuns: Vec::new(),
                dns: DnsBaseline {
                    network_service_id: "service-fixture".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: vec![Ipv4Addr::new(192, 0, 2, 53).into()],
                    search_domains: vec!["example.test".into()],
                },
            },
            route_deltas,
            planned_dns_sha256: (stage >= OwnedStage::DnsPlanned).then(|| "e".repeat(64)),
            controller_secret: "f".repeat(64),
        }
    }

    #[test]
    fn start_effect_order_persists_identity_before_every_system_delta() {
        assert_eq!(
            START_EFFECTS,
            [
                StartEffect::CaptureNetworkBaseline,
                StartEffect::VerifyUpstreamIdentity,
                StartEffect::WritePreparedRecord,
                StartEffect::SpawnSuspendedExactEngine,
                StartEffect::PersistSuspendedEngineIdentity,
                StartEffect::ResumeExactEngine,
                StartEffect::CommitEngineStarted,
                StartEffect::VerifyAndPersistTunIdentity,
                StartEffect::PlanAndPersistRoutes,
                StartEffect::ApplyPersistedRoutes,
                StartEffect::PlanAndPersistDns,
                StartEffect::ApplyPersistedDns,
                StartEffect::VerifyTransparentPath,
                StartEffect::CommitRunning,
            ]
        );
    }

    #[test]
    fn every_stage_has_one_strict_valid_record_shape() {
        for stage in [
            OwnedStage::Prepared,
            OwnedStage::EnginePrepared,
            OwnedStage::EngineStarted,
            OwnedStage::TunVerified,
            OwnedStage::RoutesPlanned,
            OwnedStage::RoutesApplied,
            OwnedStage::DnsPlanned,
            OwnedStage::DnsApplied,
            OwnedStage::Running,
        ] {
            record(stage).validate().unwrap();
        }
    }

    #[test]
    fn running_recovery_reverses_exact_deltas_before_engine_and_record() {
        let plan = plan_recovery(
            &record(OwnedStage::Running),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::AppliedExact,
                dns: DeltaFact::AppliedExact,
            },
        )
        .unwrap();
        assert_eq!(
            plan.effects,
            vec![
                RecoveryEffect::RestoreExactDnsBaseline,
                RecoveryEffect::RemoveExactOwnedRoutes,
                RecoveryEffect::TerminateExactEngine,
                RecoveryEffect::RemoveExactEngineConfig,
                RecoveryEffect::WaitForExactTunRemoval,
                RecoveryEffect::ClearOwnedRecord,
            ]
        );
    }

    #[test]
    fn crashed_engine_can_restore_exact_network_delta_and_clear() {
        let plan = plan_recovery(
            &record(OwnedStage::Running),
            RecoveryFacts {
                engine: IdentityFact::Absent,
                tun: IdentityFact::Absent,
                routes: DeltaFact::AppliedExact,
                dns: DeltaFact::AppliedExact,
            },
        )
        .unwrap();
        assert_eq!(
            plan.effects,
            vec![
                RecoveryEffect::RestoreExactDnsBaseline,
                RecoveryEffect::RemoveExactOwnedRoutes,
                RecoveryEffect::RemoveExactEngineConfig,
                RecoveryEffect::ClearOwnedRecord,
            ]
        );
    }

    #[test]
    fn partially_applied_owned_routes_are_still_removed_exactly() {
        let plan = plan_recovery(
            &record(OwnedStage::RoutesApplied),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::AppliedSubset,
                dns: DeltaFact::Restored,
            },
        )
        .unwrap();
        assert_eq!(
            plan.effects,
            vec![
                RecoveryEffect::RemoveExactOwnedRoutes,
                RecoveryEffect::TerminateExactEngine,
                RecoveryEffect::RemoveExactEngineConfig,
                RecoveryEffect::WaitForExactTunRemoval,
                RecoveryEffect::ClearOwnedRecord,
            ]
        );
    }

    #[test]
    fn planned_but_not_applied_network_deltas_need_no_global_cleanup() {
        let plan = plan_recovery(
            &record(OwnedStage::RoutesPlanned),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::Restored,
                dns: DeltaFact::Restored,
            },
        )
        .unwrap();
        assert_eq!(
            plan.effects,
            vec![
                RecoveryEffect::TerminateExactEngine,
                RecoveryEffect::RemoveExactEngineConfig,
                RecoveryEffect::WaitForExactTunRemoval,
                RecoveryEffect::ClearOwnedRecord,
            ]
        );

        let plan = plan_recovery(
            &record(OwnedStage::DnsPlanned),
            RecoveryFacts {
                engine: IdentityFact::Exact,
                tun: IdentityFact::Exact,
                routes: DeltaFact::AppliedExact,
                dns: DeltaFact::Restored,
            },
        )
        .unwrap();
        assert_eq!(
            plan.effects,
            vec![
                RecoveryEffect::RemoveExactOwnedRoutes,
                RecoveryEffect::TerminateExactEngine,
                RecoveryEffect::RemoveExactEngineConfig,
                RecoveryEffect::WaitForExactTunRemoval,
                RecoveryEffect::ClearOwnedRecord,
            ]
        );
    }

    #[test]
    fn prepared_record_without_effects_only_clears_exact_journal() {
        let plan = plan_recovery(
            &record(OwnedStage::Prepared),
            RecoveryFacts {
                engine: IdentityFact::Absent,
                tun: IdentityFact::Absent,
                routes: DeltaFact::Restored,
                dns: DeltaFact::Restored,
            },
        )
        .unwrap();
        assert_eq!(plan.effects, vec![RecoveryEffect::ClearOwnedRecord]);
    }

    #[test]
    fn unknown_mismatch_drift_and_orphaned_tun_never_produce_cleanup_effects() {
        let base = RecoveryFacts {
            engine: IdentityFact::Exact,
            tun: IdentityFact::Exact,
            routes: DeltaFact::AppliedExact,
            dns: DeltaFact::AppliedExact,
        };
        for (facts, expected) in [
            (
                RecoveryFacts {
                    engine: IdentityFact::Unknown,
                    ..base
                },
                PlanError::IdentityUnknown,
            ),
            (
                RecoveryFacts {
                    tun: IdentityFact::Mismatch,
                    ..base
                },
                PlanError::IdentityMismatch,
            ),
            (
                RecoveryFacts {
                    routes: DeltaFact::Drifted,
                    ..base
                },
                PlanError::NetworkStateDrifted,
            ),
            (
                RecoveryFacts {
                    dns: DeltaFact::Unknown,
                    ..base
                },
                PlanError::NetworkStateUnknown,
            ),
            (
                RecoveryFacts {
                    engine: IdentityFact::Absent,
                    tun: IdentityFact::Exact,
                    ..base
                },
                PlanError::OrphanedTun,
            ),
        ] {
            assert_eq!(
                plan_recovery(&record(OwnedStage::Running), facts),
                Err(expected)
            );
        }
    }

    #[test]
    fn record_validation_rejects_cross_stage_forgery_and_redacts_secret() {
        let mut legacy = record(OwnedStage::Prepared);
        legacy.schema_version = 1;
        assert_eq!(legacy.validate(), Err(PlanError::InvalidRecord));

        let mut forged = record(OwnedStage::Prepared);
        forged.engine = Some(process(700, 'b'));
        assert_eq!(forged.validate(), Err(PlanError::InvalidRecord));

        let running = record(OwnedStage::Running);
        let debug = format!("{running:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&"f".repeat(64)));

        let mut value = serde_json::to_value(running).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<OwnedRunRecord>(value).is_err());
    }

    #[test]
    fn route_scope_is_optional_in_journals_written_before_scoped_routes() {
        let unscoped = record(OwnedStage::Running);
        let value = serde_json::to_value(&unscoped).unwrap();
        assert!(value["routeDeltas"][0].get("interfaceScoped").is_none());
        assert_eq!(
            serde_json::from_value::<OwnedRunRecord>(value).unwrap(),
            unscoped
        );

        let mut scoped = record(OwnedStage::Running);
        scoped.route_deltas[0] = RouteDelta {
            destination: Ipv4Addr::UNSPECIFIED.into(),
            prefix_length: 0,
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
            interface_index: 9,
            interface_scoped: true,
        };
        scoped.validate().unwrap();
        let value = serde_json::to_value(&scoped).unwrap();
        assert_eq!(value["routeDeltas"][0]["interfaceScoped"], true);
        assert_eq!(
            serde_json::from_value::<OwnedRunRecord>(value).unwrap(),
            scoped
        );
    }

    #[test]
    fn route_tun_and_dns_bounds_fail_closed() {
        let mut invalid = record(OwnedStage::Running);
        invalid.tun.as_mut().unwrap().interface_name = "en0".into();
        assert_eq!(invalid.validate(), Err(PlanError::InvalidRecord));

        let mut invalid = record(OwnedStage::Running);
        invalid.route_deltas[0].prefix_length = 33;
        assert_eq!(invalid.validate(), Err(PlanError::InvalidRecord));

        let mut invalid = record(OwnedStage::Running);
        invalid.route_deltas[0].destination = Ipv4Addr::new(192, 0, 2, 7).into();
        invalid.route_deltas[0].prefix_length = 24;
        assert_eq!(invalid.validate(), Err(PlanError::InvalidRecord));

        let mut invalid = record(OwnedStage::Running);
        invalid.baseline.dns.search_domains = vec!["x".repeat(254)];
        assert_eq!(invalid.validate(), Err(PlanError::InvalidRecord));

        let mut automatic = record(OwnedStage::Running);
        automatic.baseline.dns.mode = DnsConfigurationMode::Automatic;
        assert_eq!(automatic.validate(), Err(PlanError::InvalidRecord));
        automatic.baseline.dns.servers.clear();
        automatic.baseline.dns.search_domains.clear();
        automatic.validate().unwrap();

        let mut duplicate = record(OwnedStage::Running);
        duplicate.baseline.preexisting_utuns = vec![
            InterfaceIdentity {
                interface_name: "utun2".into(),
                interface_index: 12,
            },
            InterfaceIdentity {
                interface_name: "utun2".into(),
                interface_index: 13,
            },
        ];
        assert_eq!(duplicate.validate(), Err(PlanError::InvalidRecord));
    }
}
