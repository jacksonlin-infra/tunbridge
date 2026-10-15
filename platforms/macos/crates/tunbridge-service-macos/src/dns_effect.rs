//! Syscall-free exact DNS effect planning.
//!
//! Plans are canonical expected states. This module never locks, writes,
//! commits, or applies SystemConfiguration preferences.

use crate::{
    darwin_state::{dns_baseline_sha256, dns_snapshot_sha256, DnsSnapshot},
    lifecycle_plan::{DnsBaseline, DnsConfigurationMode},
};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsEffectConfiguration {
    Automatic,
    Manual {
        servers: Vec<IpAddr>,
        search_domains: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEffectRequest {
    pub network_service_id: String,
    pub configuration: DnsEffectConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEffectPlan {
    pub request: DnsEffectRequest,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEffectError {
    Invalid,
}

pub fn plan_manual_dns(
    network_service_id: &str,
    servers: Vec<IpAddr>,
    search_domains: Vec<String>,
) -> Result<DnsEffectPlan, DnsEffectError> {
    plan(DnsEffectRequest {
        network_service_id: network_service_id.into(),
        configuration: DnsEffectConfiguration::Manual {
            servers,
            search_domains,
        },
    })
}

pub fn plan_restore_dns(baseline: &DnsBaseline) -> Result<DnsEffectPlan, DnsEffectError> {
    let request = DnsEffectRequest {
        network_service_id: baseline.network_service_id.clone(),
        configuration: match baseline.mode {
            DnsConfigurationMode::Automatic => DnsEffectConfiguration::Automatic,
            DnsConfigurationMode::Manual => DnsEffectConfiguration::Manual {
                servers: baseline.servers.clone(),
                search_domains: baseline.search_domains.clone(),
            },
        },
    };
    let plan = plan(request)?;
    if dns_baseline_sha256(baseline).map_err(|_| DnsEffectError::Invalid)? != plan.expected_sha256 {
        return Err(DnsEffectError::Invalid);
    }
    Ok(plan)
}

pub fn expected_snapshot(plan: &DnsEffectPlan) -> Result<DnsSnapshot, DnsEffectError> {
    let (mode, servers, search_domains) = match &plan.request.configuration {
        DnsEffectConfiguration::Automatic => {
            (DnsConfigurationMode::Automatic, Vec::new(), Vec::new())
        }
        DnsEffectConfiguration::Manual {
            servers,
            search_domains,
        } => (
            DnsConfigurationMode::Manual,
            servers.clone(),
            search_domains.clone(),
        ),
    };
    let snapshot = DnsSnapshot {
        complete: true,
        network_service_id: plan.request.network_service_id.clone(),
        mode,
        servers,
        search_domains,
    };
    if dns_snapshot_sha256(&snapshot).map_err(|_| DnsEffectError::Invalid)? != plan.expected_sha256
    {
        return Err(DnsEffectError::Invalid);
    }
    Ok(snapshot)
}

fn plan(request: DnsEffectRequest) -> Result<DnsEffectPlan, DnsEffectError> {
    let snapshot = DnsSnapshot {
        complete: true,
        network_service_id: request.network_service_id.clone(),
        mode: match &request.configuration {
            DnsEffectConfiguration::Automatic => DnsConfigurationMode::Automatic,
            DnsEffectConfiguration::Manual { .. } => DnsConfigurationMode::Manual,
        },
        servers: match &request.configuration {
            DnsEffectConfiguration::Automatic => Vec::new(),
            DnsEffectConfiguration::Manual { servers, .. } => servers.clone(),
        },
        search_domains: match &request.configuration {
            DnsEffectConfiguration::Automatic => Vec::new(),
            DnsEffectConfiguration::Manual { search_domains, .. } => search_domains.clone(),
        },
    };
    let expected_sha256 = dns_snapshot_sha256(&snapshot).map_err(|_| DnsEffectError::Invalid)?;
    Ok(DnsEffectPlan {
        request,
        expected_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_plan_binds_exact_service_ordered_values_and_hash() {
        let plan = plan_manual_dns(
            "service-id",
            vec![
                "198.18.0.1".parse().unwrap(),
                "2001:db8::53".parse().unwrap(),
            ],
            vec!["example.test".into()],
        )
        .unwrap();
        let snapshot = expected_snapshot(&plan).unwrap();
        assert_eq!(snapshot.mode, DnsConfigurationMode::Manual);
        assert_eq!(snapshot.network_service_id, "service-id");
        assert_eq!(
            dns_snapshot_sha256(&snapshot).unwrap(),
            plan.expected_sha256
        );

        let reordered = plan_manual_dns(
            "service-id",
            vec![
                "2001:db8::53".parse().unwrap(),
                "198.18.0.1".parse().unwrap(),
            ],
            vec!["example.test".into()],
        )
        .unwrap();
        assert_ne!(plan.expected_sha256, reordered.expected_sha256);
    }

    #[test]
    fn automatic_restore_clears_values_and_matches_baseline_hash() {
        let baseline = DnsBaseline {
            network_service_id: "service-id".into(),
            mode: DnsConfigurationMode::Automatic,
            servers: Vec::new(),
            search_domains: Vec::new(),
        };
        let plan = plan_restore_dns(&baseline).unwrap();
        assert_eq!(
            plan.request.configuration,
            DnsEffectConfiguration::Automatic
        );
        assert_eq!(
            plan.expected_sha256,
            dns_baseline_sha256(&baseline).unwrap()
        );
    }

    #[test]
    fn malformed_manual_and_baseline_requests_fail_before_systemconfiguration() {
        assert_eq!(
            plan_manual_dns("service-id", Vec::new(), Vec::new()),
            Err(DnsEffectError::Invalid)
        );
        assert_eq!(
            plan_manual_dns("service-id", vec!["0.0.0.0".parse().unwrap()], Vec::new()),
            Err(DnsEffectError::Invalid)
        );
        let invalid = DnsBaseline {
            network_service_id: "service-id".into(),
            mode: DnsConfigurationMode::Automatic,
            servers: vec!["192.0.2.53".parse().unwrap()],
            search_domains: Vec::new(),
        };
        assert_eq!(plan_restore_dns(&invalid), Err(DnsEffectError::Invalid));
    }
}
