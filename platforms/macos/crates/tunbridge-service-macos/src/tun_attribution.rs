//! Syscall-free causal attribution for a newly created Darwin utun.
//!
//! macOS interface inventory does not expose an owner PID. Attribution
//! therefore requires the persisted pre-start set, an exact engine identity,
//! an authenticated controller report, and one unique new utun.

use crate::{
    darwin_state::InterfaceSnapshot,
    lifecycle_plan::{InterfaceIdentity, NetworkBaseline, ProcessIdentity, TunIdentity},
};
use std::collections::BTreeSet;

const MAX_INTERFACES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerTunEvidence {
    pub authenticated: bool,
    pub engine_pid: u32,
    pub configured_device: String,
    pub tun_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunAttributionError {
    Invalid,
    Incomplete,
    Ambiguous,
    Mismatch,
}

pub fn attribute_new_utun(
    baseline: &NetworkBaseline,
    engine: &ProcessIdentity,
    controller: &ControllerTunEvidence,
    current: &InterfaceSnapshot,
) -> Result<TunIdentity, TunAttributionError> {
    if !current.complete {
        return Err(TunAttributionError::Incomplete);
    }
    if current.interfaces.len() > MAX_INTERFACES
        || engine.pid <= 1
        || !controller.authenticated
        || !controller.tun_enabled
        || controller.engine_pid != engine.pid
        || !valid_utun_name(&controller.configured_device)
    {
        return Err(TunAttributionError::Invalid);
    }

    let before = canonical_baseline(&baseline.preexisting_utuns)?;
    let mut observed = BTreeSet::new();
    let mut observed_names = BTreeSet::new();
    let mut observed_indexes = BTreeSet::new();
    let mut additions = Vec::new();
    for interface in &current.interfaces {
        if !interface.name.starts_with("utun") {
            continue;
        }
        if interface.index == 0
            || !valid_utun_name(&interface.name)
            || !observed_names.insert(interface.name.clone())
            || !observed_indexes.insert(interface.index)
        {
            return Err(TunAttributionError::Ambiguous);
        }
        observed.insert((interface.name.clone(), interface.index));
        if interface.owner_pid.is_some_and(|owner| owner != engine.pid) {
            return Err(TunAttributionError::Mismatch);
        }
        if !before.contains(&(interface.name.clone(), interface.index)) {
            additions.push(interface);
        }
    }
    if !before.is_subset(&observed) {
        return Err(TunAttributionError::Mismatch);
    }
    if additions.len() != 1 {
        return Err(TunAttributionError::Ambiguous);
    }
    let addition = additions[0];
    if addition.name != controller.configured_device {
        return Err(TunAttributionError::Mismatch);
    }
    Ok(TunIdentity {
        interface_name: addition.name.clone(),
        interface_index: addition.index,
        engine_pid: engine.pid,
    })
}

fn canonical_baseline(
    interfaces: &[InterfaceIdentity],
) -> Result<BTreeSet<(String, u32)>, TunAttributionError> {
    if interfaces.len() > 64 {
        return Err(TunAttributionError::Invalid);
    }
    let mut result = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut indexes = BTreeSet::new();
    for interface in interfaces {
        if interface.interface_index == 0
            || !valid_utun_name(&interface.interface_name)
            || !names.insert(interface.interface_name.clone())
            || !indexes.insert(interface.interface_index)
        {
            return Err(TunAttributionError::Invalid);
        }
        result.insert((interface.interface_name.clone(), interface.interface_index));
    }
    Ok(result)
}

fn valid_utun_name(value: &str) -> bool {
    value.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        darwin_state::DarwinInterface,
        lifecycle_plan::{DnsBaseline, DnsConfigurationMode},
    };

    fn baseline() -> NetworkBaseline {
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: "192.0.2.1".parse().unwrap(),
            routes_sha256: "a".repeat(64),
            preexisting_utuns: vec![InterfaceIdentity {
                interface_name: "utun2".into(),
                interface_index: 12,
            }],
            dns: DnsBaseline {
                network_service_id: "service-id".into(),
                mode: DnsConfigurationMode::Automatic,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
        }
    }

    fn engine() -> ProcessIdentity {
        ProcessIdentity {
            pid: 700,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: "b".repeat(64),
        }
    }

    fn controller() -> ControllerTunEvidence {
        ControllerTunEvidence {
            authenticated: true,
            engine_pid: 700,
            configured_device: "utun7".into(),
            tun_enabled: true,
        }
    }

    fn snapshot(additions: &[(&str, u32)]) -> InterfaceSnapshot {
        let mut interfaces = vec![
            DarwinInterface {
                name: "en0".into(),
                index: 9,
                owner_pid: None,
            },
            DarwinInterface {
                name: "utun2".into(),
                index: 12,
                owner_pid: None,
            },
        ];
        interfaces.extend(additions.iter().map(|(name, index)| DarwinInterface {
            name: (*name).into(),
            index: *index,
            owner_pid: None,
        }));
        InterfaceSnapshot {
            complete: true,
            interfaces,
        }
    }

    #[test]
    fn exact_controller_and_one_new_utun_establish_causal_identity() {
        assert_eq!(
            attribute_new_utun(
                &baseline(),
                &engine(),
                &controller(),
                &snapshot(&[("utun7", 17)])
            )
            .unwrap(),
            TunIdentity {
                interface_name: "utun7".into(),
                interface_index: 17,
                engine_pid: 700,
            }
        );
    }

    #[test]
    fn unauthenticated_wrong_engine_or_wrong_device_never_attributes() {
        let mut evidence = controller();
        evidence.authenticated = false;
        assert!(attribute_new_utun(
            &baseline(),
            &engine(),
            &evidence,
            &snapshot(&[("utun7", 17)])
        )
        .is_err());
        evidence = controller();
        evidence.engine_pid = 701;
        assert!(attribute_new_utun(
            &baseline(),
            &engine(),
            &evidence,
            &snapshot(&[("utun7", 17)])
        )
        .is_err());
        evidence = controller();
        evidence.configured_device = "utun8".into();
        assert_eq!(
            attribute_new_utun(
                &baseline(),
                &engine(),
                &evidence,
                &snapshot(&[("utun7", 17)])
            ),
            Err(TunAttributionError::Mismatch)
        );
    }

    #[test]
    fn zero_or_multiple_new_utuns_and_foreign_owner_are_ambiguous_or_mismatch() {
        assert_eq!(
            attribute_new_utun(&baseline(), &engine(), &controller(), &snapshot(&[])),
            Err(TunAttributionError::Ambiguous)
        );
        assert_eq!(
            attribute_new_utun(
                &baseline(),
                &engine(),
                &controller(),
                &snapshot(&[("utun7", 17), ("utun8", 18)])
            ),
            Err(TunAttributionError::Ambiguous)
        );
        let mut owned = snapshot(&[("utun7", 17)]);
        owned.interfaces.last_mut().unwrap().owner_pid = Some(900);
        assert_eq!(
            attribute_new_utun(&baseline(), &engine(), &controller(), &owned),
            Err(TunAttributionError::Mismatch)
        );

        let missing_baseline = InterfaceSnapshot {
            complete: true,
            interfaces: vec![DarwinInterface {
                name: "utun7".into(),
                index: 17,
                owner_pid: None,
            }],
        };
        assert_eq!(
            attribute_new_utun(&baseline(), &engine(), &controller(), &missing_baseline),
            Err(TunAttributionError::Mismatch)
        );
    }
}
