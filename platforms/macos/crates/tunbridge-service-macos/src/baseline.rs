//! Read-only Darwin network baseline discovery.

use crate::{
    darwin_state::{route_snapshot_sha256, DnsSnapshot, InterfaceSnapshot, RouteSnapshot},
    dns_store::native_dns_snapshot_for_device,
    lifecycle_plan::{DnsBaseline, InterfaceIdentity, NetworkBaseline},
    native::{interface_snapshot, native_route_snapshot},
};
use std::net::{IpAddr, Ipv4Addr};

const BASELINE_RETRIES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBaselineError {
    Unavailable,
    Invalid,
    Ambiguous,
    Incomplete,
}

pub fn native_network_baseline() -> Result<NetworkBaseline, NativeBaselineError> {
    for _ in 0..BASELINE_RETRIES {
        let first = native_baseline_sample()?;
        let second = native_baseline_sample()?;
        if first == second {
            return Ok(second);
        }
    }
    Err(NativeBaselineError::Incomplete)
}

fn native_baseline_sample() -> Result<NetworkBaseline, NativeBaselineError> {
    let routes = native_route_snapshot().map_err(|_| NativeBaselineError::Unavailable)?;
    let interfaces = interface_snapshot().map_err(|_| NativeBaselineError::Unavailable)?;
    let (interface_index, gateway, interface_name) = physical_ipv4_default(&routes, &interfaces)?;
    let dns = native_dns_snapshot_for_device(&interface_name)
        .map_err(|_| NativeBaselineError::Unavailable)?;
    baseline_from_snapshots(&routes, &interfaces, interface_index, gateway, dns)
}

fn physical_ipv4_default(
    routes: &RouteSnapshot,
    interfaces: &InterfaceSnapshot,
) -> Result<(u32, Ipv4Addr, String), NativeBaselineError> {
    if !routes.complete || !interfaces.complete {
        return Err(NativeBaselineError::Incomplete);
    }
    // Scoped defaults (secondary services, or ours from a running tunnel) do
    // not route unscoped traffic and never identify the physical default.
    let mut defaults = routes.routes.iter().filter_map(|route| {
        if route.interface_scoped {
            return None;
        }
        match (route.destination, route.prefix_length, route.gateway) {
            (IpAddr::V4(destination), 0, Some(IpAddr::V4(gateway)))
                if destination.is_unspecified()
                    && !gateway.is_unspecified()
                    && !gateway.is_multicast() =>
            {
                Some((route.interface_index, gateway))
            }
            _ => None,
        }
    });
    let Some((interface_index, gateway)) = defaults.next() else {
        return Err(NativeBaselineError::Invalid);
    };
    if defaults.next().is_some() {
        return Err(NativeBaselineError::Ambiguous);
    }
    let mut names = interfaces
        .interfaces
        .iter()
        .filter(|interface| interface.index == interface_index);
    let Some(interface) = names.next() else {
        return Err(NativeBaselineError::Invalid);
    };
    if names.next().is_some() || interface.name.starts_with("utun") {
        return Err(NativeBaselineError::Ambiguous);
    }
    Ok((interface_index, gateway, interface.name.clone()))
}

fn baseline_from_snapshots(
    routes: &RouteSnapshot,
    interfaces: &InterfaceSnapshot,
    default_interface_index: u32,
    default_gateway: Ipv4Addr,
    dns: DnsSnapshot,
) -> Result<NetworkBaseline, NativeBaselineError> {
    let routes_sha256 = route_snapshot_sha256(routes).map_err(|_| NativeBaselineError::Invalid)?;
    let mut preexisting_utuns = Vec::new();
    for interface in &interfaces.interfaces {
        if interface.name.starts_with("utun") {
            let suffix = interface.name.strip_prefix("utun").unwrap();
            if interface.index == 0
                || suffix.is_empty()
                || suffix.len() > 4
                || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(NativeBaselineError::Invalid);
            }
            preexisting_utuns.push(InterfaceIdentity {
                interface_name: interface.name.clone(),
                interface_index: interface.index,
            });
        }
    }
    preexisting_utuns.sort_by_key(|item| item.interface_index);
    if preexisting_utuns.len() > 64
        || preexisting_utuns.iter().enumerate().any(|(index, item)| {
            preexisting_utuns[..index]
                .iter()
                .any(|prior| prior.interface_name == item.interface_name)
        })
    {
        return Err(NativeBaselineError::Ambiguous);
    }
    Ok(NetworkBaseline {
        default_interface_index,
        default_gateway: default_gateway.into(),
        routes_sha256,
        preexisting_utuns,
        dns: DnsBaseline {
            network_service_id: dns.network_service_id,
            mode: dns.mode,
            servers: dns.servers,
            search_domains: dns.search_domains,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        darwin_state::DarwinInterface,
        lifecycle_plan::{DnsConfigurationMode, RouteDelta},
    };

    fn route(
        destination: &str,
        prefix_length: u8,
        gateway: Option<&str>,
        interface_index: u32,
    ) -> RouteDelta {
        RouteDelta {
            destination: destination.parse().unwrap(),
            prefix_length,
            gateway: gateway.map(|value| value.parse().unwrap()),
            interface_index,
            interface_scoped: false,
        }
    }

    #[test]
    fn physical_default_requires_one_ip_gateway_and_exact_interface() {
        let routes = RouteSnapshot {
            complete: true,
            routes: vec![
                route("0.0.0.0", 0, Some("192.0.2.1"), 7),
                route("0.0.0.0", 0, None, 23),
            ],
        };
        let interfaces = InterfaceSnapshot {
            complete: true,
            interfaces: vec![
                DarwinInterface {
                    name: "en0".into(),
                    index: 7,
                    owner_pid: None,
                },
                DarwinInterface {
                    name: "utun4".into(),
                    index: 23,
                    owner_pid: None,
                },
            ],
        };
        assert_eq!(
            physical_ipv4_default(&routes, &interfaces).unwrap(),
            (7, "192.0.2.1".parse().unwrap(), "en0".into())
        );

        // A scoped default (a secondary service, or the one a running tunnel
        // owns) never routes unscoped traffic and is not a second default.
        let mut scoped = routes.clone();
        let mut secondary = route("0.0.0.0", 0, Some("198.51.100.1"), 9);
        secondary.interface_scoped = true;
        let mut tunnel_owned = route("0.0.0.0", 0, Some("192.0.2.1"), 7);
        tunnel_owned.interface_scoped = true;
        scoped.routes.extend([secondary, tunnel_owned]);
        assert_eq!(
            physical_ipv4_default(&scoped, &interfaces).unwrap(),
            (7, "192.0.2.1".parse().unwrap(), "en0".into())
        );

        let mut ambiguous = routes;
        ambiguous
            .routes
            .push(route("0.0.0.0", 0, Some("198.51.100.1"), 9));
        assert_eq!(
            physical_ipv4_default(&ambiguous, &interfaces),
            Err(NativeBaselineError::Ambiguous)
        );
    }

    #[test]
    fn baseline_includes_route_hash_and_dns_configuration_mode() {
        let routes = RouteSnapshot {
            complete: true,
            routes: vec![route("0.0.0.0", 0, Some("192.0.2.1"), 7)],
        };
        let interfaces = InterfaceSnapshot {
            complete: true,
            interfaces: vec![
                DarwinInterface {
                    name: "en0".into(),
                    index: 7,
                    owner_pid: None,
                },
                DarwinInterface {
                    name: "utun4".into(),
                    index: 14,
                    owner_pid: None,
                },
            ],
        };
        let baseline = baseline_from_snapshots(
            &routes,
            &interfaces,
            7,
            "192.0.2.1".parse().unwrap(),
            DnsSnapshot {
                complete: true,
                network_service_id: "service-id".into(),
                mode: DnsConfigurationMode::Automatic,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(baseline.default_interface_index, 7);
        assert_eq!(
            baseline.default_gateway,
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(baseline.dns.mode, DnsConfigurationMode::Automatic);
        assert_eq!(baseline.routes_sha256.len(), 64);
        assert_eq!(
            baseline.preexisting_utuns,
            [InterfaceIdentity {
                interface_name: "utun4".into(),
                interface_index: 14,
            }]
        );
    }

    #[test]
    fn current_network_baseline_is_read_only_stable_and_exact() {
        let baseline = native_network_baseline().unwrap();
        assert!(baseline.default_interface_index > 0);
        assert!(matches!(baseline.default_gateway, IpAddr::V4(_)));
        assert_eq!(baseline.routes_sha256.len(), 64);
        assert!(!baseline.dns.network_service_id.is_empty());
    }
}
