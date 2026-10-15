//! Pure Darwin network-state planning and observation.
//!
//! This module intentionally contains no syscalls or command execution. Native
//! observers may populate these bounded snapshots later; recovery decisions can
//! then be tested without touching the development machine's network state.

use crate::lifecycle_plan::{
    DeltaFact, DnsBaseline, DnsConfigurationMode, IdentityFact, NetworkBaseline, RouteDelta,
    TunIdentity,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const MAX_SNAPSHOT_ROUTES: usize = 4096;
const MAX_OWNED_ROUTES: usize = 32;
const MAX_INTERFACES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    Incomplete,
    Invalid,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub complete: bool,
    pub routes: Vec<RouteDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSnapshot {
    pub complete: bool,
    pub network_service_id: String,
    pub mode: DnsConfigurationMode,
    pub servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DarwinInterface {
    pub name: String,
    pub index: u32,
    pub owner_pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSnapshot {
    pub complete: bool,
    pub interfaces: Vec<DarwinInterface>,
}

pub fn plan_tunnel_routes(
    baseline: &NetworkBaseline,
    tun: &TunIdentity,
    upstream_address: IpAddr,
    include_ipv6: bool,
) -> Result<Vec<RouteDelta>, SnapshotError> {
    plan_tunnel_routes_with_bypass(baseline, tun, upstream_address, include_ipv6, &[])
}

/// Plans split-default routes plus exact physical routes for the CIDRs that
/// must not be sent through the tunnel.  The baseline currently records only
/// the physical IPv4 default gateway, so IPv6 bypasses fail closed instead of
/// guessing a gateway or silently leaving a profile rule ineffective.
pub fn plan_tunnel_routes_with_bypass(
    baseline: &NetworkBaseline,
    tun: &TunIdentity,
    upstream_address: IpAddr,
    include_ipv6: bool,
    bypass_cidrs: &[String],
) -> Result<Vec<RouteDelta>, SnapshotError> {
    if baseline.default_interface_index == 0
        || tun.interface_index == 0
        || !valid_utun_name(&tun.interface_name)
        || upstream_address.is_unspecified()
        || upstream_address.is_multicast()
    {
        return Err(SnapshotError::Invalid);
    }

    let mut tunnel_routes = vec![
        route(Ipv4Addr::UNSPECIFIED.into(), 1, None, tun.interface_index),
        route(
            Ipv4Addr::new(128, 0, 0, 0).into(),
            1,
            None,
            tun.interface_index,
        ),
    ];
    if include_ipv6 {
        tunnel_routes.extend([
            route(Ipv6Addr::UNSPECIFIED.into(), 1, None, tun.interface_index),
            route(
                Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(),
                1,
                None,
                tun.interface_index,
            ),
        ]);
    }

    let mut bypass_routes = Vec::new();
    if !upstream_address.is_loopback() {
        if upstream_address.is_ipv4() != baseline.default_gateway.is_ipv4() {
            return Err(SnapshotError::Invalid);
        }
        bypass_routes.push(route(
            upstream_address,
            if upstream_address.is_ipv4() { 32 } else { 128 },
            Some(baseline.default_gateway),
            baseline.default_interface_index,
        ));
    }

    for cidr in bypass_cidrs {
        let (destination, prefix_length) = parse_bypass_cidr(cidr)?;
        if destination.is_ipv4() != baseline.default_gateway.is_ipv4()
            || prefix_length < 2
            || destination.is_unspecified()
            || destination.is_multicast()
        {
            return Err(SnapshotError::Invalid);
        }
        bypass_routes.push(route(
            destination,
            prefix_length,
            Some(baseline.default_gateway),
            baseline.default_interface_index,
        ));
    }
    // The split routes below are more specific than the unscoped default, so
    // without a default scoped to the physical interface every socket bound
    // to it (the engine's DIRECT outbound, clients pinned to the primary
    // interface) fails with ENETUNREACH. Unscoped traffic never uses it.
    bypass_routes.push(RouteDelta {
        interface_scoped: true,
        ..route(
            unspecified(baseline.default_gateway),
            0,
            Some(baseline.default_gateway),
            baseline.default_interface_index,
        )
    });
    // Physical escape routes must exist before split-default capture is
    // installed, otherwise the verified loopback proxy can recursively enter
    // the new TUN during the route-application window.
    bypass_routes.extend(tunnel_routes);
    let routes = bypass_routes;
    validate_unique_routes(&routes, MAX_OWNED_ROUTES)?;
    Ok(routes)
}

fn unspecified(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

fn parse_bypass_cidr(value: &str) -> Result<(IpAddr, u8), SnapshotError> {
    let (address, prefix) = value.split_once('/').ok_or(SnapshotError::Invalid)?;
    if value.matches('/').count() != 1 || address.is_empty() || prefix.is_empty() {
        return Err(SnapshotError::Invalid);
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| SnapshotError::Invalid)?;
    let prefix = prefix.parse::<u8>().map_err(|_| SnapshotError::Invalid)?;
    let canonical = match address {
        IpAddr::V4(address) if prefix <= 32 => IpAddr::V4(canonical_v4_network(address, prefix)),
        IpAddr::V6(address) if prefix <= 128 => IpAddr::V6(canonical_v6_network(address, prefix)),
        _ => return Err(SnapshotError::Invalid),
    };
    Ok((canonical, prefix))
}

pub fn classify_routes(
    baseline_sha256: &str,
    planned: &[RouteDelta],
    snapshot: &RouteSnapshot,
) -> Result<DeltaFact, SnapshotError> {
    if !snapshot.complete {
        return Ok(DeltaFact::Unknown);
    }
    if snapshot.routes.len() > MAX_SNAPSHOT_ROUTES
        || !valid_digest(baseline_sha256)
        || planned.is_empty()
    {
        return Err(SnapshotError::Invalid);
    }
    validate_unique_routes(planned, MAX_OWNED_ROUTES)?;
    validate_unique_routes(&snapshot.routes, MAX_SNAPSHOT_ROUTES)?;

    let planned_set = route_set(planned);
    let observed_set = route_set(&snapshot.routes);
    if has_conflicting_owned_key(&planned_set, &observed_set) {
        return Ok(DeltaFact::Drifted);
    }
    let applied = planned_set.intersection(&observed_set).count();
    if applied == planned_set.len() {
        return Ok(DeltaFact::AppliedExact);
    }
    if applied > 0 {
        return Ok(DeltaFact::AppliedSubset);
    }
    // Recovery owns only the exact destination/prefix keys in `planned`.
    // Kernel-connected TUN routes and unrelated routes may legitimately appear
    // after the pre-TUN baseline was captured; neither authorizes touching them.
    Ok(DeltaFact::Restored)
}

pub fn classify_dns(
    baseline: &DnsBaseline,
    planned_sha256: &str,
    snapshot: &DnsSnapshot,
) -> Result<DeltaFact, SnapshotError> {
    if !snapshot.complete {
        return Ok(DeltaFact::Unknown);
    }
    if !valid_digest(planned_sha256) {
        return Err(SnapshotError::Invalid);
    }
    if snapshot.network_service_id != baseline.network_service_id {
        return Ok(DeltaFact::Drifted);
    }
    let current = dns_snapshot_sha256(snapshot)?;
    if current == dns_baseline_sha256(baseline)? {
        Ok(DeltaFact::Restored)
    } else if current == planned_sha256 {
        Ok(DeltaFact::AppliedExact)
    } else {
        Ok(DeltaFact::Drifted)
    }
}

pub fn classify_tun(
    expected: &TunIdentity,
    snapshot: &InterfaceSnapshot,
) -> Result<IdentityFact, SnapshotError> {
    if !snapshot.complete {
        return Ok(IdentityFact::Unknown);
    }
    if snapshot.interfaces.len() > MAX_INTERFACES
        || expected.interface_index == 0
        || !valid_utun_name(&expected.interface_name)
    {
        return Err(SnapshotError::Invalid);
    }

    let mut identities = BTreeSet::new();
    for interface in &snapshot.interfaces {
        if interface.index == 0
            || interface.name.is_empty()
            || !identities.insert((interface.index, interface.name.as_str()))
        {
            return Err(SnapshotError::Ambiguous);
        }
    }

    let collision = snapshot.interfaces.iter().find(|interface| {
        interface.index == expected.interface_index || interface.name == expected.interface_name
    });
    match collision {
        Some(interface)
            if interface.index == expected.interface_index
                && interface.name == expected.interface_name
                && interface.owner_pid == Some(expected.engine_pid) =>
        {
            Ok(IdentityFact::Exact)
        }
        Some(interface) if interface.owner_pid.is_none() => Ok(IdentityFact::Unknown),
        Some(_) => Ok(IdentityFact::Mismatch),
        None => Ok(IdentityFact::Absent),
    }
}

pub fn route_snapshot_sha256(snapshot: &RouteSnapshot) -> Result<String, SnapshotError> {
    if !snapshot.complete || snapshot.routes.len() > MAX_SNAPSHOT_ROUTES {
        return Err(SnapshotError::Incomplete);
    }
    validate_unique_routes(&snapshot.routes, MAX_SNAPSHOT_ROUTES)?;
    let mut entries: Vec<String> = snapshot.routes.iter().map(canonical_route).collect();
    entries.sort_unstable();
    Ok(digest_lines(entries.iter().map(String::as_str)))
}

pub fn dns_baseline_sha256(baseline: &DnsBaseline) -> Result<String, SnapshotError> {
    dns_values_sha256(
        &baseline.network_service_id,
        &baseline.mode,
        &baseline.servers,
        &baseline.search_domains,
    )
}

pub fn dns_snapshot_sha256(snapshot: &DnsSnapshot) -> Result<String, SnapshotError> {
    if !snapshot.complete {
        return Err(SnapshotError::Incomplete);
    }
    dns_values_sha256(
        &snapshot.network_service_id,
        &snapshot.mode,
        &snapshot.servers,
        &snapshot.search_domains,
    )
}

fn dns_values_sha256(
    service_id: &str,
    mode: &DnsConfigurationMode,
    servers: &[IpAddr],
    domains: &[String],
) -> Result<String, SnapshotError> {
    if service_id.is_empty()
        || service_id.len() > 128
        || service_id.chars().any(char::is_control)
        || servers.len() > 8
        || domains.len() > 16
        || servers
            .iter()
            .any(|server| server.is_unspecified() || server.is_multicast())
        || match mode {
            DnsConfigurationMode::Automatic => !servers.is_empty() || !domains.is_empty(),
            DnsConfigurationMode::Manual => servers.is_empty() && domains.is_empty(),
        }
        || domains.iter().any(|domain| {
            domain.is_empty()
                || domain.len() > 253
                || !domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
    {
        return Err(SnapshotError::Invalid);
    }
    let mut lines = vec![
        format!("service={service_id}"),
        format!(
            "mode={}",
            match mode {
                DnsConfigurationMode::Automatic => "automatic",
                DnsConfigurationMode::Manual => "manual",
            }
        ),
    ];
    lines.extend(servers.iter().map(|server| format!("server={server}")));
    lines.extend(domains.iter().map(|domain| format!("domain={domain}")));
    Ok(digest_lines(lines.iter().map(String::as_str)))
}

fn route(
    destination: IpAddr,
    prefix_length: u8,
    gateway: Option<IpAddr>,
    interface_index: u32,
) -> RouteDelta {
    RouteDelta {
        destination,
        prefix_length,
        gateway,
        interface_index,
        interface_scoped: false,
    }
}

fn validate_unique_routes(routes: &[RouteDelta], maximum: usize) -> Result<(), SnapshotError> {
    if routes.len() > maximum {
        return Err(SnapshotError::Invalid);
    }
    let mut exact = BTreeSet::new();
    for route in routes {
        if !valid_route(route) || !exact.insert(canonical_route(route)) {
            return Err(SnapshotError::Invalid);
        }
    }
    Ok(())
}

fn valid_route(route: &RouteDelta) -> bool {
    route.interface_index > 0
        && match route.destination {
            IpAddr::V4(address) => {
                route.prefix_length <= 32
                    && canonical_v4_network(address, route.prefix_length) == address
            }
            IpAddr::V6(address) => {
                route.prefix_length <= 128
                    && canonical_v6_network(address, route.prefix_length) == address
            }
        }
        && route
            .gateway
            .is_none_or(|gateway| gateway.is_ipv4() == route.destination.is_ipv4())
}

fn canonical_v4_network(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn canonical_v6_network(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

fn valid_utun_name(name: &str) -> bool {
    name.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn route_set(routes: &[RouteDelta]) -> BTreeSet<String> {
    routes.iter().map(canonical_route).collect()
}

fn canonical_route(route: &RouteDelta) -> String {
    // The scope is part of the routing key: a scoped default coexists with
    // the unscoped system default instead of replacing it.
    let scope = if route.interface_scoped {
        format!("%{}", route.interface_index)
    } else {
        String::new()
    };
    format!(
        "{}/{}{}|{}|{}",
        route.destination,
        route.prefix_length,
        scope,
        route
            .gateway
            .map_or_else(|| "-".into(), |value| value.to_string()),
        route.interface_index
    )
}

fn route_key(canonical: &str) -> &str {
    canonical.split_once('|').map_or(canonical, |(key, _)| key)
}

fn has_conflicting_owned_key(planned: &BTreeSet<String>, observed: &BTreeSet<String>) -> bool {
    planned.iter().any(|owned| {
        observed
            .iter()
            .any(|candidate| route_key(candidate) == route_key(owned) && candidate != owned)
    })
}

fn digest_lines<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for line in lines {
        digest.update((line.len() as u64).to_be_bytes());
        digest.update(line.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> NetworkBaseline {
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: "192.0.2.1".parse().unwrap(),
            routes_sha256: "a".repeat(64),
            preexisting_utuns: Vec::new(),
            dns: DnsBaseline {
                network_service_id: "wifi-service-id".into(),
                mode: DnsConfigurationMode::Manual,
                servers: vec!["192.0.2.53".parse().unwrap()],
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

    #[test]
    fn route_plan_uses_split_defaults_and_exact_physical_bypass() {
        let routes =
            plan_tunnel_routes(&baseline(), &tun(), "198.51.100.7".parse().unwrap(), true).unwrap();
        assert_eq!(routes.len(), 6);
        assert_eq!(routes[0].prefix_length, 32);
        assert_eq!(routes[0].gateway, Some(baseline().default_gateway));
        assert_eq!(
            routes[1],
            RouteDelta {
                destination: "0.0.0.0".parse().unwrap(),
                prefix_length: 0,
                gateway: Some(baseline().default_gateway),
                interface_index: baseline().default_interface_index,
                interface_scoped: true,
            }
        );
        assert_eq!(routes[2].destination, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(
            routes[3].destination,
            "128.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(routes[4].destination, "::".parse::<IpAddr>().unwrap());
        assert_eq!(routes[5].destination, "8000::".parse::<IpAddr>().unwrap());
        assert!(routes
            .iter()
            .filter(|route| route.prefix_length == 1)
            .all(|route| !route.interface_scoped));
    }

    #[test]
    fn route_plan_adds_profile_bypass_cidrs_on_the_physical_default() {
        let bypass = vec!["104.20.23.154/32".into(), "10.20.0.0/16".into()];
        let routes = plan_tunnel_routes_with_bypass(
            &baseline(),
            &tun(),
            "127.0.0.1".parse().unwrap(),
            true,
            &bypass,
        )
        .unwrap();
        assert_eq!(routes.len(), 7);
        assert_eq!(
            routes[0].destination,
            "104.20.23.154".parse::<IpAddr>().unwrap()
        );
        assert_eq!(routes[0].prefix_length, 32);
        assert_eq!(routes[0].gateway, Some(baseline().default_gateway));
        assert_eq!(
            routes[0].interface_index,
            baseline().default_interface_index
        );
        assert_eq!(
            routes[1].destination,
            "10.20.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(routes[1].prefix_length, 16);
    }

    #[test]
    fn route_plan_rejects_unsafe_or_unroutable_bypass_cidrs() {
        for bypass in ["0.0.0.0/0", "128.0.0.0/1", "fd00::/8", "192.0.2.1"] {
            assert_eq!(
                plan_tunnel_routes_with_bypass(
                    &baseline(),
                    &tun(),
                    "127.0.0.1".parse().unwrap(),
                    true,
                    &[bypass.into()],
                ),
                Err(SnapshotError::Invalid)
            );
        }
    }

    #[test]
    fn loopback_upstream_needs_no_bypass_and_family_mismatch_fails_closed() {
        let routes =
            plan_tunnel_routes(&baseline(), &tun(), "127.0.0.1".parse().unwrap(), false).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(
            plan_tunnel_routes(&baseline(), &tun(), "2001:db8::1".parse().unwrap(), true),
            Err(SnapshotError::Invalid)
        );
    }

    #[test]
    fn route_observer_distinguishes_restored_exact_subset_and_conflict() {
        let planned =
            plan_tunnel_routes(&baseline(), &tun(), "127.0.0.1".parse().unwrap(), false).unwrap();
        let restored = RouteSnapshot {
            complete: true,
            routes: vec![route(
                "192.0.2.0".parse().unwrap(),
                24,
                None,
                baseline().default_interface_index,
            )],
        };
        let baseline_hash = route_snapshot_sha256(&restored).unwrap();
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &restored).unwrap(),
            DeltaFact::Restored
        );
        let mut restored_with_unowned_route = restored.clone();
        restored_with_unowned_route.routes.push(route(
            "198.18.0.1".parse().unwrap(),
            32,
            None,
            tun().interface_index,
        ));
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &restored_with_unowned_route).unwrap(),
            DeltaFact::Restored
        );

        let exact = RouteSnapshot {
            complete: true,
            routes: planned.clone(),
        };
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &exact).unwrap(),
            DeltaFact::AppliedExact
        );
        let subset = RouteSnapshot {
            complete: true,
            routes: vec![planned[0].clone()],
        };
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &subset).unwrap(),
            DeltaFact::AppliedSubset
        );
        let conflict = RouteSnapshot {
            complete: true,
            routes: vec![route(
                planned[1].destination,
                planned[1].prefix_length,
                Some("192.0.2.1".parse().unwrap()),
                9,
            )],
        };
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &conflict).unwrap(),
            DeltaFact::Drifted
        );
        // The unscoped system default shares the destination of the owned
        // scoped default but is a different routing key.
        let system_default = RouteSnapshot {
            complete: true,
            routes: vec![route(
                "0.0.0.0".parse().unwrap(),
                0,
                Some(baseline().default_gateway),
                baseline().default_interface_index,
            )],
        };
        assert_eq!(
            classify_routes(&baseline_hash, &planned, &system_default).unwrap(),
            DeltaFact::Restored
        );
    }

    #[test]
    fn incomplete_or_duplicate_route_snapshots_never_authorize_cleanup() {
        let planned =
            plan_tunnel_routes(&baseline(), &tun(), "127.0.0.1".parse().unwrap(), false).unwrap();
        assert_eq!(
            classify_routes(
                &"a".repeat(64),
                &planned,
                &RouteSnapshot {
                    complete: false,
                    routes: Vec::new()
                }
            )
            .unwrap(),
            DeltaFact::Unknown
        );
        assert_eq!(
            classify_routes(
                &"a".repeat(64),
                &planned,
                &RouteSnapshot {
                    complete: true,
                    routes: vec![planned[0].clone(), planned[0].clone()]
                }
            ),
            Err(SnapshotError::Invalid)
        );
        assert_eq!(
            route_snapshot_sha256(&RouteSnapshot {
                complete: true,
                routes: vec![route("192.0.2.7".parse().unwrap(), 24, None, 9)],
            }),
            Err(SnapshotError::Invalid)
        );
    }

    #[test]
    fn dns_is_scoped_to_exact_service_and_canonical_state() {
        let baseline = baseline().dns;
        let restored = DnsSnapshot {
            complete: true,
            network_service_id: baseline.network_service_id.clone(),
            mode: baseline.mode.clone(),
            servers: baseline.servers.clone(),
            search_domains: baseline.search_domains.clone(),
        };
        let planned = DnsSnapshot {
            servers: vec!["198.18.0.1".parse().unwrap()],
            search_domains: Vec::new(),
            ..restored.clone()
        };
        let planned_hash = dns_snapshot_sha256(&planned).unwrap();
        assert_eq!(
            classify_dns(&baseline, &planned_hash, &restored).unwrap(),
            DeltaFact::Restored
        );
        assert_eq!(
            classify_dns(&baseline, &planned_hash, &planned).unwrap(),
            DeltaFact::AppliedExact
        );
        let foreign = DnsSnapshot {
            network_service_id: "ethernet-service-id".into(),
            ..planned
        };
        assert_eq!(
            classify_dns(&baseline, &planned_hash, &foreign).unwrap(),
            DeltaFact::Drifted
        );

        let automatic = DnsSnapshot {
            complete: true,
            network_service_id: baseline.network_service_id.clone(),
            mode: DnsConfigurationMode::Automatic,
            servers: Vec::new(),
            search_domains: Vec::new(),
        };
        assert_ne!(
            dns_snapshot_sha256(&automatic).unwrap(),
            dns_snapshot_sha256(&restored).unwrap()
        );
        assert_eq!(
            dns_snapshot_sha256(&DnsSnapshot {
                servers: baseline.servers,
                ..automatic
            }),
            Err(SnapshotError::Invalid)
        );
    }

    #[test]
    fn utun_requires_name_index_and_engine_pid_to_match() {
        let exact = InterfaceSnapshot {
            complete: true,
            interfaces: vec![DarwinInterface {
                name: "utun7".into(),
                index: 17,
                owner_pid: Some(700),
            }],
        };
        assert_eq!(classify_tun(&tun(), &exact).unwrap(), IdentityFact::Exact);

        let reused = InterfaceSnapshot {
            complete: true,
            interfaces: vec![DarwinInterface {
                owner_pid: Some(701),
                ..exact.interfaces[0].clone()
            }],
        };
        assert_eq!(
            classify_tun(&tun(), &reused).unwrap(),
            IdentityFact::Mismatch
        );
        let unowned = InterfaceSnapshot {
            complete: true,
            interfaces: vec![DarwinInterface {
                owner_pid: None,
                ..exact.interfaces[0].clone()
            }],
        };
        assert_eq!(
            classify_tun(&tun(), &unowned).unwrap(),
            IdentityFact::Unknown
        );
    }
}
