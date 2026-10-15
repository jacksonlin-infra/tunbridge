use crate::upstream::{normalize_remote_host, Endpoint, IpPreference};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};
use thiserror::Error;

pub const MAX_RESOLVED_ADDRESSES: usize = 8;
pub const NETWORK_GENERATION_HEX_BYTES: usize = 64;
pub const OWNERSHIP_TOKEN_HEX_BYTES: usize = 32;

pub fn ordered_candidates(
    endpoint: &Endpoint,
    resolved: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<IpAddr>, RemoteResolutionError> {
    endpoint
        .validate()
        .map_err(|_| RemoteResolutionError::InvalidEndpoint)?;

    if let Some(literal) = endpoint.literal_address() {
        if address_matches_preference(literal, endpoint.ip_preference) {
            return Ok(vec![literal]);
        }
        return Err(RemoteResolutionError::AddressFamilyUnavailable);
    }

    let mut unique = BTreeSet::new();
    for address in resolved {
        normalize_remote_host(&address.to_string())
            .map_err(|_| RemoteResolutionError::DisallowedAddress)?;
        unique.insert(address);
        if unique.len() > MAX_RESOLVED_ADDRESSES {
            return Err(RemoteResolutionError::TooManyAddresses);
        }
    }
    if unique.is_empty() {
        return Err(RemoteResolutionError::NoAddresses);
    }

    let mut addresses: Vec<IpAddr> = unique
        .into_iter()
        .filter(|address| address_matches_preference(*address, endpoint.ip_preference))
        .collect();
    if addresses.is_empty() {
        return Err(RemoteResolutionError::AddressFamilyUnavailable);
    }
    addresses.sort_by_key(|address| preference_rank(*address, endpoint.ip_preference));
    Ok(addresses)
}

/// Resolve a single saved endpoint through the operating system resolver.
/// Callers must invoke this before installing TUN routes, then pin one returned
/// address for both configuration rendering and transport escape.
pub fn resolve_endpoint_system(endpoint: &Endpoint) -> Result<Vec<IpAddr>, RemoteResolutionError> {
    endpoint
        .validate()
        .map_err(|_| RemoteResolutionError::InvalidEndpoint)?;
    if let Some(literal) = endpoint.literal_address() {
        return ordered_candidates(endpoint, [literal]);
    }
    let resolved = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|_| RemoteResolutionError::ResolutionUnavailable)?
        .map(|address| address.ip());
    ordered_candidates(endpoint, resolved)
}

/// Prove basic transport reachability to the pinned endpoint before TUN
/// routes are installed. Protocol, authentication, and TLS validation remain
/// the engine's responsibility; this check only prevents entering TUN startup
/// with an already unreachable TCP endpoint.
pub fn preflight_pinned_tcp(
    address: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<(), RemoteResolutionError> {
    normalize_remote_host(&address.to_string())
        .map_err(|_| RemoteResolutionError::DisallowedAddress)?;
    if port == 0 || timeout.is_zero() || timeout > Duration::from_secs(10) {
        return Err(RemoteResolutionError::InvalidEndpoint);
    }
    TcpStream::connect_timeout(&SocketAddr::new(address, port), timeout)
        .map(|_| ())
        .map_err(|_| RemoteResolutionError::EndpointUnavailable)
}

fn address_matches_preference(address: IpAddr, preference: IpPreference) -> bool {
    match preference {
        IpPreference::Ipv4 => address.is_ipv4(),
        IpPreference::Ipv6 => address.is_ipv6(),
        IpPreference::Ipv4Prefer | IpPreference::Ipv6Prefer => true,
    }
}

fn preference_rank(address: IpAddr, preference: IpPreference) -> u8 {
    match (preference, address) {
        (IpPreference::Ipv4Prefer, IpAddr::V4(_)) | (IpPreference::Ipv6Prefer, IpAddr::V6(_)) => 0,
        _ => 1,
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhysicalEgress {
    pub interface_index: u32,
    pub interface_name: Option<String>,
    pub gateway: IpAddr,
    pub route_generation: String,
    pub dns_generation: String,
}

impl PhysicalEgress {
    pub fn validate_for(&self, endpoint: IpAddr) -> Result<(), RemoteResolutionError> {
        if self.interface_index == 0
            || self.gateway.is_unspecified()
            || self.gateway.is_multicast()
            || self.gateway.is_ipv4() != endpoint.is_ipv4()
            || !valid_generation(&self.route_generation)
            || !valid_generation(&self.dns_generation)
            || self
                .interface_name
                .as_deref()
                .is_some_and(|name| !valid_interface_name(name))
        {
            return Err(RemoteResolutionError::InvalidPhysicalEgress);
        }
        Ok(())
    }
}

impl fmt::Debug for PhysicalEgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhysicalEgress")
            .field("interface_index", &self.interface_index)
            .field("interface_name", &self.interface_name)
            .field("gateway", &"[REDACTED]")
            .field("route_generation", &"[REDACTED]")
            .field("dns_generation", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportEscapePlan {
    pub pinned_endpoint: IpAddr,
    pub endpoint_port: u16,
    pub endpoint_prefix: u8,
    pub physical_egress: PhysicalEgress,
    pub ownership_token: String,
}

impl TransportEscapePlan {
    pub fn new(
        pinned_endpoint: IpAddr,
        endpoint_port: u16,
        physical_egress: PhysicalEgress,
        ownership_token: String,
    ) -> Result<Self, RemoteResolutionError> {
        let plan = Self {
            pinned_endpoint,
            endpoint_port,
            endpoint_prefix: if pinned_endpoint.is_ipv4() { 32 } else { 128 },
            physical_egress,
            ownership_token,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), RemoteResolutionError> {
        normalize_remote_host(&self.pinned_endpoint.to_string())
            .map_err(|_| RemoteResolutionError::DisallowedAddress)?;
        if self.endpoint_port == 0
            || self.endpoint_prefix
                != if self.pinned_endpoint.is_ipv4() {
                    32
                } else {
                    128
                }
            || !valid_lower_hex(&self.ownership_token, OWNERSHIP_TOKEN_HEX_BYTES)
        {
            return Err(RemoteResolutionError::InvalidEscapePlan);
        }
        self.physical_egress.validate_for(self.pinned_endpoint)
    }

    pub fn endpoint_cidr(&self) -> String {
        format!("{}/{}", self.pinned_endpoint, self.endpoint_prefix)
    }
}

impl fmt::Debug for TransportEscapePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportEscapePlan")
            .field("pinned_endpoint", &"[REDACTED]")
            .field("endpoint_port", &self.endpoint_port)
            .field("endpoint_prefix", &self.endpoint_prefix)
            .field("physical_egress", &self.physical_egress)
            .field("ownership_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RemoteResolutionError {
    #[error("the remote endpoint is invalid")]
    InvalidEndpoint,
    #[error("the resolver returned no usable addresses")]
    NoAddresses,
    #[error("the operating system resolver is unavailable")]
    ResolutionUnavailable,
    #[error("the resolver returned too many addresses")]
    TooManyAddresses,
    #[error("the resolver returned a disallowed address")]
    DisallowedAddress,
    #[error("the requested address family is unavailable")]
    AddressFamilyUnavailable,
    #[error("the pinned remote endpoint is unavailable")]
    EndpointUnavailable,
    #[error("the physical egress identity is invalid")]
    InvalidPhysicalEgress,
    #[error("the transport escape plan is invalid")]
    InvalidEscapePlan,
}

fn valid_generation(value: &str) -> bool {
    valid_lower_hex(value, NETWORK_GENERATION_HEX_BYTES)
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::IpPreference;

    #[test]
    fn candidates_are_bounded_filtered_deduplicated_and_preferred() {
        let endpoint = Endpoint::new("proxy.example.com", 443, IpPreference::Ipv4Prefer).unwrap();
        let ordered = ordered_candidates(
            &endpoint,
            [
                "2001:4860:4860::8888".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(ordered[0], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(ordered.len(), 2);

        let too_many: Vec<IpAddr> = (1..=9)
            .map(|last| format!("10.0.0.{last}").parse().unwrap())
            .collect();
        assert_eq!(
            ordered_candidates(&endpoint, too_many).unwrap_err(),
            RemoteResolutionError::TooManyAddresses
        );
        assert_eq!(
            ordered_candidates(&endpoint, ["127.0.0.1".parse().unwrap()]).unwrap_err(),
            RemoteResolutionError::DisallowedAddress
        );
    }

    #[test]
    fn strict_family_preference_fails_closed() {
        let endpoint = Endpoint::new("proxy.example.com", 443, IpPreference::Ipv4).unwrap();
        assert_eq!(
            ordered_candidates(&endpoint, ["2001:4860:4860::8888".parse().unwrap()]).unwrap_err(),
            RemoteResolutionError::AddressFamilyUnavailable
        );
    }

    #[test]
    fn escape_plan_is_exact_and_debug_redacts_network_identity() {
        let egress = PhysicalEgress {
            interface_index: 4,
            interface_name: Some("en0".into()),
            gateway: "192.168.1.1".parse().unwrap(),
            route_generation: "a".repeat(64),
            dns_generation: "b".repeat(64),
        };
        let plan =
            TransportEscapePlan::new("8.8.8.8".parse().unwrap(), 443, egress, "c".repeat(32))
                .unwrap();
        assert_eq!(plan.endpoint_cidr(), "8.8.8.8/32");
        let debug = format!("{plan:?}");
        assert!(!debug.contains("8.8.8.8"));
        assert!(!debug.contains("192.168.1.1"));
        assert!(!debug.contains(&"a".repeat(64)));
    }

    #[test]
    fn escape_plan_rejects_family_mismatch_and_forged_owner() {
        let egress = PhysicalEgress {
            interface_index: 4,
            interface_name: Some("eth0".into()),
            gateway: "192.168.1.1".parse().unwrap(),
            route_generation: "a".repeat(64),
            dns_generation: "b".repeat(64),
        };
        assert!(TransportEscapePlan::new(
            "2001:4860:4860::8888".parse().unwrap(),
            443,
            egress.clone(),
            "c".repeat(32),
        )
        .is_err());
        assert!(TransportEscapePlan::new(
            "8.8.8.8".parse().unwrap(),
            443,
            egress,
            "not-hex".into(),
        )
        .is_err());
    }
}
