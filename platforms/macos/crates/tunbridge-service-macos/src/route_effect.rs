//! Syscall-free Darwin routing message encoder.
//!
//! This module only creates bounded RTM_ADD/RTM_DELETE frames. It never opens a
//! routing socket or applies a network change.

use crate::lifecycle_plan::RouteDelta;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER_BYTES: usize = 92;
const RTM_VERSION: u8 = 5;
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTA_DST_GATEWAY_NETMASK: i32 = 0x7;
const RTA_DST_GATEWAY: i32 = 0x3;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_HOST: i32 = 0x4;
const RTF_STATIC: i32 = 0x800;
const RTF_IFSCOPE: i32 = 0x100_0000;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;
const MAX_MESSAGE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteEffectOperation {
    Add,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEffectRequest {
    pub operation: RouteEffectOperation,
    pub route: RouteDelta,
    pub sequence: u32,
    pub sender_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteEffectError {
    Invalid,
    Oversize,
}

pub fn encode_route_effect(request: &RouteEffectRequest) -> Result<Vec<u8>, RouteEffectError> {
    encode_route_effect_with_link_gateway(request, None)
}

pub(crate) fn encode_route_effect_with_link_gateway(
    request: &RouteEffectRequest,
    link_gateway: Option<&[u8]>,
) -> Result<Vec<u8>, RouteEffectError> {
    validate_request(request)?;
    if link_gateway.is_some_and(|value| {
        value.len() < 8
            || value.len() > 32
            || usize::from(value[0]) != value.len()
            || value[1] != AF_LINK
            || u16::from_ne_bytes([value[2], value[3]]) != request.route.interface_index as u16
    }) {
        return Err(RouteEffectError::Invalid);
    }
    let host = match request.route.destination {
        IpAddr::V4(_) => request.route.prefix_length == 32,
        IpAddr::V6(_) => request.route.prefix_length == 128,
    };
    let mut message = vec![0_u8; HEADER_BYTES];
    message[2] = RTM_VERSION;
    message[3] = match request.operation {
        RouteEffectOperation::Add => RTM_ADD,
        RouteEffectOperation::Delete => RTM_DELETE,
    };
    message[4..6].copy_from_slice(&(request.route.interface_index as u16).to_ne_bytes());
    let mut flags = RTF_UP | RTF_STATIC;
    if request.route.gateway.is_some() {
        flags |= RTF_GATEWAY;
    }
    if host {
        flags |= RTF_HOST;
    }
    if request.route.interface_scoped {
        // rtm_index above names the scope for both add and delete.
        flags |= RTF_IFSCOPE;
    }
    message[8..12].copy_from_slice(&flags.to_ne_bytes());
    message[12..16].copy_from_slice(
        &(if host {
            RTA_DST_GATEWAY
        } else {
            RTA_DST_GATEWAY_NETMASK
        })
        .to_ne_bytes(),
    );
    message[16..20].copy_from_slice(&(request.sender_pid as i32).to_ne_bytes());
    message[20..24].copy_from_slice(&(request.sequence as i32).to_ne_bytes());

    push_sockaddr(&mut message, destination_sockaddr(&request.route)?)?;
    push_sockaddr(
        &mut message,
        gateway_sockaddr(&request.route, link_gateway)?,
    )?;
    if !host {
        push_sockaddr(&mut message, netmask_sockaddr(&request.route)?)?;
    }
    if message.len() > MAX_MESSAGE_BYTES || message.len() > u16::MAX as usize {
        return Err(RouteEffectError::Oversize);
    }
    let length = message.len() as u16;
    message[0..2].copy_from_slice(&length.to_ne_bytes());
    Ok(message)
}

fn validate_request(request: &RouteEffectRequest) -> Result<(), RouteEffectError> {
    if request.sequence == 0
        || request.sequence > i32::MAX as u32
        || request.sender_pid <= 1
        || request.sender_pid > i32::MAX as u32
        || request.route.interface_index == 0
        || request.route.interface_index > u16::MAX as u32
    {
        return Err(RouteEffectError::Invalid);
    }
    let canonical = match request.route.destination {
        IpAddr::V4(address) if request.route.prefix_length <= 32 => {
            canonical_v4(address, request.route.prefix_length) == address
        }
        IpAddr::V6(address) if request.route.prefix_length <= 128 => {
            canonical_v6(address, request.route.prefix_length) == address
        }
        _ => false,
    };
    if !canonical
        || request.route.gateway.is_some_and(|gateway| {
            gateway.is_ipv4() != request.route.destination.is_ipv4()
                || gateway.is_unspecified()
                || gateway.is_multicast()
        })
    {
        return Err(RouteEffectError::Invalid);
    }
    Ok(())
}

fn destination_sockaddr(route: &RouteDelta) -> Result<Vec<u8>, RouteEffectError> {
    ip_sockaddr(route.destination, route.interface_index)
}

fn gateway_sockaddr(
    route: &RouteDelta,
    link_gateway: Option<&[u8]>,
) -> Result<Vec<u8>, RouteEffectError> {
    match route.gateway {
        Some(gateway) => ip_sockaddr(gateway, route.interface_index),
        None => {
            if let Some(value) = link_gateway {
                return Ok(value.to_vec());
            }
            let mut value = vec![0_u8; 8];
            value[0] = 8;
            value[1] = AF_LINK;
            value[2..4].copy_from_slice(&(route.interface_index as u16).to_ne_bytes());
            Ok(value)
        }
    }
}

fn ip_sockaddr(address: IpAddr, interface_index: u32) -> Result<Vec<u8>, RouteEffectError> {
    match address {
        IpAddr::V4(address) => {
            let mut value = vec![0_u8; 16];
            value[0] = 16;
            value[1] = AF_INET;
            value[4..8].copy_from_slice(&address.octets());
            Ok(value)
        }
        IpAddr::V6(address) => {
            let mut bytes = address.octets();
            if address.is_unicast_link_local() {
                bytes[2..4].copy_from_slice(&(interface_index as u16).to_be_bytes());
            }
            let mut value = vec![0_u8; 28];
            value[0] = 28;
            value[1] = AF_INET6;
            value[8..24].copy_from_slice(&bytes);
            Ok(value)
        }
    }
}

fn netmask_sockaddr(route: &RouteDelta) -> Result<Vec<u8>, RouteEffectError> {
    if route.prefix_length == 0 {
        return Ok(vec![0_u8; 4]);
    }
    let (structural, width) = if route.destination.is_ipv4() {
        // A compact sockaddr_in netmask keeps sin_len plus the three bytes
        // preceding sin_addr, then trims trailing zero address bytes.
        (3, 4)
    } else {
        (7, 16)
    };
    let mask_bytes = usize::from(route.prefix_length).div_ceil(8);
    let mut value = vec![0_u8; 1 + structural + mask_bytes];
    value[1 + structural..].fill(0xff);
    value[0] = value.len() as u8;
    let remainder = route.prefix_length % 8;
    if remainder != 0 {
        let last = value.len() - 1;
        value[last] = u8::MAX << (8 - remainder);
    }
    if mask_bytes > width {
        return Err(RouteEffectError::Invalid);
    }
    Ok(value)
}

fn push_sockaddr(message: &mut Vec<u8>, value: Vec<u8>) -> Result<(), RouteEffectError> {
    let padded = value
        .len()
        .checked_add(3)
        .ok_or(RouteEffectError::Oversize)?
        & !3;
    message.extend_from_slice(&value);
    message.resize(
        message
            .len()
            .checked_add(padded - value.len())
            .ok_or(RouteEffectError::Oversize)?,
        0,
    );
    Ok(())
}

fn canonical_v4(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn canonical_v6(address: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_message::decode_route_messages;

    fn request(route: RouteDelta) -> RouteEffectRequest {
        RouteEffectRequest {
            operation: RouteEffectOperation::Add,
            route,
            sequence: 7,
            sender_pid: 500,
        }
    }

    fn round_trip(mut encoded: Vec<u8>) -> RouteDelta {
        encoded[3] = 0x14;
        decode_route_messages(&encoded).unwrap().routes.remove(0)
    }

    #[test]
    fn encodes_ipv4_split_default_and_host_bypass() {
        let split = RouteDelta {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 1,
            gateway: None,
            interface_index: 17,
            interface_scoped: false,
        };
        let encoded = encode_route_effect(&request(split.clone())).unwrap();
        assert_eq!(encoded[3], RTM_ADD);
        assert_eq!(&encoded[116..124], &[5, 0, 0, 0, 128, 0, 0, 0]);
        assert_eq!(round_trip(encoded), split);

        let bypass = RouteDelta {
            destination: "198.51.100.7".parse().unwrap(),
            prefix_length: 32,
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface_index: 9,
            interface_scoped: false,
        };
        let mut delete = request(bypass.clone());
        delete.operation = RouteEffectOperation::Delete;
        let encoded = encode_route_effect(&delete).unwrap();
        assert_eq!(encoded[3], RTM_DELETE);
        assert_eq!(round_trip(encoded), bypass);
    }

    #[test]
    fn encodes_interface_scoped_default_for_add_and_delete() {
        let scoped = RouteDelta {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface_index: 9,
            interface_scoped: true,
        };
        for operation in [RouteEffectOperation::Add, RouteEffectOperation::Delete] {
            let mut effect = request(scoped.clone());
            effect.operation = operation;
            let encoded = encode_route_effect(&effect).unwrap();
            assert_eq!(u16::from_ne_bytes([encoded[4], encoded[5]]), 9);
            let flags = i32::from_ne_bytes(encoded[8..12].try_into().unwrap());
            assert_eq!(flags & RTF_IFSCOPE, RTF_IFSCOPE);
            assert_eq!(round_trip(encoded), scoped);
        }

        let mut unscoped = scoped;
        unscoped.interface_scoped = false;
        let encoded = encode_route_effect(&request(unscoped)).unwrap();
        let flags = i32::from_ne_bytes(encoded[8..12].try_into().unwrap());
        assert_eq!(flags & RTF_IFSCOPE, 0);
    }

    #[test]
    fn encodes_ipv6_split_and_scope_bound_gateway() {
        let split = RouteDelta {
            destination: "8000::".parse().unwrap(),
            prefix_length: 1,
            gateway: None,
            interface_index: 17,
            interface_scoped: false,
        };
        assert_eq!(
            round_trip(encode_route_effect(&request(split.clone())).unwrap()),
            split
        );

        let scoped = RouteDelta {
            destination: "2001:db8::1".parse().unwrap(),
            prefix_length: 128,
            gateway: Some("fe80::1".parse().unwrap()),
            interface_index: 17,
            interface_scoped: false,
        };
        assert_eq!(
            round_trip(encode_route_effect(&request(scoped.clone())).unwrap()),
            scoped
        );
    }

    #[test]
    fn rejects_noncanonical_cross_family_and_unbound_requests() {
        let base = RouteDelta {
            destination: "192.0.2.7".parse().unwrap(),
            prefix_length: 24,
            gateway: None,
            interface_index: 17,
            interface_scoped: false,
        };
        assert_eq!(
            encode_route_effect(&request(base.clone())),
            Err(RouteEffectError::Invalid)
        );
        let mut cross_family = base;
        cross_family.destination = "192.0.2.0".parse().unwrap();
        cross_family.gateway = Some("2001:db8::1".parse().unwrap());
        assert_eq!(
            encode_route_effect(&request(cross_family)),
            Err(RouteEffectError::Invalid)
        );
        let mut unbound = request(RouteDelta {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 1,
            gateway: None,
            interface_index: 17,
            interface_scoped: false,
        });
        unbound.sequence = 0;
        assert_eq!(
            encode_route_effect(&unbound),
            Err(RouteEffectError::Invalid)
        );
    }
}
