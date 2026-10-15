//! Bounded decoder for Darwin `NET_RT_DUMP`/`NET_RT_DUMP2` messages.
//!
//! The decoder is syscall-free. It accepts only complete RTM_GET/RTM_GET2
//! records and converts them to the canonical route model used by recovery.

use crate::{
    darwin_state::{route_snapshot_sha256, RouteSnapshot, SnapshotError},
    lifecycle_plan::RouteDelta,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RTM_HEADER_BYTES: usize = 92;
const RTM_VERSION: u8 = 5;
const RTM_GET: u8 = 0x4;
const RTM_GET2: u8 = 0x14;
const RTAX_MAX: usize = 8;
const RTAX_NETMASK: usize = 2;
const RTAX_IFP: usize = 5;
const RTA_DST: i32 = 1 << 0;
const RTF_UP: i32 = 0x1;
const RTF_HOST: i32 = 0x4;
const RTF_LLINFO: i32 = 0x400;
const RTF_IFSCOPE: i32 = 0x100_0000;
const RTF_WASCLONED: i32 = 0x20_000;
const RTF_LOCAL: i32 = 0x20_0000;
const RTF_BROADCAST: i32 = 0x40_0000;
const RTF_MULTICAST: i32 = 0x80_0000;
const RTF_CONDEMNED: i32 = 0x200_0000;
const RTF_DEAD: i32 = 0x2000_0000;
const EPHEMERAL_FLAGS: i32 = RTF_LLINFO
    | RTF_WASCLONED
    | RTF_LOCAL
    | RTF_BROADCAST
    | RTF_MULTICAST
    | RTF_CONDEMNED
    | RTF_DEAD;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;
const MAX_MESSAGES: usize = 4096;

#[repr(C)]
struct DarwinRtMetrics {
    values: [u32; 14],
}

#[repr(C)]
struct DarwinRtMessageHeader {
    message_length: u16,
    version: u8,
    message_type: u8,
    interface_index: u16,
    flags: i32,
    addrs: i32,
    process_or_reference: i32,
    sequence_or_parent_flags: i32,
    error_or_reserved: i32,
    use_count: i32,
    initialized_metrics: u32,
    metrics: DarwinRtMetrics,
}

const _: () = assert!(std::mem::size_of::<DarwinRtMessageHeader>() == RTM_HEADER_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMessageError {
    Truncated,
    Oversize,
    Unsupported,
    Invalid,
    Ambiguous,
}

pub fn decode_route_messages(bytes: &[u8]) -> Result<RouteSnapshot, RouteMessageError> {
    if bytes.is_empty() {
        return Err(RouteMessageError::Truncated);
    }
    if bytes.len() > MAX_DUMP_BYTES {
        return Err(RouteMessageError::Oversize);
    }
    let mut offset = 0;
    let mut count = 0;
    let mut routes = Vec::new();
    while offset < bytes.len() {
        count += 1;
        if count > MAX_MESSAGES || bytes.len() - offset < RTM_HEADER_BYTES {
            return Err(RouteMessageError::Truncated);
        }
        let message_length = read_u16(bytes, offset)? as usize;
        if message_length < RTM_HEADER_BYTES || message_length > bytes.len() - offset {
            return Err(RouteMessageError::Truncated);
        }
        let message = &bytes[offset..offset + message_length];
        if message[2] != RTM_VERSION || !matches!(message[3], RTM_GET | RTM_GET2) {
            return Err(RouteMessageError::Unsupported);
        }
        let interface_index = read_u16(message, 4)? as u32;
        let flags = read_i32(message, 8)?;
        let addrs = read_i32(message, 12)?;
        if interface_index == 0 || addrs < 0 || addrs & !0xff != 0 {
            return Err(RouteMessageError::Invalid);
        }
        if flags & RTF_UP != 0 && flags & EPHEMERAL_FLAGS == 0 {
            let route = decode_route(message, interface_index, flags, addrs)?;
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
        offset += message_length;
    }
    let snapshot = RouteSnapshot {
        complete: true,
        routes,
    };
    route_snapshot_sha256(&snapshot).map_err(map_snapshot_error)?;
    Ok(snapshot)
}

fn decode_route(
    message: &[u8],
    interface_index: u32,
    flags: i32,
    addrs: i32,
) -> Result<RouteDelta, RouteMessageError> {
    if addrs & RTA_DST == 0 {
        return Err(RouteMessageError::Invalid);
    }
    let slots = sockaddr_slots(message, addrs)?;
    let link_interface_index = match slots[1] {
        Some(value) if value.get(1) == Some(&AF_LINK) => parse_link_index(value)?,
        _ => None,
    };
    let ifp_interface_index = match slots[RTAX_IFP] {
        Some(value) if value.get(1) == Some(&AF_LINK) => parse_link_index(value)?,
        _ => None,
    };
    if link_interface_index.is_some()
        && ifp_interface_index.is_some()
        && link_interface_index != ifp_interface_index
    {
        return Err(RouteMessageError::Ambiguous);
    }
    let route_interface_index = link_interface_index
        .or(ifp_interface_index)
        .unwrap_or(interface_index);
    let destination = parse_ip(
        slots[0].ok_or(RouteMessageError::Invalid)?,
        Some(route_interface_index),
    )?;
    let prefix_length = if flags & RTF_HOST != 0 {
        if slots[2].is_some() {
            return Err(RouteMessageError::Ambiguous);
        }
        if destination.is_ipv4() {
            32
        } else {
            128
        }
    } else {
        parse_prefix(
            slots[2].ok_or(RouteMessageError::Invalid)?,
            destination.is_ipv4(),
        )?
    };
    if !canonical_destination(destination, prefix_length) {
        return Err(RouteMessageError::Invalid);
    }
    let gateway = match slots[1] {
        None => None,
        Some(value) if value[1] == AF_LINK => None,
        Some(value) => {
            let gateway = parse_ip(value, Some(route_interface_index))?;
            if gateway.is_ipv4() != destination.is_ipv4() {
                return Err(RouteMessageError::Invalid);
            }
            Some(gateway)
        }
    };
    Ok(RouteDelta {
        destination,
        prefix_length,
        gateway,
        interface_index: route_interface_index,
        interface_scoped: flags & RTF_IFSCOPE != 0,
    })
}

fn parse_link_index(sockaddr: &[u8]) -> Result<Option<u32>, RouteMessageError> {
    if sockaddr.len() < 8 || sockaddr.get(1) != Some(&AF_LINK) {
        return Err(RouteMessageError::Unsupported);
    }
    let index = u16::from_ne_bytes(
        sockaddr[2..4]
            .try_into()
            .map_err(|_| RouteMessageError::Truncated)?,
    ) as u32;
    Ok((index != 0).then_some(index))
}

fn sockaddr_slots(
    message: &[u8],
    addrs: i32,
) -> Result<[Option<&[u8]>; RTAX_MAX], RouteMessageError> {
    let mut slots = [None; RTAX_MAX];
    let mut offset = RTM_HEADER_BYTES;
    for (index, slot) in slots.iter_mut().enumerate() {
        if addrs & (1 << index) == 0 {
            continue;
        }
        let length = *message.get(offset).ok_or(RouteMessageError::Truncated)? as usize;
        if length == 0 {
            if index != RTAX_NETMASK || offset + 4 > message.len() {
                return Err(RouteMessageError::Invalid);
            }
            *slot = Some(&message[offset..offset + 4]);
            offset += 4;
            continue;
        }
        if length < 2 {
            return Err(RouteMessageError::Invalid);
        }
        let end = offset
            .checked_add(length)
            .ok_or(RouteMessageError::Oversize)?;
        if end > message.len() {
            return Err(RouteMessageError::Truncated);
        }
        *slot = Some(&message[offset..end]);
        let padded = length.checked_add(3).ok_or(RouteMessageError::Oversize)? & !3;
        offset = offset
            .checked_add(padded)
            .ok_or(RouteMessageError::Oversize)?;
        if offset > message.len() {
            return Err(RouteMessageError::Truncated);
        }
    }
    if offset != message.len() {
        return Err(RouteMessageError::Ambiguous);
    }
    Ok(slots)
}

fn parse_ip(sockaddr: &[u8], expected_scope: Option<u32>) -> Result<IpAddr, RouteMessageError> {
    match sockaddr.get(1).copied() {
        Some(AF_INET) if sockaddr.len() >= 8 && sockaddr[2..4] == [0, 0] => {
            Ok(Ipv4Addr::new(sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7]).into())
        }
        Some(AF_INET6) if sockaddr.len() >= 24 => {
            if sockaddr[2..8].iter().any(|byte| *byte != 0) {
                return Err(RouteMessageError::Unsupported);
            }
            let mut bytes: [u8; 16] = sockaddr[8..24]
                .try_into()
                .map_err(|_| RouteMessageError::Truncated)?;
            let scope = sockaddr
                .get(24..28)
                .map(|value| u32::from_ne_bytes(value.try_into().expect("four-byte scope")))
                .unwrap_or(0);
            let embedded = u16::from_be_bytes([bytes[2], bytes[3]]) as u32;
            let link_local = bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80;
            if scope != 0 || link_local && embedded != 0 {
                let expected = expected_scope.ok_or(RouteMessageError::Unsupported)?;
                if !link_local
                    || scope != 0 && scope != expected
                    || embedded != 0 && embedded != expected
                {
                    return Err(RouteMessageError::Unsupported);
                }
                bytes[2] = 0;
                bytes[3] = 0;
            }
            Ok(Ipv6Addr::from(bytes).into())
        }
        _ => Err(RouteMessageError::Unsupported),
    }
}

fn parse_prefix(sockaddr: &[u8], ipv4: bool) -> Result<u8, RouteMessageError> {
    if sockaddr[0] == 0 {
        return Ok(0);
    }
    let (start, width) = if ipv4 { (4, 4) } else { (8, 16) };
    if sockaddr.len() < start {
        return Err(RouteMessageError::Unsupported);
    }
    let mut mask = vec![0_u8; width];
    if sockaddr.len() > start {
        let available = (sockaddr.len() - start).min(width);
        mask[..available].copy_from_slice(&sockaddr[start..start + available]);
    }
    contiguous_prefix(&mask).ok_or(RouteMessageError::Invalid)
}

fn contiguous_prefix(mask: &[u8]) -> Option<u8> {
    let mut prefix = 0_u8;
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if zero_seen && set {
                return None;
            }
            if set {
                prefix = prefix.checked_add(1)?;
            } else {
                zero_seen = true;
            }
        }
    }
    Some(prefix)
}

fn canonical_destination(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(address) & mask == u32::from(address)
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from(address)
        }
        _ => false,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RouteMessageError> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(RouteMessageError::Truncated)?
            .try_into()
            .map_err(|_| RouteMessageError::Truncated)?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, RouteMessageError> {
    Ok(i32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(RouteMessageError::Truncated)?
            .try_into()
            .map_err(|_| RouteMessageError::Truncated)?,
    ))
}

fn map_snapshot_error(error: SnapshotError) -> RouteMessageError {
    match error {
        SnapshotError::Incomplete => RouteMessageError::Truncated,
        SnapshotError::Invalid => RouteMessageError::Invalid,
        SnapshotError::Ambiguous => RouteMessageError::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_v4(address: [u8; 4]) -> Vec<u8> {
        let mut value = vec![0_u8; 16];
        value[0] = 16;
        value[1] = AF_INET;
        value[4..8].copy_from_slice(&address);
        value
    }

    fn sockaddr_link() -> Vec<u8> {
        sockaddr_link_index(0)
    }

    fn sockaddr_link_index(index: u16) -> Vec<u8> {
        let mut value = vec![0_u8; 8];
        value[0] = 8;
        value[1] = AF_LINK;
        value[2..4].copy_from_slice(&index.to_ne_bytes());
        value
    }

    fn sockaddr_v6(address: [u8; 16]) -> Vec<u8> {
        let mut value = vec![0_u8; 28];
        value[0] = 28;
        value[1] = AF_INET6;
        value[8..24].copy_from_slice(&address);
        value
    }

    fn mask_v4(mask: [u8; 4]) -> Vec<u8> {
        let length = mask
            .iter()
            .rposition(|byte| *byte != 0)
            .map_or(0, |last| last + 5);
        let mut value = vec![0_u8; length];
        if length > 0 {
            value[0] = length as u8;
            value[4..].copy_from_slice(&mask[..length - 4]);
        }
        value
    }

    fn mask_v6(mask: [u8; 16]) -> Vec<u8> {
        let mut value = vec![0_u8; 24];
        value[0] = 24;
        value[8..24].copy_from_slice(&mask);
        value
    }

    fn message(flags: i32, index: u16, values: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut message = vec![0_u8; RTM_HEADER_BYTES];
        message[2] = RTM_VERSION;
        message[3] = RTM_GET2;
        message[4..6].copy_from_slice(&index.to_ne_bytes());
        message[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mut addrs = 0_i32;
        for (slot, value) in values {
            addrs |= 1 << slot;
            let padded = if value.is_empty() {
                4
            } else {
                (value.len() + 3) & !3
            };
            message.extend_from_slice(value);
            message.resize(message.len() + padded - value.len(), 0);
        }
        message[12..16].copy_from_slice(&addrs.to_ne_bytes());
        let length = message.len() as u16;
        message[0..2].copy_from_slice(&length.to_ne_bytes());
        message
    }

    #[test]
    fn decodes_split_default_and_direct_gateway_fixture() {
        let first = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v4([0, 0, 0, 0])),
                (1, sockaddr_link()),
                (2, mask_v4([128, 0, 0, 0])),
            ],
        );
        let second = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v4([128, 0, 0, 0])),
                (1, sockaddr_link()),
                (2, mask_v4([128, 0, 0, 0])),
            ],
        );
        let snapshot = decode_route_messages(&[first, second].concat()).unwrap();
        assert_eq!(snapshot.routes.len(), 2);
        assert_eq!(snapshot.routes[0].prefix_length, 1);
        assert_eq!(snapshot.routes[0].gateway, None);
        assert_eq!(
            snapshot.routes[1].destination,
            "128.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn zero_length_netmask_is_only_valid_for_default_prefix() {
        let default = message(
            RTF_UP,
            9,
            &[
                (0, sockaddr_v4([0, 0, 0, 0])),
                (1, sockaddr_v4([192, 0, 2, 1])),
                (2, Vec::new()),
            ],
        );
        let route = decode_route_messages(&default).unwrap().routes.remove(0);
        assert_eq!(route.prefix_length, 0);

        let invalid_destination = message(RTF_UP, 9, &[(0, Vec::new()), (2, Vec::new())]);
        assert_eq!(
            decode_route_messages(&invalid_destination),
            Err(RouteMessageError::Invalid)
        );
    }

    #[test]
    fn decodes_host_bypass_with_ip_gateway() {
        let fixture = message(
            RTF_UP | RTF_HOST,
            9,
            &[
                (0, sockaddr_v4([198, 51, 100, 7])),
                (1, sockaddr_v4([192, 0, 2, 1])),
            ],
        );
        let route = decode_route_messages(&fixture).unwrap().routes.remove(0);
        assert_eq!(route.prefix_length, 32);
        assert_eq!(route.gateway, Some("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn decodes_ipv6_split_and_scope_bound_addresses() {
        let mut destination = [0_u8; 16];
        destination[0] = 0x80;
        let mut mask = [0_u8; 16];
        mask[0] = 0x80;
        let fixture = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v6(destination)),
                (1, sockaddr_link()),
                (2, mask_v6(mask)),
            ],
        );
        let route = decode_route_messages(&fixture).unwrap().routes.remove(0);
        assert_eq!(route.destination, "8000::".parse::<IpAddr>().unwrap());
        assert_eq!(route.prefix_length, 1);

        let mut scoped = sockaddr_v6("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        scoped[24..28].copy_from_slice(&17_u32.to_ne_bytes());
        let scoped_gateway = message(
            RTF_UP | RTF_HOST,
            17,
            &[
                (
                    0,
                    sockaddr_v6("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
                ),
                (1, scoped),
            ],
        );
        let route = decode_route_messages(&scoped_gateway)
            .unwrap()
            .routes
            .remove(0);
        assert_eq!(route.gateway, Some("fe80::1".parse().unwrap()));

        let mut mismatched = sockaddr_v6("fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        mismatched[24..28].copy_from_slice(&18_u32.to_ne_bytes());
        let mismatched_gateway = message(
            RTF_UP | RTF_HOST,
            17,
            &[
                (
                    0,
                    sockaddr_v6("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
                ),
                (1, mismatched),
            ],
        );
        assert_eq!(
            decode_route_messages(&mismatched_gateway),
            Err(RouteMessageError::Unsupported)
        );

        let mut local = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        local[2..4].copy_from_slice(&17_u16.to_be_bytes());
        let local_route = message(
            RTF_UP | RTF_HOST,
            1,
            &[
                (0, sockaddr_v6(local)),
                (1, sockaddr_link()),
                (RTAX_IFP, sockaddr_link_index(17)),
            ],
        );
        let route = decode_route_messages(&local_route)
            .unwrap()
            .routes
            .remove(0);
        assert_eq!(route.destination, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(route.interface_index, 17);
    }

    #[test]
    fn rejects_truncation_unknown_version_noncanonical_and_noncontiguous_mask() {
        let valid = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v4([128, 0, 0, 0])),
                (2, mask_v4([128, 0, 0, 0])),
            ],
        );
        assert_eq!(
            decode_route_messages(&valid[..valid.len() - 1]),
            Err(RouteMessageError::Truncated)
        );
        let mut wrong_version = valid.clone();
        wrong_version[2] = 4;
        assert_eq!(
            decode_route_messages(&wrong_version),
            Err(RouteMessageError::Unsupported)
        );
        let noncanonical = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v4([192, 0, 2, 7])),
                (2, mask_v4([255, 255, 255, 0])),
            ],
        );
        assert_eq!(
            decode_route_messages(&noncanonical),
            Err(RouteMessageError::Invalid)
        );
        let noncontiguous = message(
            RTF_UP,
            17,
            &[
                (0, sockaddr_v4([0, 0, 0, 0])),
                (2, mask_v4([255, 0, 255, 0])),
            ],
        );
        assert_eq!(
            decode_route_messages(&noncontiguous),
            Err(RouteMessageError::Invalid)
        );
    }

    #[test]
    fn exact_duplicate_routes_collapse_to_topology_set() {
        let route = message(
            RTF_UP,
            17,
            &[(0, sockaddr_v4([0, 0, 0, 0])), (2, mask_v4([128, 0, 0, 0]))],
        );
        let snapshot = decode_route_messages(&[route.clone(), route].concat()).unwrap();
        assert_eq!(snapshot.routes.len(), 1);
    }

    #[test]
    fn ephemeral_kernel_cache_routes_are_not_baseline_topology() {
        let route = message(
            RTF_UP | RTF_HOST | RTF_LLINFO,
            7,
            &[
                (0, sockaddr_v4([192, 0, 2, 2])),
                (1, sockaddr_link_index(7)),
            ],
        );
        assert!(decode_route_messages(&route).unwrap().routes.is_empty());
    }
}
