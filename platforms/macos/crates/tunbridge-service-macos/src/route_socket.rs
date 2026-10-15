//! Bounded acknowledged PF_ROUTE effect boundary.
//!
//! The production entry point is intentionally not wired into the helper yet.
//! Every effect requires a matching kernel acknowledgment and a post-effect
//! read-only topology verification.

use crate::{
    darwin_state::RouteSnapshot,
    lifecycle_plan::RouteDelta,
    native::native_route_snapshot,
    route_effect::{
        encode_route_effect_with_link_gateway, RouteEffectOperation, RouteEffectRequest,
    },
};
use std::{
    ffi::c_void,
    os::fd::RawFd,
    time::{Duration, Instant},
};

const HEADER_BYTES: usize = 92;
const RTM_VERSION: u8 = 5;
const MAX_ACK_BYTES: usize = 64 * 1024;
const MAX_ACK_MESSAGES: usize = 64;
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRouteEffectError {
    Invalid,
    Unavailable,
    SystemCall(&'static str, i32),
    Timeout,
    Protocol,
    Kernel(i32),
    Observe,
    Drifted,
}

/// Applies one exact route effect from the privileged helper boundary.
///
/// The caller must already have authenticated the helper request and persisted
/// the corresponding owned journal stage. Desktop code does not call this API.
pub fn apply_route_effect(request: &RouteEffectRequest) -> Result<(), NativeRouteEffectError> {
    if request.sender_pid != std::process::id() {
        return Err(NativeRouteEffectError::Invalid);
    }

    // A process crash can remove a utun before the journal recovery pass gets
    // to its split routes.  Treat an already-absent exact delete as an
    // idempotent success before asking getifaddrs for the vanished link.
    if request.operation == RouteEffectOperation::Delete {
        let snapshot = native_route_snapshot().map_err(|_| NativeRouteEffectError::Observe)?;
        if !snapshot.complete {
            return Err(NativeRouteEffectError::Observe);
        }
        if !snapshot
            .routes
            .iter()
            .any(|candidate| candidate == &request.route)
        {
            return verify_post_effect(request.operation, &request.route, &snapshot);
        }
    }

    let link_gateway = if request.route.gateway.is_none() {
        Some(interface_link_gateway(request.route.interface_index)?)
    } else {
        None
    };
    let frame = encode_route_effect_with_link_gateway(request, link_gateway.as_deref())
        .map_err(|_| NativeRouteEffectError::Invalid)?;
    let socket = RouteSocket::open()?;
    let kernel_error = socket.transact(&frame, request)?;
    classify_kernel_result(request.operation, kernel_error)?;
    let snapshot = native_route_snapshot().map_err(|_| NativeRouteEffectError::Observe)?;
    verify_post_effect(request.operation, &request.route, &snapshot)
}

fn interface_link_gateway(index: u32) -> Result<Vec<u8>, NativeRouteEffectError> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Err(last_system_error("getifaddrs"));
    }
    let mut current = head;
    let mut result = None;
    while !current.is_null() {
        let address = unsafe { (*current).ifa_addr };
        if !address.is_null() && unsafe { (*address).sa_family as i32 } == libc::AF_LINK {
            let link = address.cast::<libc::sockaddr_dl>();
            let length = unsafe { (*link).sdl_len as usize };
            if unsafe { (*link).sdl_index as u32 } == index && (8..=32).contains(&length) {
                result = Some(unsafe {
                    std::slice::from_raw_parts(address.cast::<u8>(), length).to_vec()
                });
                break;
            }
        }
        current = unsafe { (*current).ifa_next };
    }
    unsafe { libc::freeifaddrs(head) };
    result.ok_or(NativeRouteEffectError::Invalid)
}

fn classify_kernel_result(
    operation: RouteEffectOperation,
    kernel_error: i32,
) -> Result<(), NativeRouteEffectError> {
    match (operation, kernel_error) {
        (_, 0)
        | (RouteEffectOperation::Add, libc::EEXIST)
        | (RouteEffectOperation::Delete, libc::ESRCH) => Ok(()),
        (_, error) => Err(NativeRouteEffectError::Kernel(error)),
    }
}

fn verify_post_effect(
    operation: RouteEffectOperation,
    route: &RouteDelta,
    snapshot: &RouteSnapshot,
) -> Result<(), NativeRouteEffectError> {
    if !snapshot.complete {
        return Err(NativeRouteEffectError::Observe);
    }
    let exact = snapshot.routes.iter().any(|candidate| candidate == route);
    let conflict = snapshot
        .routes
        .iter()
        .any(|candidate| candidate.same_key(route) && candidate != route);
    match operation {
        RouteEffectOperation::Add if exact && !conflict => Ok(()),
        RouteEffectOperation::Delete if !exact && !conflict => Ok(()),
        _ => Err(NativeRouteEffectError::Drifted),
    }
}

struct RouteSocket(RawFd);

impl RouteSocket {
    fn open() -> Result<Self, NativeRouteEffectError> {
        let descriptor = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if descriptor < 0 {
            return Err(last_system_error("socket"));
        }
        let socket = Self(descriptor);
        if unsafe { libc::fcntl(socket.0, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(last_system_error("fcntl"));
        }
        Ok(socket)
    }

    fn transact(
        &self,
        frame: &[u8],
        request: &RouteEffectRequest,
    ) -> Result<i32, NativeRouteEffectError> {
        let written = unsafe { libc::write(self.0, frame.as_ptr().cast::<c_void>(), frame.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if matches!(error, libc::EEXIST | libc::ESRCH) {
                return Ok(error);
            }
            return Err(NativeRouteEffectError::SystemCall("write", error));
        }
        if written as usize != frame.len() {
            return Err(NativeRouteEffectError::SystemCall("short-write", libc::EIO));
        }
        let deadline = Instant::now() + ACK_TIMEOUT;
        let mut seen = 0_usize;
        let expected_type = frame[3];
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(NativeRouteEffectError::Timeout)?;
            let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd: self.0,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(last_system_error("poll"));
            }
            if ready == 0 {
                return Err(NativeRouteEffectError::Timeout);
            }
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(NativeRouteEffectError::SystemCall(
                    "poll-revents",
                    i32::from(poll.revents),
                ));
            }
            let mut bytes = vec![0_u8; MAX_ACK_BYTES];
            let received =
                unsafe { libc::read(self.0, bytes.as_mut_ptr().cast::<c_void>(), bytes.len()) };
            if received <= 0 {
                return Err(last_system_error("read"));
            }
            bytes.truncate(received as usize);
            if let Some(kernel_error) =
                find_matching_ack(&bytes, request, expected_type, &mut seen)?
            {
                return Ok(kernel_error);
            }
        }
    }
}

fn last_system_error(operation: &'static str) -> NativeRouteEffectError {
    NativeRouteEffectError::SystemCall(
        operation,
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    )
}

fn find_matching_ack(
    bytes: &[u8],
    request: &RouteEffectRequest,
    expected_type: u8,
    seen: &mut usize,
) -> Result<Option<i32>, NativeRouteEffectError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        *seen = (*seen)
            .checked_add(1)
            .ok_or(NativeRouteEffectError::Protocol)?;
        if *seen > MAX_ACK_MESSAGES || bytes.len() - offset < HEADER_BYTES {
            return Err(NativeRouteEffectError::Protocol);
        }
        let length = u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
        if length < HEADER_BYTES || length > bytes.len() - offset {
            return Err(NativeRouteEffectError::Protocol);
        }
        let message = &bytes[offset..offset + length];
        if message[2] != RTM_VERSION {
            return Err(NativeRouteEffectError::Protocol);
        }
        let sender_pid = i32::from_ne_bytes(message[16..20].try_into().unwrap());
        let sequence = i32::from_ne_bytes(message[20..24].try_into().unwrap());
        if message[3] == expected_type
            && sender_pid == request.sender_pid as i32
            && sequence == request.sequence as i32
        {
            return Ok(Some(i32::from_ne_bytes(
                message[24..28].try_into().unwrap(),
            )));
        }
        offset += length;
    }
    Ok(None)
}

impl Drop for RouteSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_effect::encode_route_effect;

    fn route(gateway: Option<&str>, interface_index: u32) -> RouteDelta {
        RouteDelta {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 1,
            gateway: gateway.map(|value| value.parse().unwrap()),
            interface_index,
            interface_scoped: false,
        }
    }

    #[test]
    fn kernel_idempotency_is_only_a_candidate_for_post_verification() {
        for (operation, error) in [
            (RouteEffectOperation::Add, 0),
            (RouteEffectOperation::Add, libc::EEXIST),
            (RouteEffectOperation::Delete, 0),
            (RouteEffectOperation::Delete, libc::ESRCH),
        ] {
            classify_kernel_result(operation, error).unwrap();
        }
        assert_eq!(
            classify_kernel_result(RouteEffectOperation::Add, libc::EPERM),
            Err(NativeRouteEffectError::Kernel(libc::EPERM))
        );
    }

    #[test]
    fn scoped_default_is_verified_beside_the_unscoped_system_default() {
        let system = RouteDelta {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface_index: 9,
            interface_scoped: false,
        };
        let scoped = RouteDelta {
            interface_scoped: true,
            ..system.clone()
        };
        let applied = RouteSnapshot {
            complete: true,
            routes: vec![system.clone(), scoped.clone()],
        };
        verify_post_effect(RouteEffectOperation::Add, &scoped, &applied).unwrap();
        let removed = RouteSnapshot {
            complete: true,
            routes: vec![system],
        };
        verify_post_effect(RouteEffectOperation::Delete, &scoped, &removed).unwrap();
        let mut foreign = scoped.clone();
        foreign.gateway = Some("192.0.2.254".parse().unwrap());
        assert_eq!(
            verify_post_effect(
                RouteEffectOperation::Add,
                &scoped,
                &RouteSnapshot {
                    complete: true,
                    routes: vec![scoped.clone(), foreign],
                },
            ),
            Err(NativeRouteEffectError::Drifted)
        );
    }

    #[test]
    fn add_requires_exact_without_conflict_and_delete_requires_absence() {
        let expected = route(None, 17);
        let conflict = route(Some("192.0.2.1"), 9);
        let exact = RouteSnapshot {
            complete: true,
            routes: vec![expected.clone()],
        };
        verify_post_effect(RouteEffectOperation::Add, &expected, &exact).unwrap();
        assert_eq!(
            verify_post_effect(
                RouteEffectOperation::Add,
                &expected,
                &RouteSnapshot {
                    complete: true,
                    routes: vec![expected.clone(), conflict.clone()],
                }
            ),
            Err(NativeRouteEffectError::Drifted)
        );
        assert_eq!(
            verify_post_effect(RouteEffectOperation::Delete, &expected, &exact),
            Err(NativeRouteEffectError::Drifted)
        );
        assert_eq!(
            verify_post_effect(
                RouteEffectOperation::Delete,
                &expected,
                &RouteSnapshot {
                    complete: true,
                    routes: vec![conflict],
                },
            ),
            Err(NativeRouteEffectError::Drifted)
        );
        verify_post_effect(
            RouteEffectOperation::Delete,
            &expected,
            &RouteSnapshot {
                complete: true,
                routes: Vec::new(),
            },
        )
        .unwrap();
    }

    #[test]
    fn incomplete_snapshot_never_confirms_effect() {
        assert_eq!(
            verify_post_effect(
                RouteEffectOperation::Delete,
                &route(None, 17),
                &RouteSnapshot {
                    complete: false,
                    routes: Vec::new(),
                }
            ),
            Err(NativeRouteEffectError::Observe)
        );
    }

    #[test]
    fn acknowledgement_requires_exact_type_pid_sequence_and_complete_frame() {
        let request = RouteEffectRequest {
            operation: RouteEffectOperation::Add,
            route: route(None, 17),
            sequence: 7,
            sender_pid: 500,
        };
        let mut acknowledgement = encode_route_effect(&request).unwrap();
        acknowledgement[24..28].copy_from_slice(&libc::EEXIST.to_ne_bytes());
        let expected_type = acknowledgement[3];
        let mut seen = 0;
        assert_eq!(
            find_matching_ack(&acknowledgement, &request, expected_type, &mut seen),
            Ok(Some(libc::EEXIST))
        );

        let mut unrelated = acknowledgement.clone();
        unrelated[20..24].copy_from_slice(&8_i32.to_ne_bytes());
        let mut seen = 0;
        assert_eq!(
            find_matching_ack(&unrelated, &request, expected_type, &mut seen),
            Ok(None)
        );

        let mut seen = 0;
        assert_eq!(
            find_matching_ack(
                &acknowledgement[..HEADER_BYTES - 1],
                &request,
                expected_type,
                &mut seen,
            ),
            Err(NativeRouteEffectError::Protocol)
        );
    }
}
