//! Exact loopback upstream attribution for the privileged Darwin lifecycle.

use crate::{
    controller::ControllerError,
    controller_owner::listener_pids,
    lifecycle_plan::ProcessIdentity,
    native::{process_credentials, process_executable_leaf, process_identity},
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tunbridge_service::{protocol::StartProfile, watchdog::HealthSignal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamOwnerError {
    Invalid,
    EnumerationUnavailable,
    OwnershipMismatch,
    IdentityUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpstream {
    pub identity: ProcessIdentity,
    pub process_name: String,
    pub auto_bypass_cidrs: Vec<String>,
}

pub fn verify_upstream_owner(
    profile: &StartProfile,
    caller_uid: u32,
) -> Result<VerifiedUpstream, UpstreamOwnerError> {
    profile
        .validate()
        .map_err(|_| UpstreamOwnerError::Invalid)?;
    if caller_uid == 0 || profile.upstream_process_id <= 1 {
        return Err(UpstreamOwnerError::Invalid);
    }
    let addresses = profile_addresses(profile)?;
    verify_listener_set(&addresses, profile.upstream_process_id)?;

    let credentials = process_credentials(profile.upstream_process_id)
        .map_err(|_| UpstreamOwnerError::IdentityUnavailable)?;
    if !trusted_upstream_owner(credentials.effective_uid, credentials.real_uid, caller_uid) {
        return Err(UpstreamOwnerError::OwnershipMismatch);
    }
    let identity = process_identity(profile.upstream_process_id)
        .map_err(|_| UpstreamOwnerError::IdentityUnavailable)?;
    let process_name = process_executable_leaf(profile.upstream_process_id)
        .map_err(|_| UpstreamOwnerError::IdentityUnavailable)?;

    verify_listener_set(&addresses, profile.upstream_process_id)?;
    let final_identity = process_identity(profile.upstream_process_id)
        .map_err(|_| UpstreamOwnerError::IdentityUnavailable)?;
    let final_credentials = process_credentials(profile.upstream_process_id)
        .map_err(|_| UpstreamOwnerError::IdentityUnavailable)?;
    if final_identity != identity || final_credentials != credentials {
        return Err(UpstreamOwnerError::OwnershipMismatch);
    }
    Ok(VerifiedUpstream {
        identity,
        process_name,
        auto_bypass_cidrs: Vec::new(),
    })
}

/// The upstream must run as the calling user or as root. Proxy clients in
/// "service mode" (for example Clash Verge) run their core as root through a
/// privileged helper; root cannot be impersonated by another unprivileged
/// user, so trusting it does not widen the boundary. A process owned by any
/// other user, or with mixed real/effective ids, stays rejected.
fn trusted_upstream_owner(effective_uid: u32, real_uid: u32, caller_uid: u32) -> bool {
    effective_uid == real_uid && (effective_uid == caller_uid || effective_uid == 0)
}

/// The facts needed to re-check a verified local upstream while the session
/// runs: its loopback listener, the executable leaf the engine's
/// PROCESS-NAME bypass matches, and the user that started the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamWatch {
    addresses: Vec<SocketAddr>,
    process_name: String,
    caller_uid: u32,
}

impl UpstreamWatch {
    pub fn for_profile(
        profile: &StartProfile,
        verified: &VerifiedUpstream,
        caller_uid: u32,
    ) -> Option<Self> {
        Some(Self {
            addresses: profile_addresses(profile).ok()?,
            process_name: verified.process_name.clone(),
            caller_uid,
        })
    }
}

/// Samples the listener of a running session's local upstream. No listener
/// means the client exited (Unhealthy). Any owner must still be the caller
/// or root and run the same executable leaf, so a restarted client is
/// accepted while an unrelated listener on the port stays Unknown.
pub fn sample_upstream_watch(watch: &UpstreamWatch) -> HealthSignal {
    let mut owners = BTreeSet::new();
    for address in &watch.addresses {
        match listener_pids(*address) {
            Ok(pids) => owners.extend(pids),
            Err(_) => return HealthSignal::Unknown,
        }
    }
    classify_upstream_owners(
        watch,
        &owners,
        |pid| {
            process_credentials(pid)
                .ok()
                .map(|credentials| (credentials.effective_uid, credentials.real_uid))
        },
        |pid| process_executable_leaf(pid).ok(),
    )
}

fn classify_upstream_owners(
    watch: &UpstreamWatch,
    owners: &BTreeSet<u32>,
    credentials: impl Fn(u32) -> Option<(u32, u32)>,
    executable_leaf: impl Fn(u32) -> Option<String>,
) -> HealthSignal {
    if owners.is_empty() {
        return HealthSignal::Unhealthy;
    }
    let trusted = owners.iter().all(|pid| {
        credentials(*pid).is_some_and(|(effective, real)| {
            trusted_upstream_owner(effective, real, watch.caller_uid)
        }) && executable_leaf(*pid).as_deref() == Some(watch.process_name.as_str())
    });
    if trusted {
        HealthSignal::Healthy
    } else {
        HealthSignal::Unknown
    }
}

fn profile_addresses(profile: &StartProfile) -> Result<Vec<SocketAddr>, UpstreamOwnerError> {
    let port = profile.upstream_port;
    match profile.upstream_host.as_str() {
        "127.0.0.1" => Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)]),
        "::1" => Ok(vec![SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)]),
        "localhost" => Ok(vec![
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port),
        ]),
        _ => Err(UpstreamOwnerError::Invalid),
    }
}

fn verify_listener_set(
    addresses: &[SocketAddr],
    expected_pid: u32,
) -> Result<(), UpstreamOwnerError> {
    let mut owners = BTreeSet::new();
    for address in addresses {
        owners.extend(listener_pids(*address).map_err(map_enumeration_error)?);
    }
    if owners == BTreeSet::from([expected_pid]) {
        Ok(())
    } else {
        Err(UpstreamOwnerError::OwnershipMismatch)
    }
}

fn map_enumeration_error(error: ControllerError) -> UpstreamOwnerError {
    match error {
        ControllerError::Invalid | ControllerError::Protocol => UpstreamOwnerError::Invalid,
        ControllerError::OwnershipMismatch
        | ControllerError::Unavailable
        | ControllerError::ResponseTooLarge
        | ControllerError::StateMismatch => UpstreamOwnerError::EnumerationUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, TcpListener};
    use tunbridge_service::protocol::UpstreamProtocol;

    fn profile(host: &str, port: u16) -> StartProfile {
        StartProfile {
            upstream_host: host.into(),
            upstream_port: port,
            protocol: UpstreamProtocol::Socks5,
            username: None,
            password: None,
            upstream_process_id: std::process::id(),
            bypass_domains: Vec::new(),
            bypass_cidrs: Vec::new(),
            bypass_process_names: Vec::new(),
        }
    }

    #[test]
    fn running_upstream_samples_exit_restart_and_foreign_owners() {
        let watch = UpstreamWatch {
            addresses: vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7897)],
            process_name: "verge-mihomo".into(),
            caller_uid: 501,
        };
        let root_core = |pid: u32| (pid == 50368).then_some((0, 0));
        let same_leaf = |_: u32| Some("verge-mihomo".to_owned());
        assert_eq!(
            classify_upstream_owners(&watch, &BTreeSet::new(), root_core, same_leaf),
            HealthSignal::Unhealthy
        );
        // A restarted core gets a new PID; owner and executable still match.
        assert_eq!(
            classify_upstream_owners(&watch, &BTreeSet::from([50368]), root_core, same_leaf),
            HealthSignal::Healthy
        );
        assert_eq!(
            classify_upstream_owners(
                &watch,
                &BTreeSet::from([777]),
                |_| Some((502, 502)),
                same_leaf
            ),
            HealthSignal::Unknown
        );
        assert_eq!(
            classify_upstream_owners(&watch, &BTreeSet::from([50368]), root_core, |_| Some(
                "other".to_owned()
            )),
            HealthSignal::Unknown
        );
    }

    #[test]
    fn upstream_may_run_as_the_caller_or_root_only() {
        assert!(trusted_upstream_owner(501, 501, 501));
        assert!(trusted_upstream_owner(0, 0, 501));
        assert!(!trusted_upstream_owner(502, 502, 501));
        assert!(!trusted_upstream_owner(0, 501, 501));
        assert!(!trusted_upstream_owner(501, 0, 501));
    }

    #[test]
    fn native_loopback_listener_binds_port_pid_uid_and_exact_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let verified =
            verify_upstream_owner(&profile("127.0.0.1", port), unsafe { libc::geteuid() }).unwrap();
        assert_eq!(verified.identity.pid, std::process::id());
        assert!(!verified.process_name.is_empty());
        assert!(!verified.process_name.contains(['/', '\\', ',']));
    }

    #[test]
    fn localhost_unions_both_loopback_families_without_inventing_an_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            verify_upstream_owner(&profile("localhost", port), unsafe { libc::geteuid() }).is_ok()
        );
    }

    #[test]
    fn wrong_pid_uid_remote_host_and_closed_port_fail_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut wrong_pid = profile("127.0.0.1", port);
        wrong_pid.upstream_process_id = std::process::id().saturating_add(1);
        assert_eq!(
            verify_upstream_owner(&wrong_pid, unsafe { libc::geteuid() }),
            Err(UpstreamOwnerError::OwnershipMismatch)
        );
        assert_eq!(
            verify_upstream_owner(&profile("127.0.0.1", port), u32::MAX),
            Err(UpstreamOwnerError::OwnershipMismatch)
        );
        let mut remote = profile("127.0.0.1", port);
        remote.upstream_host = "192.0.2.1".into();
        assert_eq!(
            verify_upstream_owner(&remote, unsafe { libc::geteuid() }),
            Err(UpstreamOwnerError::Invalid)
        );
        let closed = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        assert_eq!(
            verify_upstream_owner(&profile("127.0.0.1", closed), unsafe { libc::geteuid() }),
            Err(UpstreamOwnerError::OwnershipMismatch)
        );
    }

    #[test]
    fn address_contract_maps_only_loopback_and_preserves_family() {
        let ipv4 = profile_addresses(&profile("127.0.0.1", 7890)).unwrap();
        assert_eq!(ipv4[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ipv6 = profile_addresses(&profile("::1", 7890)).unwrap();
        assert_eq!(ipv6[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        let both = profile_addresses(&profile("localhost", 7890)).unwrap();
        assert_eq!(both.len(), 2);
    }
}
