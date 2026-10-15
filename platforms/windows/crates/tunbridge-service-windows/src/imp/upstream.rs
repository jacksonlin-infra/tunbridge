use std::{
    ffi::c_void,
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_LISTEN,
        TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

use crate::protocol::StartProfile;
use crate::watchdog::HealthSignal;

use super::process::{normalized_path, query_process_identity, ProcessIdentityError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpstream {
    pid: u32,
    image_path: PathBuf,
    process_name: String,
    creation_time: u64,
}

impl VerifiedUpstream {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn image_path(&self) -> &Path {
        &self.image_path
    }

    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }

    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        let process = query_process_identity(std::process::id()).unwrap();
        Self {
            pid: std::process::id(),
            image_path: process.image_path().to_path_buf(),
            process_name: process.process_name().to_string(),
            creation_time: process.creation_time(),
        }
    }
}

/// Prove that the requested PID owns the requested loopback TCP listener, then
/// obtain its image identity through a process handle. A second owner-table
/// lookup closes the common listener/process-exit race before returning.
pub fn verify_upstream_listener(
    profile: &StartProfile,
) -> Result<VerifiedUpstream, UpstreamIdentityError> {
    profile.validate().map_err(UpstreamIdentityError::Profile)?;
    if !listener_owned_by(profile)? {
        return Err(UpstreamIdentityError::ListenerMismatch);
    }

    let process = query_process_identity(profile.upstream_process_id)
        .map_err(UpstreamIdentityError::ProcessQuery)?;

    if !listener_owned_by(profile)? {
        return Err(UpstreamIdentityError::ListenerChanged);
    }
    Ok(VerifiedUpstream {
        pid: profile.upstream_process_id,
        image_path: process.image_path().to_path_buf(),
        process_name: process.process_name().to_string(),
        creation_time: process.creation_time(),
    })
}

/// Resolve one fixed loopback endpoint to exactly one live process identity.
/// No caller path, process name or PID participates in the decision. A second
/// owner-table and process check closes listener handoff and PID-reuse races
/// before the identity is returned to a trusted product host.
pub fn resolve_unique_loopback_listener(
    host: &str,
    port: u16,
) -> Result<VerifiedUpstream, UpstreamIdentityError> {
    let pid = resolve_unique_loopback_listener_pid(host, port)?;
    let process = query_process_identity(pid).map_err(UpstreamIdentityError::ProcessQuery)?;
    let verified = VerifiedUpstream {
        pid,
        image_path: process.image_path().to_path_buf(),
        process_name: process.process_name().to_string(),
        creation_time: process.creation_time(),
    };
    reverify_upstream_listener(&verified, host, port)?;
    Ok(verified)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerOwnerSnapshot {
    pub ipv4_loopback: usize,
    pub ipv4_unspecified: usize,
    pub ipv6_loopback: usize,
    pub ipv6_unspecified: usize,
}

/// Resolve one fixed loopback endpoint to exactly one listener PID without
/// opening the foreign process. This is suitable for a standard-user desktop
/// preflight because the privileged service independently proves the process
/// image and listener identity before rendering or starting the engine.
pub fn resolve_unique_loopback_listener_pid(
    host: &str,
    port: u16,
) -> Result<u32, UpstreamIdentityError> {
    if port == 0 || !matches!(host, "127.0.0.1" | "::1" | "localhost") {
        return Err(UpstreamIdentityError::ListenerMismatch);
    }
    let pid = unique_listener_pid(loopback_listener_pids(host, port)?)?;
    if unique_listener_pid(loopback_listener_pids(host, port)?)? != pid {
        return Err(UpstreamIdentityError::ListenerChanged);
    }
    Ok(pid)
}

fn unique_listener_pid(mut owners: Vec<u32>) -> Result<u32, UpstreamIdentityError> {
    owners.sort_unstable();
    owners.dedup();
    match owners.as_slice() {
        [pid] => Ok(*pid),
        [] => Err(UpstreamIdentityError::ListenerMismatch),
        _ => Err(UpstreamIdentityError::AmbiguousListenerOwners),
    }
}

/// Re-prove the listener and process identity captured before configuration
/// rendering. This closes the gap between preflight and the Running commit.
pub fn reverify_upstream_listener(
    verified: &VerifiedUpstream,
    host: &str,
    port: u16,
) -> Result<(), UpstreamIdentityError> {
    verify_recorded_loopback_listener(
        host,
        port,
        verified.pid,
        verified.creation_time,
        &verified.image_path,
    )
}

pub fn verify_recorded_loopback_listener(
    host: &str,
    port: u16,
    pid: u32,
    creation_time: u64,
    image_path: &Path,
) -> Result<(), UpstreamIdentityError> {
    if pid == 0 || port == 0 || !listener_owned_by_endpoint(host, port, pid)? {
        return Err(UpstreamIdentityError::ListenerMismatch);
    }
    let process = query_process_identity(pid).map_err(UpstreamIdentityError::ProcessQuery)?;
    if process.creation_time() != creation_time
        || normalized_path(process.image_path()) != normalized_path(image_path)
    {
        return Err(UpstreamIdentityError::ProcessIdentityChanged);
    }
    if !listener_owned_by_endpoint(host, port, pid)? {
        return Err(UpstreamIdentityError::ListenerChanged);
    }
    Ok(())
}

/// Prove a fixed loopback listener is owned by the expected PID. This is used
/// for the engine controller and accepts no caller-supplied path or command.
pub fn verify_loopback_listener_owner(
    host: &str,
    port: u16,
    pid: u32,
) -> Result<(), UpstreamIdentityError> {
    if pid == 0 || port == 0 || !listener_owned_by_endpoint(host, port, pid)? {
        return Err(UpstreamIdentityError::ListenerMismatch);
    }
    Ok(())
}

fn listener_owned_by(profile: &StartProfile) -> Result<bool, UpstreamIdentityError> {
    listener_owned_by_endpoint(
        &profile.upstream_host,
        profile.upstream_port,
        profile.upstream_process_id,
    )
}

fn listener_owned_by_endpoint(
    host: &str,
    port: u16,
    pid: u32,
) -> Result<bool, UpstreamIdentityError> {
    Ok(loopback_listener_pids(host, port)?.contains(&pid))
}

fn loopback_listener_pids(host: &str, port: u16) -> Result<Vec<u32>, UpstreamIdentityError> {
    match host {
        "127.0.0.1" | "localhost" => ipv4_listeners().map(|rows| {
            rows.into_iter()
                .filter_map(|row| {
                    let address = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    (row.dwState == MIB_TCP_STATE_LISTEN as u32
                        && tcp_port(row.dwLocalPort) == port
                        // A 0.0.0.0 listener owns connections accepted through
                        // 127.0.0.1 as well. Discovery already probes that exact
                        // loopback endpoint, so keep identity validation aligned
                        // while still requiring one exact PID owner.
                        && (address.is_loopback() || address.is_unspecified()))
                    .then_some(row.dwOwningPid)
                })
                .collect()
        }),
        "::1" => ipv6_listeners().map(|rows| {
            rows.into_iter()
                .filter_map(|row| {
                    (row.dwState == MIB_TCP_STATE_LISTEN as u32
                        && tcp_port(row.dwLocalPort) == port
                        && Ipv6Addr::from(row.ucLocalAddr).is_loopback())
                    .then_some(row.dwOwningPid)
                })
                .collect()
        }),
        _ => Err(UpstreamIdentityError::ListenerMismatch),
    }
}

pub fn listener_owner_snapshot(port: u16) -> Result<ListenerOwnerSnapshot, UpstreamIdentityError> {
    if port == 0 {
        return Err(UpstreamIdentityError::ListenerMismatch);
    }
    let ipv4 = ipv4_listeners()?;
    let ipv6 = ipv6_listeners()?;
    Ok(ListenerOwnerSnapshot {
        ipv4_loopback: unique_owner_count(ipv4.iter().filter_map(|row| {
            let address = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            matching_listener(row.dwState, row.dwLocalPort, port, address.is_loopback())
                .then_some(row.dwOwningPid)
        })),
        ipv4_unspecified: unique_owner_count(ipv4.iter().filter_map(|row| {
            let address = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            matching_listener(row.dwState, row.dwLocalPort, port, address.is_unspecified())
                .then_some(row.dwOwningPid)
        })),
        ipv6_loopback: unique_owner_count(ipv6.iter().filter_map(|row| {
            let address = Ipv6Addr::from(row.ucLocalAddr);
            matching_listener(row.dwState, row.dwLocalPort, port, address.is_loopback())
                .then_some(row.dwOwningPid)
        })),
        ipv6_unspecified: unique_owner_count(ipv6.iter().filter_map(|row| {
            let address = Ipv6Addr::from(row.ucLocalAddr);
            matching_listener(row.dwState, row.dwLocalPort, port, address.is_unspecified())
                .then_some(row.dwOwningPid)
        })),
    })
}

fn matching_listener(state: u32, encoded_port: u32, port: u16, address_matches: bool) -> bool {
    state == MIB_TCP_STATE_LISTEN as u32 && tcp_port(encoded_port) == port && address_matches
}

fn unique_owner_count(owners: impl Iterator<Item = u32>) -> usize {
    let mut owners = owners.collect::<Vec<_>>();
    owners.sort_unstable();
    owners.dedup();
    owners.len()
}

pub(super) fn sample_recorded_loopback_listener(
    host: &str,
    port: u16,
    pid: u32,
    creation_time: u64,
    image_path: &Path,
) -> HealthSignal {
    match exact_listener_owner_signal(host, port, pid) {
        HealthSignal::Healthy => {}
        other => return other,
    }
    let Ok(process) = query_process_identity(pid) else {
        return HealthSignal::Unknown;
    };
    if process.creation_time() != creation_time
        || normalized_path(process.image_path()) != normalized_path(image_path)
    {
        return HealthSignal::Unknown;
    }
    exact_listener_owner_signal(host, port, pid)
}

/// A recorded local upstream that exited and was started again from the exact
/// recorded executable. The new process alone owns the recorded listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RestartedUpstream {
    pub previous_pid: u32,
    pub pid: u32,
    pub creation_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordedUpstreamSample {
    Signal(HealthSignal),
    Restarted(RestartedUpstream),
}

/// Samples the recorded upstream and recognizes a restart of the same client.
/// Any other owner remains Unknown so the watchdog keeps failing closed.
pub(super) fn sample_recorded_upstream(
    host: &str,
    port: u16,
    pid: u32,
    creation_time: u64,
    image_path: &Path,
) -> RecordedUpstreamSample {
    if pid == 0 || port == 0 {
        return RecordedUpstreamSample::Signal(HealthSignal::Unknown);
    }
    let Ok(mut owners) = loopback_listener_pids(host, port) else {
        return RecordedUpstreamSample::Signal(HealthSignal::Unknown);
    };
    owners.sort_unstable();
    owners.dedup();
    match owners.as_slice() {
        [] => RecordedUpstreamSample::Signal(HealthSignal::Unhealthy),
        [owner] if *owner == pid => RecordedUpstreamSample::Signal(
            sample_recorded_loopback_listener(host, port, pid, creation_time, image_path),
        ),
        [owner] if *owner != 0 => {
            let Ok(process) = query_process_identity(*owner) else {
                return RecordedUpstreamSample::Signal(HealthSignal::Unknown);
            };
            if normalized_path(process.image_path()) != normalized_path(image_path)
                || exact_listener_owner_signal(host, port, *owner) != HealthSignal::Healthy
            {
                return RecordedUpstreamSample::Signal(HealthSignal::Unknown);
            }
            RecordedUpstreamSample::Restarted(RestartedUpstream {
                previous_pid: pid,
                pid: *owner,
                creation_time: process.creation_time(),
            })
        }
        _ => RecordedUpstreamSample::Signal(HealthSignal::Unknown),
    }
}

pub(super) fn sample_loopback_listener_owner(host: &str, port: u16, pid: u32) -> HealthSignal {
    exact_listener_owner_signal(host, port, pid)
}

fn exact_listener_owner_signal(host: &str, port: u16, pid: u32) -> HealthSignal {
    if pid == 0 || port == 0 {
        return HealthSignal::Unknown;
    }
    match loopback_listener_pids(host, port) {
        Ok(owners) if owners.is_empty() => HealthSignal::Unhealthy,
        Ok(owners) if owners.iter().all(|owner| *owner == pid) => HealthSignal::Healthy,
        Ok(_) | Err(_) => HealthSignal::Unknown,
    }
}

fn ipv4_listeners() -> Result<Vec<MIB_TCPROW_OWNER_PID>, UpstreamIdentityError> {
    let table = query_table(u32::from(AF_INET))?;
    parse_rows::<MIB_TCPROW_OWNER_PID>(&table)
}

fn ipv6_listeners() -> Result<Vec<MIB_TCP6ROW_OWNER_PID>, UpstreamIdentityError> {
    let table = query_table(u32::from(AF_INET6))?;
    parse_rows::<MIB_TCP6ROW_OWNER_PID>(&table)
}

fn query_table(family: u32) -> Result<AlignedBuffer, UpstreamIdentityError> {
    let mut required = 0_u32;
    // SAFETY: the first call intentionally passes no buffer to obtain size.
    let first = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut required,
            0,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(UpstreamIdentityError::TcpTable(
            io::Error::from_raw_os_error(first as i32),
        ));
    }
    if required < size_of::<u32>() as u32 {
        return Err(UpstreamIdentityError::MalformedTcpTable);
    }

    for _ in 0..3 {
        let mut buffer = AlignedBuffer::new(required as usize);
        let mut size = required;
        // SAFETY: buffer is aligned and writable for size bytes.
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == NO_ERROR {
            buffer.length = size as usize;
            return Ok(buffer);
        }
        if status != ERROR_INSUFFICIENT_BUFFER {
            return Err(UpstreamIdentityError::TcpTable(
                io::Error::from_raw_os_error(status as i32),
            ));
        }
        required = size;
    }
    Err(UpstreamIdentityError::TcpTableUnstable)
}

fn parse_rows<T: Copy>(buffer: &AlignedBuffer) -> Result<Vec<T>, UpstreamIdentityError> {
    if buffer.length < size_of::<u32>() {
        return Err(UpstreamIdentityError::MalformedTcpTable);
    }
    // SAFETY: buffer is aligned and contains at least the count DWORD.
    let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let row_bytes = count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(size_of::<u32>()))
        .ok_or(UpstreamIdentityError::MalformedTcpTable)?;
    if row_bytes > buffer.length {
        return Err(UpstreamIdentityError::MalformedTcpTable);
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = size_of::<u32>() + index * size_of::<T>();
        // SAFETY: row_bytes was bounded by the initialized buffer length.
        rows.push(unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) });
    }
    Ok(rows)
}

fn tcp_port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

struct AlignedBuffer {
    words: Vec<usize>,
    length: usize,
}

impl AlignedBuffer {
    fn new(bytes: usize) -> Self {
        Self {
            words: vec![0; bytes.div_ceil(size_of::<usize>())],
            length: bytes,
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast::<u8>()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast::<c_void>()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamIdentityError {
    #[error("typed upstream profile is invalid: {0}")]
    Profile(#[source] crate::protocol::ProtocolError),
    #[error("requested PID does not own the requested loopback TCP listener")]
    ListenerMismatch,
    #[error("loopback TCP listener has multiple process owners")]
    AmbiguousListenerOwners,
    #[error("loopback listener ownership changed while verifying the process")]
    ListenerChanged,
    #[error("Windows TCP owner table query failed: {0}")]
    TcpTable(#[source] io::Error),
    #[error("Windows TCP owner table changed too quickly to verify")]
    TcpTableUnstable,
    #[error("Windows TCP owner table returned malformed data")]
    MalformedTcpTable,
    #[error("upstream process query failed: {0}")]
    ProcessQuery(#[source] ProcessIdentityError),
    #[error("loopback listener process identity changed during verification")]
    ProcessIdentityChanged,
}

impl UpstreamIdentityError {
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Profile(_) => "profile_invalid",
            Self::ListenerMismatch => "listener_mismatch",
            Self::AmbiguousListenerOwners => "listener_ambiguous",
            Self::ListenerChanged => "listener_changed",
            Self::TcpTable(_) => "tcp_table_query_failed",
            Self::TcpTableUnstable => "tcp_table_unstable",
            Self::MalformedTcpTable => "tcp_table_malformed",
            Self::ProcessQuery(_) => "process_query_failed",
            Self::ProcessIdentityChanged => "process_identity_changed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UpstreamProtocol;
    use std::net::TcpListener;

    fn profile(port: u16, pid: u32) -> StartProfile {
        StartProfile {
            upstream_host: "127.0.0.1".into(),
            upstream_port: port,
            protocol: UpstreamProtocol::Socks5,
            username: None,
            password: None,
            upstream_process_id: pid,
            bypass_domains: vec![],
            bypass_cidrs: vec![],
            bypass_process_names: vec![],
        }
    }

    #[test]
    fn verifies_real_loopback_listener_pid_and_process_image() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let identity = verify_upstream_listener(&profile(port, std::process::id())).unwrap();
        assert_eq!(identity.pid(), std::process::id());
        assert!(identity.image_path().is_absolute());
        assert!(!identity.process_name().is_empty());
        assert!(identity.creation_time() > 0);
        reverify_upstream_listener(&identity, "127.0.0.1", port).unwrap();
        verify_loopback_listener_owner("127.0.0.1", port, std::process::id()).unwrap();
        assert_eq!(
            resolve_unique_loopback_listener_pid("127.0.0.1", port).unwrap(),
            std::process::id()
        );
        let resolved = resolve_unique_loopback_listener("127.0.0.1", port).unwrap();
        assert_eq!(resolved.pid(), std::process::id());
        assert_eq!(
            sample_recorded_loopback_listener(
                "127.0.0.1",
                port,
                identity.pid(),
                identity.creation_time(),
                identity.image_path(),
            ),
            HealthSignal::Healthy
        );
        assert_eq!(
            sample_loopback_listener_owner("127.0.0.1", port, u32::MAX),
            HealthSignal::Unknown
        );

        assert!(matches!(
            verify_recorded_loopback_listener(
                "127.0.0.1",
                port,
                identity.pid(),
                identity.creation_time() + 1,
                identity.image_path(),
            ),
            Err(UpstreamIdentityError::ProcessIdentityChanged)
        ));
    }

    #[test]
    fn runtime_sampler_distinguishes_missing_listener_from_identity_change() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            sample_loopback_listener_owner("127.0.0.1", port, u32::MAX),
            HealthSignal::Unknown
        );
        drop(listener);
        assert_eq!(
            sample_loopback_listener_owner("127.0.0.1", port, std::process::id()),
            HealthSignal::Unhealthy
        );
    }

    #[test]
    fn verifies_real_ipv6_loopback_listener() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let mut request = profile(listener.local_addr().unwrap().port(), std::process::id());
        request.upstream_host = "::1".into();
        let identity = verify_upstream_listener(&request).unwrap();
        assert_eq!(identity.pid(), std::process::id());
    }

    #[test]
    fn rejects_wrong_pid_and_accepts_one_wildcard_owner_for_loopback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(
            verify_upstream_listener(&profile(port, u32::MAX)),
            Err(UpstreamIdentityError::ListenerMismatch)
        ));
        let wildcard = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let wildcard_port = wildcard.local_addr().unwrap().port();
        let identity =
            verify_upstream_listener(&profile(wildcard_port, std::process::id())).unwrap();
        assert_eq!(identity.pid(), std::process::id());
        let snapshot = listener_owner_snapshot(wildcard_port).unwrap();
        assert_eq!(snapshot.ipv4_loopback, 0);
        assert_eq!(snapshot.ipv4_unspecified, 1);
    }

    #[test]
    fn port_conversion_matches_network_byte_order() {
        let port = 7078_u16;
        assert_eq!(tcp_port(u32::from(port.to_be())), port);
    }

    #[test]
    fn unique_listener_pid_rejects_missing_and_ambiguous_owners() {
        assert!(matches!(
            unique_listener_pid(vec![]),
            Err(UpstreamIdentityError::ListenerMismatch)
        ));
        assert!(matches!(
            unique_listener_pid(vec![100, 200]),
            Err(UpstreamIdentityError::AmbiguousListenerOwners)
        ));
        assert_eq!(unique_listener_pid(vec![100, 100]).unwrap(), 100);
    }

    #[test]
    fn upstream_identity_diagnostic_codes_are_fixed() {
        assert_eq!(
            UpstreamIdentityError::ListenerMismatch.diagnostic_code(),
            "listener_mismatch"
        );
        assert_eq!(
            UpstreamIdentityError::AmbiguousListenerOwners.diagnostic_code(),
            "listener_ambiguous"
        );
    }
}
