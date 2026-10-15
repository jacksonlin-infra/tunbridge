//! Read-only Darwin ownership attribution for the fixed Mihomo controller.

use crate::{
    controller::{ControllerError, ControllerOwnerVerifier},
    engine_config::CONTROLLER_ADDRESS,
    lifecycle_plan::ProcessIdentity,
    native::{process_credentials, process_executable_path, process_identity},
};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const LSOF_PATH: &str = "/usr/sbin/lsof";
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_OUTPUT_BYTES: u64 = 4096;
const MAX_LISTENER_PIDS: usize = 8;
/// A full check enumerates every listener as root and hashes the whole engine
/// executable. Observability requests and the log monitor ask several times a
/// second, and on older Macs that work starved lease renewals behind the
/// helper's request lock until the lease expired. Between full checks the
/// exact process proven to be the sole listener is re-confirmed cheaply: no
/// other process can take the controller address while it still holds it.
const FULL_VERIFY_INTERVAL: Duration = Duration::from_secs(30);

static LAST_FULL_VERIFICATION: Mutex<Option<(ProcessIdentity, Instant)>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeControllerOwnerVerifier;

impl ControllerOwnerVerifier for NativeControllerOwnerVerifier {
    fn is_exact_owner(
        &mut self,
        address: &str,
        expected: &ProcessIdentity,
    ) -> Result<bool, ControllerError> {
        if address != CONTROLLER_ADDRESS {
            return Err(ControllerError::Invalid);
        }
        let address = parse_loopback_address(address)?;
        let now = Instant::now();
        let mut last = LAST_FULL_VERIFICATION
            .lock()
            .map_err(|_| ControllerError::Unavailable)?;
        if recently_verified(last.as_ref(), expected, now) && same_running_process(expected) {
            return Ok(true);
        }
        let owned = exact_listener_owner(address, expected)?;
        *last = owned.then(|| (expected.clone(), now));
        Ok(owned)
    }
}

fn recently_verified(
    last: Option<&(ProcessIdentity, Instant)>,
    expected: &ProcessIdentity,
    now: Instant,
) -> bool {
    last.is_some_and(|(identity, at)| {
        identity == expected && now.saturating_duration_since(*at) < FULL_VERIFY_INTERVAL
    })
}

/// The verified engine is still the same process running the same executable
/// file: the start time rules out PID reuse, the file id rules out a swapped
/// executable path.
fn same_running_process(expected: &ProcessIdentity) -> bool {
    process_credentials(expected.pid)
        .is_ok_and(|credentials| credentials.start_time_ns == expected.start_time_ns)
        && process_executable_path(expected.pid)
            .ok()
            .and_then(|path| fs::metadata(path).ok())
            .is_some_and(|metadata| metadata.ino() == expected.executable_file_id)
}

fn exact_listener_owner(
    address: SocketAddr,
    expected: &ProcessIdentity,
) -> Result<bool, ControllerError> {
    let pids = listener_pids(address)?;
    if pids.len() != 1 || !pids.contains(&expected.pid) {
        return Ok(false);
    }
    process_identity(expected.pid)
        .map(|observed| observed == *expected)
        .map_err(|_| ControllerError::Unavailable)
}

pub(crate) fn listener_pids(address: SocketAddr) -> Result<BTreeSet<u32>, ControllerError> {
    validate_lsof()?;
    let selector = match address.ip() {
        IpAddr::V4(ip) if ip.is_loopback() && address.port() != 0 => {
            format!("-iTCP@{ip}:{}", address.port())
        }
        IpAddr::V6(ip) if ip.is_loopback() && address.port() != 0 => {
            format!("-iTCP@[{ip}]:{}", address.port())
        }
        _ => return Err(ControllerError::Invalid),
    };
    let mut child = Command::new(LSOF_PATH)
        .args(["-nP", "-a"])
        .arg(selector)
        .args(["-sTCP:LISTEN", "-Fp"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ControllerError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(ControllerError::Unavailable)?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut output);
        (result, output)
    });

    let deadline = Instant::now() + ENUMERATION_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(ControllerError::Unavailable);
            }
        }
    };
    let (read_result, output) = reader.join().map_err(|_| ControllerError::Unavailable)?;
    if read_result.is_err() || output.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(ControllerError::ResponseTooLarge);
    }
    parse_lsof_status(status, &output)
}

fn parse_lsof_status(status: ExitStatus, output: &[u8]) -> Result<BTreeSet<u32>, ControllerError> {
    if status.success() {
        let pids = parse_lsof_pids(output)?;
        if pids.is_empty() {
            Err(ControllerError::Protocol)
        } else {
            Ok(pids)
        }
    } else if status.code() == Some(1) && output.is_empty() {
        Ok(BTreeSet::new())
    } else {
        Err(ControllerError::Unavailable)
    }
}

fn parse_lsof_pids(output: &[u8]) -> Result<BTreeSet<u32>, ControllerError> {
    let text = std::str::from_utf8(output).map_err(|_| ControllerError::Protocol)?;
    let mut pids = BTreeSet::new();
    for line in text.lines() {
        if let Some(descriptor) = line.strip_prefix('f') {
            if descriptor.is_empty() || !descriptor.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ControllerError::Protocol);
            }
            continue;
        }
        let value = line
            .strip_prefix('p')
            .filter(|value| !value.is_empty())
            .ok_or(ControllerError::Protocol)?;
        let pid = value
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 1 && *pid <= i32::MAX as u32)
            .ok_or(ControllerError::Protocol)?;
        pids.insert(pid);
        if pids.len() > MAX_LISTENER_PIDS {
            return Err(ControllerError::ResponseTooLarge);
        }
    }
    Ok(pids)
}

fn parse_loopback_address(address: &str) -> Result<SocketAddr, ControllerError> {
    address
        .parse::<SocketAddr>()
        .ok()
        .filter(|address| address.ip() == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        .filter(|address| address.port() != 0)
        .ok_or(ControllerError::Invalid)
}

fn validate_lsof() -> Result<(), ControllerError> {
    let metadata =
        fs::symlink_metadata(Path::new(LSOF_PATH)).map_err(|_| ControllerError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControllerError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parser_accepts_unique_bounded_pids_and_rejects_malformed_rows() {
        assert_eq!(
            parse_lsof_pids(b"p42\nf3\np42\nf4\np700\nf11\n").unwrap(),
            BTreeSet::from([42, 700])
        );
        for malformed in [
            b"".as_slice(),
            b"cMihomo\n".as_slice(),
            b"p0\n".as_slice(),
            b"p1\n".as_slice(),
            b"p-1\n".as_slice(),
            b"p4294967295\n".as_slice(),
            b"p7 trailing\n".as_slice(),
            b"f3u\n".as_slice(),
            &[0xff],
        ] {
            if malformed.is_empty() {
                assert!(parse_lsof_pids(malformed).unwrap().is_empty());
            } else {
                assert_eq!(parse_lsof_pids(malformed), Err(ControllerError::Protocol));
            }
        }
    }

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn full_verification_is_reused_only_for_the_same_engine_within_the_interval() {
        let now = Instant::now();
        let verified = (identity(700), now);
        assert!(recently_verified(Some(&verified), &identity(700), now));
        assert!(recently_verified(
            Some(&verified),
            &identity(700),
            now + FULL_VERIFY_INTERVAL - Duration::from_millis(1)
        ));
        assert!(!recently_verified(
            Some(&verified),
            &identity(700),
            now + FULL_VERIFY_INTERVAL
        ));
        assert!(!recently_verified(Some(&verified), &identity(701), now));
        let mut restarted = identity(700);
        restarted.start_time_ns = 101;
        assert!(!recently_verified(Some(&verified), &restarted, now));
        assert!(!recently_verified(None, &identity(700), now));
    }

    #[test]
    fn cheap_recheck_requires_the_live_process_and_its_executable() {
        let pid = std::process::id();
        let credentials = process_credentials(pid).unwrap();
        let path = process_executable_path(pid).unwrap();
        let mut current = identity(pid);
        current.start_time_ns = credentials.start_time_ns;
        current.executable_file_id = fs::metadata(path).unwrap().ino();
        assert!(same_running_process(&current));

        let mut reused_pid = current.clone();
        reused_pid.start_time_ns += 1;
        assert!(!same_running_process(&reused_pid));
        let mut swapped_executable = current;
        swapped_executable.executable_file_id += 1;
        assert!(!same_running_process(&swapped_executable));
    }

    #[test]
    fn fixed_verifier_rejects_any_caller_selected_endpoint() {
        let mut verifier = NativeControllerOwnerVerifier;
        let expected = process_identity(std::process::id()).unwrap();
        assert_eq!(
            verifier.is_exact_owner("127.0.0.1:25413", &expected),
            Err(ControllerError::Invalid)
        );
        assert_eq!(
            parse_loopback_address("0.0.0.0:25412"),
            Err(ControllerError::Invalid)
        );
        assert_eq!(
            parse_loopback_address("[::1]:25412"),
            Err(ControllerError::Invalid)
        );
    }

    #[test]
    fn native_enumerator_attributes_ephemeral_loopback_listener_to_exact_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = process_identity(std::process::id()).unwrap();
        assert_eq!(
            listener_pids(address).unwrap(),
            BTreeSet::from([std::process::id()])
        );
        assert!(exact_listener_owner(address, &expected).unwrap());

        let mut stale = expected;
        stale.start_time_ns += 1;
        assert!(!exact_listener_owner(address, &stale).unwrap());
    }
}
