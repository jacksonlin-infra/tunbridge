use crate::local_proxy::{
    failed_test_response, project_candidates, select_discovery_ports, successful_test_response,
    validate_test_input, DesktopProbeError, DesktopProbeErrorCode, DesktopProxyProtocol,
    DiscoveryResponse, DiscoveryWarningCode, RawCandidate, RawOwner, TestInput, TestResponse,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tunbridge_core::discovery::DEFAULT_PORTS;
use tunbridge_core::platform::windows::{TcpPortProber, WinProcessLister};
use tunbridge_core::platform::{PortProber, ProcessLister};
use tunbridge_core::probe::{self, Fingerprinter, RealFingerprinter};
use tunbridge_core::profile::{Protocol, Upstream};

const TCP_OPEN_TIMEOUT: Duration = Duration::from_millis(200);
const PROTOCOL_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(12);
const DISCOVERY_WORKERS: usize = 4;
const LINK_TEST_TIMEOUT: Duration = Duration::from_secs(4);
const OWNED_ENGINE_MIXED_PORT: u16 = 25411;
const OWNED_ENGINE_CONTROLLER_PORT: u16 = 25412;

pub fn discover_local_proxies() -> DiscoveryResponse {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let listeners = match WinProcessLister.listeners() {
        Ok(listeners) => listeners,
        Err(_) => {
            warnings.push(DiscoveryWarningCode::ListenerEnumerationUnavailable);
            Vec::new()
        }
    };
    let owned_engine_ports: BTreeSet<u16> = listeners
        .iter()
        .filter(|listener| {
            is_tunbridge_owned_engine(
                listener.local_port,
                &RawOwner {
                    pid: listener.pid,
                    process_name: listener.process_name.clone(),
                    process_path: listener.process_path.clone(),
                },
            )
        })
        .map(|listener| listener.local_port)
        .collect();
    let listener_ports: Vec<u16> = listeners
        .iter()
        .filter(|listener| !owned_engine_ports.contains(&listener.local_port))
        .map(|listener| listener.local_port)
        .collect();
    let selection = select_discovery_ports(DEFAULT_PORTS, &listener_ports);
    if selection.limit_reached {
        warnings.push(DiscoveryWarningCode::ListenerLimitReached);
    }

    let mut owners_by_port: BTreeMap<u16, Vec<RawOwner>> = BTreeMap::new();
    for listener in listeners {
        owners_by_port
            .entry(listener.local_port)
            .or_default()
            .push(RawOwner {
                pid: listener.pid,
                process_name: listener.process_name,
                process_path: listener.process_path,
            });
    }

    let next = AtomicUsize::new(0);
    let deadline_reached = AtomicBool::new(false);
    let results = Mutex::new(Vec::new());
    let ports = selection.ports;
    thread::scope(|scope| {
        for _ in 0..DISCOVERY_WORKERS {
            scope.spawn(|| loop {
                if started.elapsed() >= DISCOVERY_DEADLINE {
                    deadline_reached.store(true, Ordering::Release);
                    break;
                }
                let index = next.fetch_add(1, Ordering::AcqRel);
                let Some(port) = ports.get(index).copied() else {
                    break;
                };
                // Never offer TunBridge's own Mihomo listener as an upstream.
                // Routing the owned engine back into itself would create a loop.
                if owned_engine_ports.contains(&port) {
                    continue;
                }

                let prober = TcpPortProber;
                if !prober.is_open("127.0.0.1", port, TCP_OPEN_TIMEOUT) {
                    continue;
                }
                let fingerprinter = RealFingerprinter::new(PROTOCOL_PROBE_TIMEOUT);
                let protocol = fingerprinter
                    .probe("127.0.0.1", port)
                    .map(DesktopProxyProtocol::from);
                if protocol.is_none() {
                    continue;
                }
                if started.elapsed() >= DISCOVERY_DEADLINE {
                    deadline_reached.store(true, Ordering::Release);
                    break;
                }
                let candidate = RawCandidate {
                    port,
                    protocol,
                    owners: owners_by_port.get(&port).cloned().unwrap_or_default(),
                };
                results
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(candidate);
            });
        }
    });

    if deadline_reached.load(Ordering::Acquire) {
        warnings.push(DiscoveryWarningCode::DiscoveryDeadlineReached);
    }
    let mut results = results
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    results.sort_by_key(|candidate| (candidate.port, candidate.protocol));
    project_candidates(results, warnings)
}

fn is_tunbridge_owned_engine(port: u16, owner: &RawOwner) -> bool {
    if !owner.process_name.eq_ignore_ascii_case("mihomo.exe") {
        return false;
    }
    if matches!(port, OWNED_ENGINE_MIXED_PORT | OWNED_ENGINE_CONTROLLER_PORT) {
        return true;
    }
    let Some(actual) = owner.process_path.as_deref() else {
        return false;
    };
    let Some(program_files) = std::env::var_os("ProgramFiles") else {
        return false;
    };
    let expected = PathBuf::from(program_files)
        .join("TunBridge")
        .join("mihomo.exe");
    windows_paths_equal(Path::new(actual), &expected)
}

fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
}

pub fn test_local_proxy(input: TestInput) -> Result<TestResponse, DesktopProbeError> {
    let validated = validate_test_input(input).map_err(DesktopProbeError::from)?;
    let upstream = Upstream {
        host: "127.0.0.1".into(),
        port: validated.port,
        protocol: validated.protocol.into(),
        username: validated
            .credentials
            .as_ref()
            .map(|credentials| credentials.username.expose().to_owned()),
        password: validated
            .credentials
            .as_ref()
            .map(|credentials| credentials.password.expose().to_owned()),
        udp: matches!(validated.protocol, DesktopProxyProtocol::Socks5),
    };

    let result = probe::test_upstream(
        &upstream,
        probe::DEFAULT_TEST_HOST,
        probe::DEFAULT_TEST_PORT,
        probe::DEFAULT_TEST_PATH,
        LINK_TEST_TIMEOUT,
    );
    if result.ok {
        return Ok(match (result.http_code, result.latency_ms) {
            (Some(http_code), Some(latency_ms)) => {
                successful_test_response(http_code, latency_ms, result.udp_supported)
            }
            _ => failed_test_response(crate::local_proxy::ProbeFailure::InvalidResponse),
        });
    }

    let failure = if result.http_code.is_some() {
        crate::local_proxy::ProbeFailure::InvalidResponse
    } else {
        crate::local_proxy::ProbeFailure::ConnectFailed
    };
    Ok(failed_test_response(failure))
}

/// Whether the listener has the single owner a start requires. This uses the
/// same native TCP-table check as the start preflight: the PowerShell lister
/// slows past its bound while thousands of sockets sit in TIME_WAIT after a
/// tunnel stops, which made a working upstream look refused.
pub fn local_listener_identity_available(port: u16) -> bool {
    tunbridge_service::windows::resolve_unique_loopback_listener_pid("127.0.0.1", port).is_ok()
}

impl From<Protocol> for DesktopProxyProtocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::Socks5 => Self::Socks5,
            Protocol::Http => Self::Http,
        }
    }
}

impl From<DesktopProxyProtocol> for Protocol {
    fn from(value: DesktopProxyProtocol) -> Self {
        match value {
            DesktopProxyProtocol::Socks5 => Self::Socks5,
            DesktopProxyProtocol::Http => Self::Http,
        }
    }
}

pub fn worker_failure() -> DesktopProbeError {
    DesktopProbeError::from(DesktopProbeErrorCode::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_engine_detection_accepts_installed_path_or_reserved_port() {
        let Some(program_files) = std::env::var_os("ProgramFiles") else {
            return;
        };
        let installed = PathBuf::from(program_files)
            .join("TunBridge")
            .join("mihomo.exe")
            .to_string_lossy()
            .to_string();
        assert!(is_tunbridge_owned_engine(
            50000,
            &RawOwner {
                pid: 42,
                process_name: "MIHOMO.EXE".into(),
                process_path: Some(installed),
            }
        ));
        assert!(!is_tunbridge_owned_engine(
            50000,
            &RawOwner {
                pid: 43,
                process_name: "mihomo.exe".into(),
                process_path: Some(r"C:\Users\person\proxy\mihomo.exe".into()),
            }
        ));
        assert!(is_tunbridge_owned_engine(
            OWNED_ENGINE_MIXED_PORT,
            &RawOwner {
                pid: 44,
                process_name: "mihomo.exe".into(),
                process_path: None,
            }
        ));
    }

    #[test]
    #[ignore = "requires the user-confirmed local proxy at 127.0.0.1:7078"]
    fn real_local_proxy_7078_is_discovered_and_reaches_fixed_target() {
        let discovery = discover_local_proxies();
        let candidate = discovery
            .candidates
            .iter()
            .find(|candidate| candidate.port == 7078)
            .expect("127.0.0.1:7078 was not discovered as a supported proxy");
        let input: TestInput = serde_json::from_value(serde_json::json!({
            "port": candidate.port,
            "protocol": candidate.protocol,
        }))
        .unwrap();
        let result = test_local_proxy(input).unwrap();
        let report = serde_json::json!({
            "schemaVersion": 1,
            "port": candidate.port,
            "protocol": candidate.protocol,
            "ok": result.ok,
            "httpCode": result.http_code,
            "latencyMs": result.latency_ms,
            "udpSupported": result.udp_supported,
            "errorCode": result.error_code,
        });
        println!("M3_LOCAL_PROXY_REPORT={report}");
        assert!(result.ok, "fixed connectivity test did not pass");
    }
}
