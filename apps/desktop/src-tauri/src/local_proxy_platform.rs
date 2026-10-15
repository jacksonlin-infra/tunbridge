use crate::local_proxy::{
    failed_test_response, project_candidates, select_discovery_ports, successful_test_response,
    validate_test_input, DesktopProbeError, DesktopProbeErrorCode, DesktopProxyProtocol,
    DiscoveryResponse, DiscoveryWarningCode, RawCandidate, TestInput, TestResponse,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tunbridge_core::discovery::DEFAULT_PORTS;
use tunbridge_core::platform::stub::TcpPortProber;
use tunbridge_core::platform::PortProber;
use tunbridge_core::probe::{self, Fingerprinter, RealFingerprinter};
use tunbridge_core::profile::{Protocol, Upstream};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tunbridge_desktop_contract::adapter::{ListenerIdentity, ProcessDiscovery};

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
    let listeners = match platform_listeners() {
        Ok(listeners) => listeners,
        Err(_) => {
            warnings.push(DiscoveryWarningCode::ListenerEnumerationUnavailable);
            Vec::new()
        }
    };
    let owned_engine_ports: BTreeSet<u16> = listeners
        .iter()
        .filter(|listener| is_tunbridge_owned_engine(listener))
        .map(|listener| listener.port)
        .collect();
    let listener_ports: Vec<u16> = listeners
        .iter()
        .filter(|listener| !owned_engine_ports.contains(&listener.port))
        .map(|listener| listener.port)
        .collect();
    let selection = select_discovery_ports(DEFAULT_PORTS, &listener_ports);
    if selection.limit_reached {
        warnings.push(DiscoveryWarningCode::ListenerLimitReached);
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
                results
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(RawCandidate {
                        port,
                        protocol,
                        owners: listeners
                            .iter()
                            .filter(|listener| listener.port == port)
                            .filter_map(|listener| {
                                Some(crate::local_proxy::RawOwner {
                                    pid: listener.process_id?,
                                    process_name: listener.process_name.clone()?,
                                    process_path: listener
                                        .process_path
                                        .as_ref()
                                        .map(|path| path.to_string_lossy().into_owned()),
                                })
                            })
                            .collect(),
                    });
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_tunbridge_owned_engine(listener: &ListenerIdentity) -> bool {
    if !listener
        .process_name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("mihomo"))
    {
        return false;
    }
    if matches!(
        listener.port,
        OWNED_ENGINE_MIXED_PORT | OWNED_ENGINE_CONTROLLER_PORT
    ) {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        listener.process_path.as_deref()
            == Some(std::path::Path::new(tunbridge_service_linux::ENGINE_PATH))
    }
    #[cfg(target_os = "macos")]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn platform_listeners() -> Result<
    Vec<tunbridge_desktop_contract::adapter::ListenerIdentity>,
    tunbridge_desktop_contract::adapter::AdapterError,
> {
    tunbridge_platform_linux::LinuxProcessDiscovery.loopback_listeners()
}

#[cfg(target_os = "macos")]
fn platform_listeners() -> Result<
    Vec<tunbridge_desktop_contract::adapter::ListenerIdentity>,
    tunbridge_desktop_contract::adapter::AdapterError,
> {
    tunbridge_platform_macos::MacosProcessDiscovery.loopback_listeners()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_listeners() -> Result<
    Vec<tunbridge_desktop_contract::adapter::ListenerIdentity>,
    tunbridge_desktop_contract::adapter::AdapterError,
> {
    Err(tunbridge_desktop_contract::adapter::AdapterError::not_ready())
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

pub fn local_listener_identity_available(port: u16) -> bool {
    let Ok(listeners) = platform_listeners() else {
        return false;
    };
    let owners: BTreeSet<u32> = listeners
        .into_iter()
        .filter(|listener| listener.port == port)
        .filter_map(|listener| listener.process_id)
        .collect();
    owners.len() == 1
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn listener(port: u16, name: &str, path: Option<&str>) -> ListenerIdentity {
        ListenerIdentity {
            address: "127.0.0.1".into(),
            port,
            process_id: Some(42),
            process_name: Some(name.into()),
            process_path: path.map(PathBuf::from),
        }
    }

    #[test]
    fn owned_engine_detection_accepts_fixed_path_or_reserved_ports() {
        assert!(is_tunbridge_owned_engine(&listener(
            50000,
            "mihomo",
            Some(tunbridge_service_linux::ENGINE_PATH),
        )));
        assert!(is_tunbridge_owned_engine(&listener(
            OWNED_ENGINE_MIXED_PORT,
            "MIHOMO",
            None,
        )));
        assert!(is_tunbridge_owned_engine(&listener(
            OWNED_ENGINE_CONTROLLER_PORT,
            "mihomo",
            None,
        )));
    }

    #[test]
    fn owned_engine_detection_preserves_unrelated_proxy_processes() {
        assert!(!is_tunbridge_owned_engine(&listener(
            OWNED_ENGINE_MIXED_PORT,
            "proxy-client",
            None,
        )));
        assert!(!is_tunbridge_owned_engine(&listener(
            50000,
            "mihomo",
            Some("/opt/proxy/mihomo"),
        )));
    }
}
