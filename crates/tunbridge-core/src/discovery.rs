use crate::platform::{PortProber, ProcessLister};
use crate::probe::Fingerprinter;
use crate::profile::Protocol;
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;

pub const DEFAULT_PORTS: &[u16] = &[
    7890, 7891, 7892, 1080, 1081, 8080, 8118, 8889, 10808, 10809, 2080, 7078,
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Candidate {
    pub port: u16,
    pub protocol: Option<Protocol>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryReport {
    pub candidates: Vec<Candidate>,
    pub warnings: Vec<String>,
}

pub fn discover(
    ports: &[u16],
    prober: &dyn PortProber,
    lister: &dyn ProcessLister,
    fp: &dyn Fingerprinter,
    timeout: Duration,
) -> DiscoveryReport {
    let (listeners, warnings) = match lister.listeners() {
        Ok(rows) => (rows, Vec::new()),
        Err(error) => (
            Vec::new(),
            vec![format!(
                "could not enumerate loopback listeners or process owners: {error}"
            )],
        ),
    };
    let candidate_ports: BTreeSet<u16> = ports
        .iter()
        .copied()
        .chain(listeners.iter().map(|listener| listener.local_port))
        .collect();
    let mut out = Vec::new();
    for port in candidate_ports {
        if !prober.is_open("127.0.0.1", port, timeout) {
            continue;
        }
        let Some(protocol) = fp.probe("127.0.0.1", port) else {
            continue;
        };
        let owner = listeners.iter().find(|l| l.local_port == port);
        out.push(Candidate {
            port,
            protocol: Some(protocol),
            process_name: owner.map(|l| l.process_name.clone()),
            process_path: owner.and_then(|l| l.process_path.clone()),
            pid: owner.map(|l| l.pid),
        });
    }
    DiscoveryReport {
        candidates: out,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::model::Listener;
    use crate::platform::{PortProber, ProcessLister};
    use crate::probe::Fingerprinter;
    use crate::Result;
    use std::time::Duration;

    struct FakeProber {
        open: Vec<u16>,
    }
    impl PortProber for FakeProber {
        fn is_open(&self, _host: &str, port: u16, _t: Duration) -> bool {
            self.open.contains(&port)
        }
    }
    struct FakeLister {
        rows: Vec<Listener>,
        fail: bool,
    }
    impl ProcessLister for FakeLister {
        fn listeners(&self) -> Result<Vec<Listener>> {
            if self.fail {
                Err(crate::CoreError::Discovery("access denied".into()))
            } else {
                Ok(self.rows.clone())
            }
        }
    }
    struct FakeFp;
    impl Fingerprinter for FakeFp {
        fn probe(&self, _host: &str, port: u16) -> Option<Protocol> {
            if matches!(port, 7078 | 45678) {
                Some(Protocol::Socks5)
            } else {
                None
            }
        }
    }

    #[test]
    fn discover_joins_open_ports_with_process_and_protocol() {
        let prober = FakeProber { open: vec![7078] };
        let lister = FakeLister {
            rows: vec![Listener {
                local_port: 7078,
                pid: 47440,
                process_name: "ExampleProxy_Mix.bin".into(),
                process_path: Some("C:\\a\\ExampleProxy_Mix.bin".into()),
            }],
            fail: false,
        };
        let fp = FakeFp;
        let got = discover(
            &[7078, 1080, 8080],
            &prober,
            &lister,
            &fp,
            Duration::from_millis(50),
        );
        assert_eq!(got.candidates.len(), 1);
        assert_eq!(got.candidates[0].port, 7078);
        assert_eq!(got.candidates[0].protocol, Some(Protocol::Socks5));
        assert_eq!(
            got.candidates[0].process_name.as_deref(),
            Some("ExampleProxy_Mix.bin")
        );
        assert_eq!(got.candidates[0].pid, Some(47440));
        assert!(got.warnings.is_empty());
    }

    #[test]
    fn discover_skips_closed_ports() {
        let prober = FakeProber { open: vec![] };
        let lister = FakeLister {
            rows: vec![],
            fail: false,
        };
        let got = discover(
            &[1080, 8080],
            &prober,
            &lister,
            &FakeFp,
            Duration::from_millis(50),
        );
        assert!(got.candidates.is_empty());
    }

    #[test]
    fn discover_includes_nonstandard_loopback_listener_ports() {
        let prober = FakeProber { open: vec![45678] };
        let lister = FakeLister {
            rows: vec![Listener {
                local_port: 45678,
                pid: 99,
                process_name: "custom-proxy.exe".into(),
                process_path: Some("C:\\custom-proxy.exe".into()),
            }],
            fail: false,
        };
        let got = discover(
            &[1080],
            &prober,
            &lister,
            &FakeFp,
            Duration::from_millis(50),
        );
        assert_eq!(got.candidates.len(), 1);
        assert_eq!(got.candidates[0].port, 45678);
        assert_eq!(
            got.candidates[0].process_name.as_deref(),
            Some("custom-proxy.exe")
        );
    }

    #[test]
    fn discover_reports_process_enumeration_failures() {
        let prober = FakeProber { open: vec![7078] };
        let lister = FakeLister {
            rows: vec![],
            fail: true,
        };
        let got = discover(
            &[7078],
            &prober,
            &lister,
            &FakeFp,
            Duration::from_millis(50),
        );
        assert_eq!(got.candidates.len(), 1);
        assert_eq!(got.warnings.len(), 1);
        assert!(got.warnings[0].contains("access denied"));
    }

    #[test]
    fn discover_filters_non_proxy_listeners() {
        let prober = FakeProber {
            open: vec![7078, 6379],
        };
        let lister = FakeLister {
            rows: vec![
                Listener {
                    local_port: 7078,
                    pid: 7,
                    process_name: "proxy.exe".into(),
                    process_path: None,
                },
                Listener {
                    local_port: 6379,
                    pid: 8,
                    process_name: "redis-server.exe".into(),
                    process_path: None,
                },
            ],
            fail: false,
        };
        let got = discover(&[], &prober, &lister, &FakeFp, Duration::from_millis(50));
        assert_eq!(got.candidates.len(), 1);
        assert_eq!(got.candidates[0].port, 7078);
    }
}
