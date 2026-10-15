use crate::net::{http, httpconnect, socks5};
use crate::profile::{Protocol, Upstream};
use serde::Serialize;
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const DEFAULT_TEST_HOST: &str = "cp.cloudflare.com";
pub const DEFAULT_TEST_PORT: u16 = 80;
pub const DEFAULT_TEST_PATH: &str = "/generate_204";

pub trait Fingerprinter {
    fn probe(&self, host: &str, port: u16) -> Option<Protocol>;
}

pub struct RealFingerprinter {
    timeout: Duration,
}

impl RealFingerprinter {
    pub fn new(timeout: Duration) -> Self {
        RealFingerprinter { timeout }
    }
}

fn parse_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let mut addresses = (host, port).to_socket_addrs().ok()?;
    addresses
        .find(SocketAddr::is_ipv4)
        .or_else(|| (host, port).to_socket_addrs().ok()?.next())
}

impl Fingerprinter for RealFingerprinter {
    fn probe(&self, host: &str, port: u16) -> Option<Protocol> {
        let addr = parse_addr(host, port)?;
        if socks5::handshake_only(addr, self.timeout).is_ok() {
            return Some(Protocol::Socks5);
        }
        // http proxy: a successful CONNECT proves it speaks http-proxy.
        if httpconnect::connect(
            addr,
            DEFAULT_TEST_HOST,
            DEFAULT_TEST_PORT,
            None,
            self.timeout,
        )
        .is_ok()
        {
            return Some(Protocol::Http);
        }
        None
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkTestResult {
    pub ok: bool,
    pub http_code: Option<u16>,
    pub latency_ms: Option<u128>,
    pub udp_supported: bool,
    pub error: Option<String>,
}

pub fn test_upstream(
    upstream: &Upstream,
    test_host: &str,
    test_port: u16,
    test_path: &str,
    timeout: Duration,
) -> LinkTestResult {
    let addr = match parse_addr(&upstream.host, upstream.port) {
        Some(a) => a,
        None => {
            return LinkTestResult {
                ok: false,
                http_code: None,
                latency_ms: None,
                udp_supported: false,
                error: Some("invalid upstream address".into()),
            }
        }
    };
    let auth = match (&upstream.username, &upstream.password) {
        (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
        _ => None,
    };

    let started = Instant::now();
    let tunnel: crate::Result<TcpStream> = match upstream.protocol {
        Protocol::Socks5 => socks5::connect(addr, test_host, test_port, auth, timeout),
        Protocol::Http => httpconnect::connect(addr, test_host, test_port, auth, timeout),
    };

    let mut stream = match tunnel {
        Ok(s) => s,
        Err(e) => {
            return LinkTestResult {
                ok: false,
                http_code: None,
                latency_ms: None,
                udp_supported: false,
                error: Some(e.to_string()),
            }
        }
    };

    let udp_supported =
        matches!(upstream.protocol, Protocol::Socks5) && socks5::udp_associate_ok(addr, timeout);

    match http::get_status(&mut stream, test_host, test_path, &[], timeout) {
        Ok((code, _)) => LinkTestResult {
            ok: (200..400).contains(&code),
            http_code: Some(code),
            latency_ms: Some(started.elapsed().as_millis()),
            udp_supported,
            error: None,
        },
        Err(e) => LinkTestResult {
            ok: false,
            http_code: None,
            latency_ms: None,
            udp_supported,
            error: Some(e.to_string()),
        },
    }
}

/// Test ordinary system traffic after TUN startup. DNS resolution and the TCP
/// connection both use the host network stack, so with auto-route active this
/// exercises the transparent path rather than connecting to the upstream port
/// explicitly.
pub fn test_transparent_http(
    host: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> crate::Result<u16> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| crate::CoreError::Io(format!("could not resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| crate::CoreError::Io(format!("no address resolved for {host}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| crate::CoreError::Io(format!("transparent connect failed: {e}")))?;
    let (code, _) = http::get_status(&mut stream, host, path, &[], timeout)?;
    if (200..400).contains(&code) {
        Ok(code)
    } else {
        Err(crate::CoreError::Io(format!(
            "transparent HTTP probe returned {code}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Protocol, Upstream};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;
    use std::time::Duration;

    // A socks5 server that ALSO tunnels a canned 204 to whatever GET arrives.
    fn spawn_socks5_then_204() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..8 {
                let (mut s, _) = match l.accept() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                thread::spawn(move || {
                    let mut hello = [0u8; 2];
                    if s.read_exact(&mut hello).is_err() {
                        return;
                    }
                    let mut m = vec![0u8; hello[1] as usize];
                    if s.read_exact(&mut m).is_err() {
                        return;
                    }
                    s.write_all(&[0x05, 0x00]).unwrap();
                    let mut head = [0u8; 4];
                    if s.read_exact(&mut head).is_err() {
                        return;
                    } // handshake_only path
                      // read domain address
                    if head[3] == 0x03 {
                        let mut l1 = [0u8; 1];
                        s.read_exact(&mut l1).unwrap();
                        let mut d = vec![0u8; l1[0] as usize + 2];
                        s.read_exact(&mut d).unwrap();
                    }
                    if head[1] == 0x03 {
                        // UDP associate probe: reply success, done
                        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .unwrap();
                        return;
                    }
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .unwrap();
                    let mut req = [0u8; 256];
                    let _ = s.read(&mut req).unwrap();
                    s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                });
            }
        });
        addr
    }

    #[test]
    fn fingerprint_detects_socks5() {
        let addr = spawn_socks5_then_204();
        let fp = RealFingerprinter::new(Duration::from_secs(3));
        assert_eq!(fp.probe("127.0.0.1", addr.port()), Some(Protocol::Socks5));
    }

    #[test]
    fn localhost_resolves_for_manual_upstreams() {
        let address = parse_addr("localhost", 7078).unwrap();
        assert!(address.ip().is_loopback());
        assert_eq!(address.port(), 7078);
    }

    #[test]
    fn test_upstream_reports_204_ok() {
        let addr = spawn_socks5_then_204();
        let up = Upstream {
            host: "127.0.0.1".into(),
            port: addr.port(),
            protocol: Protocol::Socks5,
            username: None,
            password: None,
            udp: false,
        };
        let r = test_upstream(
            &up,
            "cp.cloudflare.com",
            80,
            "/generate_204",
            Duration::from_secs(3),
        );
        assert!(r.ok, "expected ok, got {:?}", r);
        assert_eq!(r.http_code, Some(204));
    }

    #[test]
    fn transparent_http_reports_204() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let code = test_transparent_http(
            "127.0.0.1",
            addr.port(),
            "/generate_204",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(code, 204);
    }
}
