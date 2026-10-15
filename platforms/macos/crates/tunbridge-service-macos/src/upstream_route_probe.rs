//! Discover exact physical escape routes for the verified loopback proxy.

use crate::{native::process_identity, upstream_owner::VerifiedUpstream};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tunbridge_core::{
    net::{httpconnect, socks5},
    probe::{DEFAULT_TEST_HOST, DEFAULT_TEST_PATH, DEFAULT_TEST_PORT},
};
use tunbridge_service::protocol::{StartProfile, UpstreamProtocol};

const LSOF_PATH: &str = "/usr/sbin/lsof";
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_OUTPUT_BYTES: u64 = 16 * 1024;
const MAX_AUTO_BYPASS_ROUTES: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRouteProbeError {
    Invalid,
    ProbeUnavailable,
    EnumerationUnavailable,
    IdentityChanged,
}

pub fn discover_upstream_bypass_cidrs(
    profile: &StartProfile,
    upstream: &VerifiedUpstream,
) -> Result<Vec<String>, UpstreamRouteProbeError> {
    if upstream.identity.pid != profile.upstream_process_id {
        return Err(UpstreamRouteProbeError::Invalid);
    }
    let proxy = proxy_address(profile)?;
    let auth = match (&profile.username, &profile.password) {
        (Some(username), Some(password)) => Some((username.as_str(), password.as_str())),
        (None, None) => None,
        _ => return Err(UpstreamRouteProbeError::Invalid),
    };
    let mut held_tunnel: TcpStream = match profile.protocol {
        UpstreamProtocol::Socks5 => socks5::connect(
            proxy,
            DEFAULT_TEST_HOST,
            DEFAULT_TEST_PORT,
            auth,
            PROBE_TIMEOUT,
        ),
        UpstreamProtocol::Http => httpconnect::connect(
            proxy,
            DEFAULT_TEST_HOST,
            DEFAULT_TEST_PORT,
            auth,
            PROBE_TIMEOUT,
        ),
    }
    .map_err(|_| UpstreamRouteProbeError::ProbeUnavailable)?;
    // A CONNECT reply can be optimistic: Clash-compatible proxies may defer
    // selecting and dialing the real outbound node until the first payload.
    // Complete one bounded HTTP exchange before enumerating the proxy PID so
    // lsof observes the actual transport endpoint rather than only an
    // unrelated pre-existing DNS connection.
    prime_http_probe(&mut held_tunnel)?;

    let endpoints = connected_remote_ipv4(upstream.identity.pid)?;
    if endpoints.is_empty()
        || process_identity(upstream.identity.pid)
            .map_err(|_| UpstreamRouteProbeError::IdentityChanged)?
            != upstream.identity
    {
        return Err(UpstreamRouteProbeError::IdentityChanged);
    }
    Ok(endpoints
        .into_iter()
        .map(|address| format!("{address}/32"))
        .collect())
}

fn prime_http_probe(stream: &mut TcpStream) -> Result<(), UpstreamRouteProbeError> {
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(PROBE_TIMEOUT)))
        .map_err(|_| UpstreamRouteProbeError::ProbeUnavailable)?;
    let request = format!(
        "GET {DEFAULT_TEST_PATH} HTTP/1.1\r\nHost: {DEFAULT_TEST_HOST}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| UpstreamRouteProbeError::ProbeUnavailable)?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 512];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut buffer)
            .map_err(|_| UpstreamRouteProbeError::ProbeUnavailable)?;
        if read == 0 || response.len() + read > 4096 {
            return Err(UpstreamRouteProbeError::ProbeUnavailable);
        }
        response.extend_from_slice(&buffer[..read]);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(UpstreamRouteProbeError::ProbeUnavailable)?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| UpstreamRouteProbeError::ProbeUnavailable)?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(UpstreamRouteProbeError::ProbeUnavailable)?;
    if !(200..400).contains(&status)
        || headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("connection: close"))
    {
        return Err(UpstreamRouteProbeError::ProbeUnavailable);
    }
    Ok(())
}

fn proxy_address(profile: &StartProfile) -> Result<SocketAddr, UpstreamRouteProbeError> {
    let host = match profile.upstream_host.as_str() {
        "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "::1" => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        _ => return Err(UpstreamRouteProbeError::Invalid),
    };
    if profile.upstream_port == 0 {
        return Err(UpstreamRouteProbeError::Invalid);
    }
    Ok(SocketAddr::new(host, profile.upstream_port))
}

fn connected_remote_ipv4(pid: u32) -> Result<BTreeSet<Ipv4Addr>, UpstreamRouteProbeError> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(UpstreamRouteProbeError::Invalid);
    }
    validate_lsof()?;
    let mut child = Command::new(LSOF_PATH)
        .args(["-nP", "-a", "-p"])
        .arg(pid.to_string())
        .args(["-iTCP", "-sTCP:ESTABLISHED", "-Fpn"])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| UpstreamRouteProbeError::EnumerationUnavailable)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(UpstreamRouteProbeError::EnumerationUnavailable)?;
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
                return Err(UpstreamRouteProbeError::EnumerationUnavailable);
            }
        }
    };
    let (read_result, output) = reader
        .join()
        .map_err(|_| UpstreamRouteProbeError::EnumerationUnavailable)?;
    if !status.success() || read_result.is_err() || output.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(UpstreamRouteProbeError::EnumerationUnavailable);
    }
    parse_lsof_remote_ipv4(&output, pid)
}

fn parse_lsof_remote_ipv4(
    output: &[u8],
    expected_pid: u32,
) -> Result<BTreeSet<Ipv4Addr>, UpstreamRouteProbeError> {
    let text = std::str::from_utf8(output).map_err(|_| UpstreamRouteProbeError::Invalid)?;
    let mut saw_pid = false;
    let mut endpoints = BTreeSet::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix('p') {
            if value.parse::<u32>().ok() != Some(expected_pid) || saw_pid {
                return Err(UpstreamRouteProbeError::Invalid);
            }
            saw_pid = true;
        } else if let Some(value) = line.strip_prefix('f') {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(UpstreamRouteProbeError::Invalid);
            }
        } else if let Some(value) = line.strip_prefix('n') {
            let remote = value
                .split_once("->")
                .and_then(|(_, remote)| remote.parse::<SocketAddr>().ok())
                .ok_or(UpstreamRouteProbeError::Invalid)?;
            if let IpAddr::V4(address) = remote.ip() {
                if !address.is_loopback()
                    && !address.is_unspecified()
                    && !address.is_multicast()
                    && address != Ipv4Addr::BROADCAST
                    && !is_mihomo_fake_ip(address)
                {
                    endpoints.insert(address);
                    if endpoints.len() > MAX_AUTO_BYPASS_ROUTES {
                        return Err(UpstreamRouteProbeError::Invalid);
                    }
                }
            }
        } else {
            return Err(UpstreamRouteProbeError::Invalid);
        }
    }
    if !saw_pid {
        return Err(UpstreamRouteProbeError::Invalid);
    }
    Ok(endpoints)
}

fn is_mihomo_fake_ip(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 198 && matches!(octets[1], 18 | 19)
}

fn validate_lsof() -> Result<(), UpstreamRouteProbeError> {
    let metadata = fs::symlink_metadata(Path::new(LSOF_PATH))
        .map_err(|_| UpstreamRouteProbeError::EnumerationUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(UpstreamRouteProbeError::EnumerationUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, sync::mpsc};

    #[test]
    fn http_probe_sends_payload_and_keeps_the_tunnel_open_for_enumeration() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let read = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..read]).unwrap();
            assert!(request.contains("GET /generate_204 HTTP/1.1"));
            assert!(request.contains("Connection: keep-alive"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            let mut marker = [0_u8; 1];
            stream.read_exact(&mut marker).unwrap();
            sender.send(marker[0]).unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        prime_http_probe(&mut stream).unwrap();
        stream.write_all(&[7]).unwrap();
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 7);
        server.join().unwrap();
    }

    #[test]
    fn parser_extracts_deduplicated_exact_ipv4_remote_endpoints() {
        let output = b"p788\nf7\nn127.0.0.1:7897->127.0.0.1:50100\nf26\nn192.168.64.3:50101->17.188.170.72:443\nf27\nn192.168.64.3:50102->104.16.132.229:443\nf28\nn192.168.64.3:50103->17.188.170.72:443\nf29\nn198.18.0.1:50104->198.18.0.19:80\n";
        assert_eq!(
            parse_lsof_remote_ipv4(output, 788).unwrap(),
            BTreeSet::from([
                "17.188.170.72".parse().unwrap(),
                "104.16.132.229".parse().unwrap(),
            ])
        );
    }

    #[test]
    fn parser_fails_closed_on_pid_mismatch_malformed_or_oversized_data() {
        for output in [
            b"p789\nf7\nn192.0.2.1:1->198.51.100.1:2\n".as_slice(),
            b"p788\nf7u\nn192.0.2.1:1->198.51.100.1:2\n".as_slice(),
            b"p788\nf7\nnnot-an-endpoint\n".as_slice(),
            b"f7\nn192.0.2.1:1->198.51.100.1:2\n".as_slice(),
            &[0xff],
        ] {
            assert_eq!(
                parse_lsof_remote_ipv4(output, 788),
                Err(UpstreamRouteProbeError::Invalid)
            );
        }

        let mut oversized = b"p788\n".to_vec();
        for index in 1..=29 {
            oversized.extend_from_slice(
                format!("f{index}\nn192.0.2.1:1->198.51.100.{index}:2\n").as_bytes(),
            );
        }
        assert_eq!(
            parse_lsof_remote_ipv4(&oversized, 788),
            Err(UpstreamRouteProbeError::Invalid)
        );
    }
}
