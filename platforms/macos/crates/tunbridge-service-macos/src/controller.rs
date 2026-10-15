//! Bounded, authenticated Mihomo controller evidence for Darwin.
//!
//! The controller is fixed to loopback, and its responses are only trusted
//! when the listener is attributed to the exact engine identity both before
//! and after the two authenticated reads.

use crate::{
    engine_config::CONTROLLER_ADDRESS, lifecycle_plan::ProcessIdentity,
    tun_attribution::ControllerTunEvidence,
};
use serde::Deserialize;
use std::{
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
use zeroize::Zeroize;

const MAX_RESPONSE_BYTES: usize = tunbridge_core::engine::MAX_ENGINE_RESPONSE_BYTES;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerError {
    Invalid,
    OwnershipMismatch,
    Unavailable,
    Protocol,
    ResponseTooLarge,
    StateMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerVersion {
    pub version: String,
}

pub trait ControllerTransport {
    fn get(&mut self, path: &'static str, secret: &str) -> Result<Vec<u8>, ControllerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityMethod {
    Get,
    Delete,
}

pub trait ObservabilityControllerTransport {
    fn request(
        &mut self,
        method: ObservabilityMethod,
        connection_id: Option<&str>,
        secret: &str,
    ) -> Result<Vec<u8>, ControllerError>;
}

pub trait ControllerOwnerVerifier {
    fn is_exact_owner(
        &mut self,
        address: &str,
        expected: &ProcessIdentity,
    ) -> Result<bool, ControllerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpControllerTransport;

impl ControllerTransport for TcpControllerTransport {
    fn get(&mut self, path: &'static str, secret: &str) -> Result<Vec<u8>, ControllerError> {
        if !matches!(path, "/version" | "/configs") || !valid_secret(secret) {
            return Err(ControllerError::Invalid);
        }
        let address: SocketAddr = CONTROLLER_ADDRESS
            .parse()
            .map_err(|_| ControllerError::Invalid)?;
        if !address.ip().is_loopback() {
            return Err(ControllerError::Invalid);
        }
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .map_err(|_| ControllerError::Unavailable)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|_| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|_| ControllerError::Unavailable)?;
        let request = encode_get_request(path, secret)?;
        stream
            .write_all(request.as_bytes())
            .map_err(|_| ControllerError::Unavailable)?;

        let mut response = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    response.extend_from_slice(&buffer[..size]);
                    if response.len() > MAX_RESPONSE_BYTES {
                        return Err(ControllerError::ResponseTooLarge);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(ControllerError::Unavailable);
                }
                Err(_) => return Err(ControllerError::Unavailable),
            }
        }
        decode_http_response(&response)
    }
}

impl ObservabilityControllerTransport for TcpControllerTransport {
    fn request(
        &mut self,
        method: ObservabilityMethod,
        connection_id: Option<&str>,
        secret: &str,
    ) -> Result<Vec<u8>, ControllerError> {
        let request = encode_observability_request(method, connection_id, secret)?;
        let address: SocketAddr = CONTROLLER_ADDRESS
            .parse()
            .map_err(|_| ControllerError::Invalid)?;
        if !address.ip().is_loopback() {
            return Err(ControllerError::Invalid);
        }
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)
            .map_err(|_| ControllerError::Unavailable)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|_| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|_| ControllerError::Unavailable)?;
        stream
            .write_all(request.as_bytes())
            .map_err(|_| ControllerError::Unavailable)?;
        let response = read_bounded_response(&mut stream)?;
        match method {
            ObservabilityMethod::Get => decode_http_response_with_status(&response, &[200]),
            ObservabilityMethod::Delete => decode_http_response_with_status(&response, &[200, 204]),
        }
    }
}

struct ControllerRequest(Vec<u8>);

impl ControllerRequest {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ControllerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControllerRequest([REDACTED])")
    }
}

impl Drop for ControllerRequest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn read_tun_evidence<T, V>(
    transport: &mut T,
    verifier: &mut V,
    engine: &ProcessIdentity,
    controller_secret: &str,
    configured_device: &str,
) -> Result<ControllerTunEvidence, ControllerError>
where
    T: ControllerTransport,
    V: ControllerOwnerVerifier,
{
    if engine.pid <= 1
        || engine.start_time_ns == 0
        || engine.executable_file_id == 0
        || !valid_secret(controller_secret)
        || !valid_utun_name(configured_device)
        || !valid_sha256(&engine.executable_sha256)
    {
        return Err(ControllerError::Invalid);
    }
    verify_owner(verifier, engine)?;

    let version_body = transport.get("/version", controller_secret)?;
    enforce_body_bound(&version_body)?;
    parse_version(&version_body)?;
    let config_body = transport.get("/configs", controller_secret)?;
    enforce_body_bound(&config_body)?;
    let state = parse_tun_state(&config_body)?;
    if !state.enabled || state.device != configured_device {
        return Err(ControllerError::StateMismatch);
    }

    verify_owner(verifier, engine)?;
    Ok(ControllerTunEvidence {
        authenticated: true,
        engine_pid: engine.pid,
        configured_device: state.device,
        tun_enabled: state.enabled,
    })
}

fn enforce_body_bound(body: &[u8]) -> Result<(), ControllerError> {
    if body.len() > MAX_RESPONSE_BYTES {
        Err(ControllerError::ResponseTooLarge)
    } else {
        Ok(())
    }
}

fn verify_owner<V: ControllerOwnerVerifier>(
    verifier: &mut V,
    engine: &ProcessIdentity,
) -> Result<(), ControllerError> {
    if verifier.is_exact_owner(CONTROLLER_ADDRESS, engine)? {
        Ok(())
    } else {
        Err(ControllerError::OwnershipMismatch)
    }
}

fn encode_get_request(
    path: &'static str,
    secret: &str,
) -> Result<ControllerRequest, ControllerError> {
    if !matches!(path, "/version" | "/configs") || !valid_secret(secret) {
        return Err(ControllerError::Invalid);
    }
    Ok(ControllerRequest(
        format!(
        "GET {path} HTTP/1.1\r\nHost: {CONTROLLER_ADDRESS}\r\nAuthorization: Bearer {secret}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
        .into_bytes(),
    ))
}

fn encode_observability_request(
    method: ObservabilityMethod,
    connection_id: Option<&str>,
    secret: &str,
) -> Result<ControllerRequest, ControllerError> {
    if !valid_secret(secret)
        || matches!(method, ObservabilityMethod::Get) && connection_id.is_some()
        || connection_id.is_some_and(|value| !valid_connection_id(value))
    {
        return Err(ControllerError::Invalid);
    }
    let method_name = match method {
        ObservabilityMethod::Get => "GET",
        ObservabilityMethod::Delete => "DELETE",
    };
    let path = connection_id
        .map(|value| format!("/connections/{value}"))
        .unwrap_or_else(|| "/connections".into());
    Ok(ControllerRequest(
        format!(
            "{method_name} {path} HTTP/1.1\r\nHost: {CONTROLLER_ADDRESS}\r\nAuthorization: Bearer {secret}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    ))
}

fn decode_http_response(response: &[u8]) -> Result<Vec<u8>, ControllerError> {
    decode_http_response_with_status(response, &[200])
}

fn decode_http_response_with_status(
    response: &[u8],
    accepted_statuses: &[u16],
) -> Result<Vec<u8>, ControllerError> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(ControllerError::ResponseTooLarge);
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ControllerError::Protocol)?;
    if header_end > MAX_HEADER_BYTES {
        return Err(ControllerError::ResponseTooLarge);
    }
    let header_bytes = &response[..header_end];
    let headers = std::str::from_utf8(header_bytes).map_err(|_| ControllerError::Protocol)?;
    let mut lines = headers.split("\r\n");
    let mut status = lines
        .next()
        .ok_or(ControllerError::Protocol)?
        .split_ascii_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(ControllerError::Protocol);
    }
    let status_code = status
        .next()
        .ok_or(ControllerError::Protocol)?
        .parse::<u16>()
        .map_err(|_| ControllerError::Protocol)?;
    // The protocol requires a reason phrase and forbids extra status tokens
    // only implicitly; body framing remains authoritative below.
    if !accepted_statuses.contains(&status_code) || status.next().is_none() {
        return Err(ControllerError::Protocol);
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(ControllerError::Protocol);
        }
        let (name, value) = line.split_once(':').ok_or(ControllerError::Protocol)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ControllerError::Protocol);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| ControllerError::Protocol)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(ControllerError::Protocol);
            }
            transfer_encoding = Some(value);
        }
    }
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(ControllerError::Protocol);
    }

    let body = &response[header_end + 4..];
    let decoded = if let Some(encoding) = transfer_encoding {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(ControllerError::Protocol);
        }
        decode_chunked(body)?
    } else if let Some(length) = content_length {
        if length > MAX_RESPONSE_BYTES || body.len() != length {
            return Err(ControllerError::Protocol);
        }
        body.to_vec()
    } else {
        body.to_vec()
    };
    if decoded.len() > MAX_RESPONSE_BYTES {
        return Err(ControllerError::ResponseTooLarge);
    }
    Ok(decoded)
}

fn read_bounded_response(stream: &mut TcpStream) -> Result<Vec<u8>, ControllerError> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(response),
            Ok(size) => {
                response.extend_from_slice(&buffer[..size]);
                if response.len() > MAX_RESPONSE_BYTES {
                    return Err(ControllerError::ResponseTooLarge);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ControllerError::Unavailable);
            }
            Err(_) => return Err(ControllerError::Unavailable),
        }
    }
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, ControllerError> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(ControllerError::Protocol)?;
        if line_end > 128 {
            return Err(ControllerError::Protocol);
        }
        let size_text =
            std::str::from_utf8(&input[..line_end]).map_err(|_| ControllerError::Protocol)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|_| ControllerError::Protocol)?;
        input = &input[line_end + 2..];
        if size == 0 {
            if input == b"\r\n" {
                return Ok(output);
            }
            let trailer_end = input
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .ok_or(ControllerError::Protocol)?;
            if trailer_end > MAX_HEADER_BYTES || trailer_end + 4 != input.len() {
                return Err(ControllerError::Protocol);
            }
            return Ok(output);
        }
        let next_len = output
            .len()
            .checked_add(size)
            .ok_or(ControllerError::ResponseTooLarge)?;
        let framed_size = size
            .checked_add(2)
            .ok_or(ControllerError::ResponseTooLarge)?;
        if next_len > MAX_RESPONSE_BYTES
            || input.len() < framed_size
            || &input[size..framed_size] != b"\r\n"
        {
            return Err(ControllerError::Protocol);
        }
        output.extend_from_slice(&input[..size]);
        input = &input[framed_size..];
    }
}

#[derive(Deserialize)]
struct VersionResponse {
    meta: bool,
    version: String,
}

fn parse_version(body: &[u8]) -> Result<ControllerVersion, ControllerError> {
    let response: VersionResponse =
        serde_json::from_slice(body).map_err(|_| ControllerError::Protocol)?;
    if !response.meta
        || response.version.is_empty()
        || response.version.len() > 128
        || response.version.chars().any(char::is_control)
    {
        return Err(ControllerError::StateMismatch);
    }
    Ok(ControllerVersion {
        version: response.version,
    })
}

#[derive(Deserialize)]
struct ConfigResponse {
    tun: TunStateResponse,
}

#[derive(Deserialize)]
struct TunStateResponse {
    enable: bool,
    device: String,
}

struct TunState {
    enabled: bool,
    device: String,
}

fn parse_tun_state(body: &[u8]) -> Result<TunState, ControllerError> {
    let response: ConfigResponse =
        serde_json::from_slice(body).map_err(|_| ControllerError::Protocol)?;
    if !valid_utun_name(&response.tun.device) {
        return Err(ControllerError::StateMismatch);
    }
    Ok(TunState {
        enabled: response.tun.enable,
        device: response.tun.device,
    })
}

fn valid_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    valid_secret(value)
}

fn valid_utun_name(value: &str) -> bool {
    value.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_connection_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn engine() -> ProcessIdentity {
        ProcessIdentity {
            pid: 700,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: "b".repeat(64),
        }
    }

    struct MockTransport {
        responses: VecDeque<(&'static str, Vec<u8>)>,
        calls: Vec<(&'static str, String)>,
    }

    impl ControllerTransport for MockTransport {
        fn get(&mut self, path: &'static str, secret: &str) -> Result<Vec<u8>, ControllerError> {
            self.calls.push((path, secret.into()));
            let (expected, response) = self
                .responses
                .pop_front()
                .ok_or(ControllerError::Unavailable)?;
            if expected != path {
                return Err(ControllerError::Protocol);
            }
            Ok(response)
        }
    }

    struct MockVerifier {
        results: VecDeque<bool>,
        calls: usize,
    }

    impl ControllerOwnerVerifier for MockVerifier {
        fn is_exact_owner(
            &mut self,
            address: &str,
            expected: &ProcessIdentity,
        ) -> Result<bool, ControllerError> {
            assert_eq!(address, CONTROLLER_ADDRESS);
            assert_eq!(expected, &engine());
            self.calls += 1;
            self.results.pop_front().ok_or(ControllerError::Unavailable)
        }
    }

    fn mock_transport(version: &[u8], config: &[u8]) -> MockTransport {
        MockTransport {
            responses: VecDeque::from([
                ("/version", version.to_vec()),
                ("/configs", config.to_vec()),
            ]),
            calls: Vec::new(),
        }
    }

    #[test]
    fn authenticated_reads_and_double_owner_check_create_exact_evidence() {
        let mut transport = mock_transport(
            br#"{"meta":true,"version":"v1.19.28","extra":"allowed"}"#,
            br#"{"tun":{"enable":true,"device":"utun7","stack":"gvisor"},"mode":"rule"}"#,
        );
        let mut verifier = MockVerifier {
            results: VecDeque::from([true, true]),
            calls: 0,
        };
        let evidence =
            read_tun_evidence(&mut transport, &mut verifier, &engine(), SECRET, "utun7").unwrap();
        assert_eq!(
            evidence,
            ControllerTunEvidence {
                authenticated: true,
                engine_pid: 700,
                configured_device: "utun7".into(),
                tun_enabled: true,
            }
        );
        assert_eq!(verifier.calls, 2);
        assert_eq!(
            transport.calls,
            vec![("/version", SECRET.into()), ("/configs", SECRET.into())]
        );
    }

    #[test]
    fn listener_replacement_before_or_after_reads_is_rejected() {
        let mut transport = mock_transport(
            br#"{"meta":true,"version":"v1"}"#,
            br#"{"tun":{"enable":true,"device":"utun7"}}"#,
        );
        let mut verifier = MockVerifier {
            results: VecDeque::from([false]),
            calls: 0,
        };
        assert_eq!(
            read_tun_evidence(&mut transport, &mut verifier, &engine(), SECRET, "utun7"),
            Err(ControllerError::OwnershipMismatch)
        );
        assert!(transport.calls.is_empty());

        let mut transport = mock_transport(
            br#"{"meta":true,"version":"v1"}"#,
            br#"{"tun":{"enable":true,"device":"utun7"}}"#,
        );
        let mut verifier = MockVerifier {
            results: VecDeque::from([true, false]),
            calls: 0,
        };
        assert_eq!(
            read_tun_evidence(&mut transport, &mut verifier, &engine(), SECRET, "utun7"),
            Err(ControllerError::OwnershipMismatch)
        );
        assert_eq!(transport.calls.len(), 2);
    }

    #[test]
    fn non_mihomo_version_disabled_tun_and_device_mismatch_are_rejected() {
        let cases: [(&[u8], &[u8]); 3] = [
            (
                br#"{"meta":false,"version":"other"}"#,
                br#"{"tun":{"enable":true,"device":"utun7"}}"#,
            ),
            (
                br#"{"meta":true,"version":"v1"}"#,
                br#"{"tun":{"enable":false,"device":"utun7"}}"#,
            ),
            (
                br#"{"meta":true,"version":"v1"}"#,
                br#"{"tun":{"enable":true,"device":"utun8"}}"#,
            ),
        ];
        for (version, config) in cases {
            let mut transport = mock_transport(version, config);
            let mut verifier = MockVerifier {
                results: VecDeque::from([true, true]),
                calls: 0,
            };
            assert!(
                read_tun_evidence(&mut transport, &mut verifier, &engine(), SECRET, "utun7")
                    .is_err()
            );
        }
    }

    #[test]
    fn request_is_fixed_loopback_bearer_get_without_secret_in_debug_state() {
        let request = encode_get_request("/version", SECRET).unwrap();
        assert!(!format!("{request:?}").contains(SECRET));
        let request = std::str::from_utf8(request.as_bytes()).unwrap();
        assert!(request.starts_with("GET /version HTTP/1.1\r\n"));
        assert!(request.contains("Host: 127.0.0.1:25412\r\n"));
        assert!(request.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
        assert!(request.ends_with("Connection: close\r\n\r\n"));
        assert!(matches!(
            encode_get_request("/connections", SECRET),
            Err(ControllerError::Invalid)
        ));
    }

    #[test]
    fn observability_requests_are_bounded_authenticated_and_path_safe() {
        let get = encode_observability_request(ObservabilityMethod::Get, None, SECRET).unwrap();
        let get_text = std::str::from_utf8(get.as_bytes()).unwrap();
        assert!(get_text.starts_with("GET /connections HTTP/1.1\r\n"));
        assert!(get_text.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
        assert!(!format!("{get:?}").contains(SECRET));

        let delete = encode_observability_request(
            ObservabilityMethod::Delete,
            Some("connection_7-A"),
            SECRET,
        )
        .unwrap();
        assert!(std::str::from_utf8(delete.as_bytes())
            .unwrap()
            .starts_with("DELETE /connections/connection_7-A HTTP/1.1\r\n"));
        for invalid in ["", "../configs", "space id", "ü"] {
            assert!(matches!(
                encode_observability_request(ObservabilityMethod::Delete, Some(invalid), SECRET),
                Err(ControllerError::Invalid)
            ));
        }
        assert!(matches!(
            encode_observability_request(ObservabilityMethod::Get, Some("id"), SECRET),
            Err(ControllerError::Invalid)
        ));
    }

    #[test]
    fn observability_decoder_accepts_delete_no_content_but_not_error_status() {
        assert_eq!(
            decode_http_response_with_status(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
                &[200, 204]
            )
            .unwrap(),
            b""
        );
        assert_eq!(
            decode_http_response_with_status(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                &[200, 204]
            ),
            Err(ControllerError::Protocol)
        );
    }

    #[test]
    fn incomplete_engine_identity_and_transport_bypassing_size_limit_are_rejected() {
        let mut incomplete = engine();
        incomplete.start_time_ns = 0;
        let mut transport = mock_transport(
            br#"{"meta":true,"version":"v1"}"#,
            br#"{"tun":{"enable":true,"device":"utun7"}}"#,
        );
        let mut verifier = MockVerifier {
            results: VecDeque::from([true]),
            calls: 0,
        };
        assert_eq!(
            read_tun_evidence(&mut transport, &mut verifier, &incomplete, SECRET, "utun7"),
            Err(ControllerError::Invalid)
        );
        assert_eq!(verifier.calls, 0);

        let mut transport = mock_transport(
            &vec![b'x'; MAX_RESPONSE_BYTES + 1],
            br#"{"tun":{"enable":true,"device":"utun7"}}"#,
        );
        let mut verifier = MockVerifier {
            results: VecDeque::from([true]),
            calls: 0,
        };
        assert_eq!(
            read_tun_evidence(&mut transport, &mut verifier, &engine(), SECRET, "utun7"),
            Err(ControllerError::ResponseTooLarge)
        );
    }

    #[test]
    fn strict_http_decoder_accepts_length_chunked_and_close_framing() {
        assert_eq!(
            decode_http_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}"
            )
            .unwrap(),
            b"{}"
        );
        assert_eq!(
            decode_http_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
            )
            .unwrap(),
            b"{}"
        );
        assert_eq!(
            decode_http_response(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n{}").unwrap(),
            b"{}"
        );
    }

    #[test]
    fn busy_engine_connections_response_is_not_rejected_as_too_large() {
        // A /connections-sized body of about 2.4 MB (roughly 3,000 live
        // connections), far above the former 512 KiB limit.
        let body = format!("[{}]", vec!["\"x\""; 600_000].join(","));
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in body.as_bytes().chunks(16 * 1024) {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        assert!(response.len() > 2 * 1024 * 1024);
        assert_eq!(decode_http_response(&response).unwrap(), body.as_bytes());
    }

    #[test]
    fn unauthorized_truncated_ambiguous_and_oversized_http_are_rejected() {
        for response in [
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        ] {
            assert_eq!(
                decode_http_response(response),
                Err(ControllerError::Protocol)
            );
        }
        assert_eq!(
            decode_http_response(&vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            Err(ControllerError::ResponseTooLarge)
        );
    }
}
