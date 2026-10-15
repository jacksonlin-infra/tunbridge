use crate::{CoreError, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Send an HTTP/1.1 GET over an already-connected stream and return
/// (status_code, body). Reads until the peer closes (Connection: close) or a
/// 1 MiB safety cap; adequate for 204 responses and small JSON bodies.
pub fn get_status(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, String)> {
    request_status(stream, "GET", host, path, extra_headers, timeout)
}

/// Like [`get_status`], for responses that may legitimately exceed 1 MiB.
/// A response larger than `max_bytes` is an error rather than a silently
/// truncated (and therefore unparsable) body.
pub fn get_status_limited(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> Result<(u16, String)> {
    let (code, body, truncated) =
        request(stream, "GET", host, path, extra_headers, timeout, max_bytes)?;
    if truncated {
        return Err(CoreError::Io(format!(
            "response exceeds the {max_bytes} byte limit"
        )));
    }
    Ok((code, body))
}

/// Send a bodyless HTTP/1.1 DELETE over an already-connected stream.
pub fn delete_status(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, String)> {
    request_status(stream, "DELETE", host, path, extra_headers, timeout)
}

fn request_status(
    stream: &mut TcpStream,
    method: &str,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, String)> {
    let (code, body, _) = request(
        stream,
        method,
        host,
        path,
        extra_headers,
        timeout,
        DEFAULT_MAX_RESPONSE_BYTES,
    )?;
    Ok((code, body))
}

const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Returns (status, body, truncated); `truncated` is set when the response hit
/// `max_bytes` before the peer closed.
fn request(
    stream: &mut TcpStream,
    method: &str,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
    max_bytes: usize,
) -> Result<(u16, String, bool)> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > max_bytes {
                    truncated = true;
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(CoreError::Io(e.to_string())),
        }
    }

    let split_at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| CoreError::Io("no header/body separator in response".into()))?;
    let head = String::from_utf8_lossy(&raw[..split_at]).to_string();
    let body_bytes = &raw[split_at + 4..];

    let status_line = head.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| CoreError::Io(format!("bad status line: {status_line}")))?;

    // Go's http server (mihomo's REST API) sets Content-Length for small bodies
    // but switches to chunked once the response outgrows its ~2KB buffer, which
    // /connections does as soon as real traffic flows. Decode both.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked(body_bytes)?
    } else {
        String::from_utf8_lossy(body_bytes).to_string()
    };
    Ok((code, body, truncated))
}

/// Decode an HTTP/1.1 chunked body: repeated `<hex-size>\r\n<data>\r\n`,
/// terminated by a zero-size chunk.
fn decode_chunked(mut data: &[u8]) -> Result<String> {
    let mut out: Vec<u8> = Vec::new();
    while let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") {
        let size_line = String::from_utf8_lossy(&data[..line_end]);
        // a chunk size may carry extensions: "1a;name=value"
        let size_tok = size_line.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_tok, 16)
            .map_err(|_| CoreError::Io(format!("bad chunk size: {size_tok:?}")))?;
        data = &data[line_end + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            out.extend_from_slice(data);
            break; // truncated
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.len() >= 2 && &data[..2] == b"\r\n" {
            data = &data[2..];
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn spawn_http_204() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        addr
    }

    #[test]
    fn get_status_parses_204() {
        let addr = spawn_http_204();
        let mut s = TcpStream::connect(addr).unwrap();
        let (code, _body) = get_status(
            &mut s,
            "cp.cloudflare.com",
            "/generate_204",
            &[],
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(code, 204);
    }

    /// Go's http server switches to chunked once a response exceeds its ~2KB
    /// buffer, which mihomo's /connections does under real load. Verified
    /// against the real engine: a >2KB body comes back `Transfer-Encoding:
    /// chunked` with no Content-Length.
    fn spawn_http_chunked() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).unwrap();
            // two chunks + terminator, split mid-JSON on purpose
            let body = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "1a\r\n{\"downloadTotal\":5,\"upload\r\n",
                "1b\r\nTotal\":7,\"connections\":[]}\r\n",
                "0\r\n\r\n"
            );
            s.write_all(body.as_bytes()).unwrap();
        });
        addr
    }

    #[test]
    fn get_status_decodes_chunked_body() {
        let addr = spawn_http_chunked();
        let mut s = TcpStream::connect(addr).unwrap();
        let (code, body) = get_status(
            &mut s,
            "127.0.0.1",
            "/connections",
            &[],
            Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(code, 200);
        // The decoded body must be valid JSON - raw chunk framing would not parse.
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("body must be de-chunked JSON, got {body:?} ({e})"));
        assert_eq!(v["downloadTotal"], 5);
        assert_eq!(v["uploadTotal"], 7);
    }

    #[test]
    fn get_status_limited_errors_instead_of_truncating() {
        let addr = spawn_http_chunked();
        let mut s = TcpStream::connect(addr).unwrap();
        let error = get_status_limited(
            &mut s,
            "127.0.0.1",
            "/connections",
            &[],
            Duration::from_secs(3),
            16,
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn delete_status_uses_bodyless_delete_method() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 512];
            let read = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8_lossy(&bytes[..read]).to_string();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let (status, _) = delete_status(
            &mut stream,
            "127.0.0.1",
            "/connections/test-id",
            &[],
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(status, 204);
        assert!(server
            .join()
            .unwrap()
            .starts_with("DELETE /connections/test-id HTTP/1.1\r\n"));
    }
}
