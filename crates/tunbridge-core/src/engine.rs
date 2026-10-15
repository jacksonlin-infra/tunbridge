use crate::net::http;
use crate::{CoreError, Result};
use serde::Serialize;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn locate() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TUNBRIDGE_ENGINE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
    }
    let manifest_dev_engine = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("windows-engine")
        .join("mihomo.exe");
    let executable_engine = std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|parent| parent.join("engine").join("mihomo.exe"))
    });
    let candidates = [
        Some(PathBuf::from("engine/mihomo.exe")),
        Some(PathBuf::from("target/windows-engine/mihomo.exe")),
        Some(manifest_dev_engine),
        executable_engine,
    ];
    for pb in candidates.into_iter().flatten() {
        if pb.exists() {
            return Ok(std::fs::canonicalize(&pb).unwrap_or(pb));
        }
    }
    Err(CoreError::Engine(
        "mihomo.exe not found (set TUNBRIDGE_ENGINE)".into(),
    ))
}

/// Extract a leading-`v` semver token from arbitrary engine output.
pub fn parse_version(raw: &str) -> Option<String> {
    for tok in raw.split_whitespace() {
        let t = tok.trim();
        if let Some(rest) = t.strip_prefix('v') {
            let parts: Vec<&str> = rest.split('.').collect();
            let ok = parts.len() >= 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
            if ok {
                return Some(t.to_string());
            }
        }
    }
    None
}

pub fn version(path: &Path) -> Result<String> {
    let out = Command::new(path)
        .arg("-v")
        .output()
        .map_err(|e| CoreError::Engine(e.to_string()))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parse_version(&text).ok_or_else(|| CoreError::Engine(format!("no version in: {}", text.trim())))
}

/// Stop our own std handles from being inherited by processes we spawn.
///
/// Rust's `Command` calls CreateProcess with bInheritHandles=TRUE, so a child
/// inherits *every* inheritable handle we hold - including our stdout when the
/// caller captured it through a pipe. A daemonized kernel that outlives us then
/// keeps that pipe open, and the caller blocks forever waiting for an EOF that
/// never comes (PowerShell `| Out-String`, CI, the GUI). Redirecting the child's
/// own stdio is not enough; the leak is the *other* handles.
///
/// Clearing HANDLE_FLAG_INHERIT on our std handles is safe: the explicit stdio
/// we hand each child is duplicated by std as inheritable regardless.
#[cfg(windows)]
#[allow(unsafe_code)]
fn detach_std_handles_from_children() {
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle returns a borrowed handle we do not close, and
        // SetHandleInformation only flips the inherit bit on it.
        unsafe {
            let h = GetStdHandle(id);
            if !h.is_null() && h != INVALID_HANDLE_VALUE {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

#[cfg(not(windows))]
fn detach_std_handles_from_children() {}

/// Spawn a detached long-lived process with its stdio redirected to log files in
/// `workdir`, returning its pid. The child outlives us on purpose.
pub fn spawn_detached(program: &Path, args: &[&str], workdir: &Path) -> Result<u32> {
    use std::fs::File;
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    std::fs::create_dir_all(workdir).map_err(|e| CoreError::Io(e.to_string()))?;
    let out_log =
        File::create(workdir.join("mihomo.out.log")).map_err(|e| CoreError::Io(e.to_string()))?;
    let err_log =
        File::create(workdir.join("mihomo.err.log")).map_err(|e| CoreError::Io(e.to_string()))?;

    // Must happen before spawning: see the doc comment above.
    detach_std_handles_from_children();

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(out_log)
        .stderr(err_log);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let child = cmd.spawn().map_err(|e| CoreError::Engine(e.to_string()))?;
    Ok(child.id())
}

pub fn spawn(engine: &Path, config: &Path, workdir: &Path) -> Result<u32> {
    let config = config.to_string_lossy().to_string();
    let dir = workdir.to_string_lossy().to_string();
    spawn_detached(engine, &["-f", &config, "-d", &dir], workdir)
}

fn stop(pid: u32) -> Result<()> {
    #[cfg(windows)]
    {
        let out = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()
            .map_err(|e| CoreError::Io(e.to_string()))?;
        if out.status.success() || !is_alive(pid)? {
            Ok(())
        } else {
            Err(CoreError::Engine(format!(
                "failed to stop process {pid}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(CoreError::Unsupported(
            "engine stop only implemented on windows".into(),
        ))
    }
}

#[cfg(windows)]
fn process_path(pid: u32) -> Result<Option<PathBuf>> {
    use std::os::windows::process::CommandExt;

    if !is_alive(pid)? {
        return Ok(None);
    }
    let script = format!(
        "$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($null -eq $p) {{ exit 3 }}; if (-not $p.Path) {{ Write-Error 'process path unavailable'; exit 4 }}; [Console]::Out.Write($p.Path)"
    );
    let mut command = Command::new("powershell");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW);
    let out = command
        .output()
        .map_err(|e| CoreError::Io(format!("failed to inspect process {pid}: {e}")))?;
    if out.status.code() == Some(3) {
        return Ok(None);
    }
    if !out.status.success() {
        return Err(CoreError::Io(format!(
            "failed to inspect process {pid}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if raw.is_empty() {
        return Err(CoreError::Io(format!(
            "failed to inspect process {pid}: executable path was empty"
        )));
    }
    Ok(Some(PathBuf::from(raw)))
}

#[cfg(not(windows))]
fn process_path(pid: u32) -> Result<Option<PathBuf>> {
    let _ = pid;
    Err(CoreError::Unsupported(
        "process inspection only implemented on windows".into(),
    ))
}

fn normalized_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', "\\");
    raw.trim_start_matches("\\\\?\\").to_ascii_lowercase()
}

pub fn paths_match(actual: &Path, expected: &Path) -> bool {
    normalized_path(actual) == normalized_path(expected)
}

/// Stop a process only after proving that the PID still belongs to the exact
/// engine executable recorded when TunBridge spawned it. This prevents PID
/// reuse and avoids killing unrelated mihomo-based applications.
pub fn stop_owned(pid: u32, expected_path: &Path) -> Result<()> {
    let Some(actual_path) = process_path(pid)? else {
        return Ok(());
    };
    if !paths_match(&actual_path, expected_path) {
        return Err(CoreError::Engine(format!(
            "refusing to stop pid {pid}: executable `{}` does not match tracked engine `{}`",
            actual_path.display(),
            expected_path.display()
        )));
    }
    stop(pid)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !is_alive(pid)? {
            return Ok(());
        }
        sleep(Duration::from_millis(100));
    }
    Err(CoreError::Engine(format!(
        "process {pid} did not exit after taskkill"
    )))
}

pub fn is_alive(pid: u32) -> Result<bool> {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map_err(|e| CoreError::Io(format!("failed to query process {pid}: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(CoreError::Io(format!(
                "failed to query process {pid}: {}",
                if stderr.is_empty() {
                    format!("tasklist exited with {}", out.status)
                } else {
                    stderr
                }
            )));
        }
        let pid_text = pid.to_string();
        Ok(String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .any(|token| token == pid_text))
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(CoreError::Unsupported(
            "process inspection only implemented on windows".into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineConnections {
    pub count: usize,
    pub download_total: u64,
    pub upload_total: u64,
}

pub const MAX_ENGINE_CONNECTIONS: usize = 10_000;
/// Largest controller response any platform service accepts. `/connections`
/// grows by roughly 800 bytes per live connection, so this leaves headroom for
/// `MAX_ENGINE_CONNECTIONS`; larger responses are rejected, never truncated.
pub const MAX_ENGINE_RESPONSE_BYTES: usize = 16 << 20;
const _: () = assert!(MAX_ENGINE_RESPONSE_BYTES >= MAX_ENGINE_CONNECTIONS * 1024);
const MAX_CONNECTION_ID_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 512;
const MAX_METADATA_VALUE_BYTES: usize = 512;
const MAX_CHAIN_ITEMS: usize = 32;
const MAX_CHAIN_ITEM_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub memory_bytes: u64,
    pub connections: Vec<EngineConnection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineConnection {
    pub id: String,
    pub host: String,
    pub network: String,
    pub connection_type: String,
    pub source: String,
    pub destination: String,
    pub process_name: Option<String>,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: Option<String>,
    pub upload_total: u64,
    pub download_total: u64,
    pub started_at: String,
}

pub fn parse_connections(json: &str) -> Result<EngineConnections> {
    let snapshot = parse_engine_snapshot(json)?;
    Ok(EngineConnections {
        count: snapshot.connections.len(),
        download_total: snapshot.download_total,
        upload_total: snapshot.upload_total,
    })
}

pub fn parse_engine_snapshot(json: &str) -> Result<EngineSnapshot> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| CoreError::Engine(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| CoreError::Engine("connections response must be an object".into()))?;
    let connections = match object.get("connections") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            if items.len() > MAX_ENGINE_CONNECTIONS {
                return Err(CoreError::Engine(format!(
                    "connections response exceeds {MAX_ENGINE_CONNECTIONS} items"
                )));
            }
            items
                .iter()
                .map(parse_engine_connection)
                .collect::<Result<Vec<_>>>()?
        }
        Some(_) => {
            return Err(CoreError::Engine(
                "connections field must be an array or null".into(),
            ));
        }
    };
    Ok(EngineSnapshot {
        download_total: unsigned_field(object, "downloadTotal"),
        upload_total: unsigned_field(object, "uploadTotal"),
        memory_bytes: unsigned_field(object, "memory"),
        connections,
    })
}

fn parse_engine_connection(value: &serde_json::Value) -> Result<EngineConnection> {
    let object = value
        .as_object()
        .ok_or_else(|| CoreError::Engine("connection item must be an object".into()))?;
    let id = required_bounded_string(object.get("id"), "connection id", MAX_CONNECTION_ID_BYTES)?;
    let metadata = object
        .get("metadata")
        .and_then(serde_json::Value::as_object);
    let host = metadata_string(metadata, "host", MAX_HOST_BYTES)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| endpoint(metadata, "destinationIP", "destinationPort"));
    let process_name = metadata_string(metadata, "process", MAX_METADATA_VALUE_BYTES)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            metadata_string(metadata, "processPath", MAX_METADATA_VALUE_BYTES)
                .and_then(|path| process_basename(&path))
        });
    let chains = match object.get("chains") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(items)) if items.len() <= MAX_CHAIN_ITEMS => items
            .iter()
            .map(|item| {
                required_bounded_string(Some(item), "connection chain item", MAX_CHAIN_ITEM_BYTES)
            })
            .collect::<Result<Vec<_>>>()?,
        Some(serde_json::Value::Array(_)) => {
            return Err(CoreError::Engine(format!(
                "connection chains exceed {MAX_CHAIN_ITEMS} items"
            )));
        }
        Some(_) => {
            return Err(CoreError::Engine(
                "connection chains must be an array or null".into(),
            ));
        }
    };
    Ok(EngineConnection {
        id,
        host,
        network: metadata_string(metadata, "network", 32).unwrap_or_default(),
        connection_type: metadata_string(metadata, "type", 64).unwrap_or_default(),
        source: endpoint(metadata, "sourceIP", "sourcePort"),
        destination: endpoint(metadata, "destinationIP", "destinationPort"),
        process_name,
        chains,
        rule: optional_bounded_string(object.get("rule"), MAX_METADATA_VALUE_BYTES)
            .unwrap_or_default(),
        rule_payload: optional_bounded_string(object.get("rulePayload"), MAX_METADATA_VALUE_BYTES)
            .filter(|value| !value.is_empty()),
        upload_total: unsigned_field(object, "upload"),
        download_total: unsigned_field(object, "download"),
        started_at: optional_bounded_string(object.get("start"), 64).unwrap_or_default(),
    })
}

fn unsigned_field(object: &serde_json::Map<String, serde_json::Value>, field: &str) -> u64 {
    object
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn metadata_string(
    metadata: Option<&serde_json::Map<String, serde_json::Value>>,
    field: &str,
    max_bytes: usize,
) -> Option<String> {
    optional_bounded_string(metadata?.get(field), max_bytes)
}

fn optional_bounded_string(value: Option<&serde_json::Value>, max_bytes: usize) -> Option<String> {
    let value = value?.as_str()?;
    if value.len() > max_bytes || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn required_bounded_string(
    value: Option<&serde_json::Value>,
    field: &str,
    max_bytes: usize,
) -> Result<String> {
    optional_bounded_string(value, max_bytes)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CoreError::Engine(format!("{field} is missing or invalid")))
}

fn endpoint(
    metadata: Option<&serde_json::Map<String, serde_json::Value>>,
    address_field: &str,
    port_field: &str,
) -> String {
    let address =
        metadata_string(metadata, address_field, MAX_METADATA_VALUE_BYTES).unwrap_or_default();
    let port_value = metadata.and_then(|value| value.get(port_field));
    let port = port_value
        .and_then(serde_json::Value::as_u64)
        .map(|value| value.to_string())
        .or_else(|| optional_bounded_string(port_value, 8))
        .unwrap_or_default();
    match (address.is_empty(), port.is_empty()) {
        (false, false) if address.contains(':') => format!("[{address}]:{port}"),
        (false, false) => format!("{address}:{port}"),
        (false, true) => address,
        (true, false) => port,
        (true, true) => String::new(),
    }
}

fn process_basename(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .find(|part| !part.is_empty())
        .filter(|part| part.len() <= MAX_METADATA_VALUE_BYTES)
        .map(str::to_string)
}

fn rest_get(controller: &str, path: &str, secret: &str, timeout: Duration) -> Result<String> {
    let addr = controller
        .parse()
        .map_err(|_| CoreError::Engine(format!("bad controller addr: {controller}")))?;
    let mut s =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| CoreError::Engine(e.to_string()))?;
    let bearer = format!("Bearer {secret}");
    let host = controller.to_string();
    // /connections grows with the number of live connections (up to
    // MAX_ENGINE_CONNECTIONS at roughly 800 bytes each); the default 1 MiB
    // response cap would truncate it into unparsable JSON on a busy machine.
    let (_code, body) = http::get_status_limited(
        &mut s,
        &host,
        path,
        &[("Authorization", &bearer)],
        timeout,
        MAX_ENGINE_RESPONSE_BYTES,
    )?;
    Ok(body)
}

fn rest_delete(controller: &str, path: &str, secret: &str, timeout: Duration) -> Result<()> {
    if path.chars().any(char::is_control) || !path.starts_with("/connections") {
        return Err(CoreError::Engine("invalid controller delete path".into()));
    }
    let addr = controller
        .parse()
        .map_err(|_| CoreError::Engine(format!("bad controller addr: {controller}")))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| CoreError::Engine(e.to_string()))?;
    let bearer = format!("Bearer {secret}");
    let host = controller.to_string();
    let (status, _) = http::delete_status(
        &mut stream,
        &host,
        path,
        &[("Authorization", &bearer)],
        timeout,
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(CoreError::Engine(format!(
            "controller delete returned HTTP {status}"
        )))
    }
}

pub fn rest_version(controller: &str, secret: &str, timeout: Duration) -> Result<String> {
    let body = rest_get(controller, "/version", secret, timeout)?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| CoreError::Engine(e.to_string()))?;
    v.get("version")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CoreError::Engine("no version field".into()))
}

pub fn rest_connections(
    controller: &str,
    secret: &str,
    timeout: Duration,
) -> Result<EngineConnections> {
    let body = rest_get(controller, "/connections", secret, timeout)?;
    parse_connections(&body)
}

pub fn rest_engine_snapshot(
    controller: &str,
    secret: &str,
    timeout: Duration,
) -> Result<EngineSnapshot> {
    let body = rest_get(controller, "/connections", secret, timeout)?;
    parse_engine_snapshot(&body)
}

pub fn close_engine_connection(
    controller: &str,
    secret: &str,
    connection_id: &str,
    timeout: Duration,
) -> Result<()> {
    if connection_id.is_empty()
        || connection_id.len() > MAX_CONNECTION_ID_BYTES
        || !connection_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CoreError::Engine("invalid connection id".into()));
    }
    rest_delete(
        controller,
        &format!("/connections/{connection_id}"),
        secret,
        timeout,
    )
}

pub fn close_all_engine_connections(
    controller: &str,
    secret: &str,
    timeout: Duration,
) -> Result<()> {
    rest_delete(controller, "/connections", secret, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chunked `/connections` response with `count` realistic (~775 byte)
    /// connections, served once from a loopback listener like mihomo does.
    fn serve_connections(count: usize) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let items = (0..count)
            .map(|i| {
                format!(
                    r#"{{"id":"4f0c2a1e-9b7d-4c1a-8a55-{i:012}","metadata":{{"network":"tcp","type":"Tun","sourceIP":"198.18.0.1","destinationIP":"142.250.1.1","sourceGeoIP":null,"destinationGeoIP":null,"sourceIPASN":"","destinationIPASN":"","sourcePort":"50000","destinationPort":"443","inboundIP":"","inboundPort":"0","inboundName":"","inboundUser":"","host":"host{i}.example.com","dnsMode":"normal","uid":0,"process":"chrome.exe","processPath":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","specialProxy":"","specialRules":"","remoteDestination":"","dscp":0,"sniffHost":""}},"upload":1,"download":2,"start":"2026-10-15T10:26:55.123456789+08:00","chains":["Proxy","Upstream"],"providerChains":[],"rule":"DomainSuffix","rulePayload":"example.com"}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let body =
            format!(r#"{{"downloadTotal":1,"uploadTotal":2,"memory":3,"connections":[{items}]}}"#);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for chunk in body.as_bytes().chunks(16 * 1024) {
                response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                response.extend_from_slice(chunk);
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
            let _ = stream.write_all(&response);
        });
        (addr, server)
    }

    #[test]
    fn engine_snapshot_survives_a_busy_machine_with_over_a_thousand_connections() {
        let (addr, server) = serve_connections(1541);
        let snapshot = rest_engine_snapshot(&addr, &"a".repeat(64), Duration::from_secs(5))
            .expect("1541 connections must not be truncated");
        server.join().unwrap();
        assert_eq!(snapshot.connections.len(), 1541);
    }

    #[test]
    fn parse_version_extracts_semver_with_v() {
        let raw = "Mihomo Meta v1.19.28 windows amd64 with go1.26.5";
        assert_eq!(parse_version(raw).as_deref(), Some("v1.19.28"));
    }

    #[test]
    fn parse_version_none_when_absent() {
        assert_eq!(parse_version("no version here"), None);
    }

    #[test]
    fn parse_connections_counts_and_totals() {
        let json =
            r#"{"downloadTotal":22943,"uploadTotal":1858,"connections":[{"id":"a"},{"id":"b"}]}"#;
        let c = parse_connections(json).unwrap();
        assert_eq!(c.count, 2);
        assert_eq!(c.download_total, 22943);
        assert_eq!(c.upload_total, 1858);
    }

    #[test]
    fn parse_connections_handles_null_connections() {
        let json = r#"{"downloadTotal":0,"uploadTotal":0,"connections":null}"#;
        let c = parse_connections(json).unwrap();
        assert_eq!(c.count, 0);
    }

    #[test]
    fn parses_connection_details_without_exposing_process_path() {
        let json = r#"{
            "downloadTotal": 22943,
            "uploadTotal": 1858,
            "memory": 71303168,
            "connections": [{
                "id": "abc-123",
                "metadata": {
                    "network": "tcp",
                    "type": "TUN",
                    "sourceIP": "198.18.0.1",
                    "sourcePort": "50000",
                    "destinationIP": "142.250.1.1",
                    "destinationPort": "443",
                    "host": "www.google.com",
                    "processPath": "C:\\Program Files\\Browser\\browser.exe"
                },
                "upload": 1024,
                "download": 4096,
                "start": "2026-07-25T12:00:00.000Z",
                "chains": ["TunBridge", "DIRECT"],
                "rule": "DomainSuffix",
                "rulePayload": "google.com"
            }]
        }"#;
        let snapshot = parse_engine_snapshot(json).unwrap();
        assert_eq!(snapshot.memory_bytes, 71_303_168);
        assert_eq!(snapshot.connections.len(), 1);
        let connection = &snapshot.connections[0];
        assert_eq!(connection.host, "www.google.com");
        assert_eq!(connection.process_name.as_deref(), Some("browser.exe"));
        assert!(!serde_json::to_string(connection)
            .unwrap()
            .contains("Program Files"));
        assert_eq!(connection.destination, "142.250.1.1:443");
        assert_eq!(connection.chains, ["TunBridge", "DIRECT"]);
    }

    #[test]
    fn falls_back_to_ipv6_destination_and_rejects_invalid_ids() {
        let json = r#"{"connections":[{
            "id":"v6",
            "metadata":{"destinationIP":"2001:db8::1","destinationPort":443}
        }]}"#;
        let snapshot = parse_engine_snapshot(json).unwrap();
        assert_eq!(snapshot.connections[0].host, "[2001:db8::1]:443");

        let invalid = r#"{"connections":[{"id":"","metadata":{}}]}"#;
        assert!(parse_engine_snapshot(invalid).is_err());
    }

    #[test]
    fn close_connection_rejects_path_injection_before_network_access() {
        for id in ["", "../all", "id/other", "line\r\nheader", "a.b"] {
            assert!(
                close_engine_connection("127.0.0.1:1", "secret", id, Duration::from_millis(1))
                    .is_err()
            );
        }
    }

    #[test]
    fn paths_match_is_case_and_prefix_insensitive_on_windows_style_paths() {
        assert!(paths_match(
            Path::new(r"\\?\C:\Tools\mihomo.exe"),
            Path::new(r"c:/tools/MIHOMO.EXE")
        ));
        assert!(!paths_match(
            Path::new(r"C:\Other\mihomo.exe"),
            Path::new(r"C:\Tools\mihomo.exe")
        ));
    }
}
