use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tunbridge_desktop_contract::adapter::{
    AdapterError, AdapterErrorCode, ListenerIdentity, ProcessDiscovery,
};

const LSOF: &str = "/usr/sbin/lsof";
const NETSTAT: &str = "/usr/sbin/netstat";
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_PROCESS_NAME_BYTES: usize = 256;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: libc::c_int, buffer: *mut c_void, buffersize: u32) -> libc::c_int;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosProcessDiscovery;

impl ProcessDiscovery for MacosProcessDiscovery {
    fn loopback_listeners(&self) -> Result<Vec<ListenerIdentity>, AdapterError> {
        let output = run_bounded(LSOF, &["-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-Fpcn"])?;
        let mut listeners = parse_lsof(&output, process_path)?;
        // lsof cannot see sockets of other users' processes, such as a proxy
        // core that its own helper runs as root ("service mode"). netstat still
        // reports their PIDs. This only informs discovery; the privileged
        // helper re-verifies the owner before any start.
        if let Ok(rows) = run_bounded(NETSTAT, &["-anv", "-p", "tcp"])
            .and_then(|output| parse_netstat_listeners(&output))
        {
            merge_unattributed_listeners(&mut listeners, rows, process_path);
        }
        Ok(listeners)
    }
}

fn run_bounded(binary: &str, arguments: &[&str]) -> Result<Vec<u8>, AdapterError> {
    validate_system_executable(Path::new(binary))?;
    let mut child = Command::new(binary)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| unavailable())?;
    let mut output = Vec::new();
    let read_result = child
        .stdout
        .take()
        .ok_or_else(unavailable)?
        .take(MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut output);
    if read_result.is_err() || output.len() as u64 > MAX_OUTPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(invalid_data());
    }
    let status = child.wait().map_err(|_| unavailable())?;
    if !status.success() {
        return Err(unavailable());
    }
    Ok(output)
}

/// Parses `netstat -anv -p tcp` loopback listeners as (port, pid, address).
/// The PID column is located from the header because macOS releases differ
/// (`pid` on Monterey, `process:pid` later). In the header "Local Address"
/// and "Foreign Address" are two words each but one field in data rows.
fn parse_netstat_listeners(bytes: &[u8]) -> Result<Vec<(u16, u32, String)>, AdapterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_data())?;
    let mut lines = text.lines();
    let header = lines
        .by_ref()
        .find(|line| line.starts_with("Proto"))
        .ok_or_else(invalid_data)?;
    let columns: Vec<&str> = header.split_whitespace().collect();
    if columns.get(3..7) != Some(&["Local", "Address", "Foreign", "Address"][..]) {
        return Err(invalid_data());
    }
    let pid_column = columns
        .iter()
        .position(|column| *column == "pid" || column.ends_with(":pid"))
        .and_then(|index| index.checked_sub(2))
        .ok_or_else(invalid_data)?;
    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if !matches!(fields.first(), Some(&("tcp4" | "tcp6" | "tcp46")))
            || fields.get(5) != Some(&"LISTEN")
        {
            continue;
        }
        let Some((address, port)) = fields.get(3).and_then(|local| local.rsplit_once('.')) else {
            continue;
        };
        let address = match address {
            "127.0.0.1" => "127.0.0.1",
            "::1" => "::1",
            _ => continue,
        };
        let Some(port) = port.parse::<u16>().ok().filter(|port| *port > 0) else {
            continue;
        };
        let pid = fields
            .get(pid_column)
            .map(|field| field.rsplit(':').next().unwrap_or(field))
            .and_then(|pid| pid.parse::<u32>().ok())
            .filter(|pid| *pid > 0);
        if let Some(pid) = pid {
            rows.push((port, pid, address.to_owned()));
        }
    }
    Ok(rows)
}

fn merge_unattributed_listeners(
    listeners: &mut Vec<ListenerIdentity>,
    rows: Vec<(u16, u32, String)>,
    resolve_path: impl Fn(u32) -> Option<PathBuf>,
) {
    let known: BTreeSet<(u16, String)> = listeners
        .iter()
        .map(|listener| (listener.port, listener.address.clone()))
        .collect();
    let unknown: BTreeSet<(u16, u32, String)> = rows
        .into_iter()
        .filter(|(port, _, address)| !known.contains(&(*port, address.clone())))
        .collect();
    for (port, pid, address) in unknown {
        let path = resolve_path(pid);
        let name = path
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .and_then(sanitize_process_name);
        listeners.push(ListenerIdentity {
            address,
            port,
            process_id: Some(pid),
            process_name: name,
            process_path: path,
        });
    }
}

fn parse_lsof(
    bytes: &[u8],
    resolve_path: impl Fn(u32) -> Option<PathBuf>,
) -> Result<Vec<ListenerIdentity>, AdapterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_data())?;
    let mut process_id = None;
    let mut process_name: Option<String> = None;
    let mut rows = BTreeSet::new();

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                process_id = value.parse::<u32>().ok().filter(|pid| *pid > 0);
                process_name = None;
            }
            "c" => {
                process_name = sanitize_process_name(value);
            }
            "n" => {
                let (Some(pid), Some((address, port))) =
                    (process_id, parse_loopback_endpoint(value))
                else {
                    continue;
                };
                rows.insert((port, pid, address, process_name.clone()));
            }
            _ => {}
        }
    }

    let mut paths = BTreeMap::new();
    let mut listeners = Vec::with_capacity(rows.len());
    for (port, pid, address, lsof_name) in rows {
        let path = paths
            .entry(pid)
            .or_insert_with(|| resolve_path(pid))
            .clone();
        let name = path
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .and_then(sanitize_process_name)
            .or(lsof_name);
        listeners.push(ListenerIdentity {
            address,
            port,
            process_id: Some(pid),
            process_name: name,
            process_path: path,
        });
    }
    Ok(listeners)
}

fn parse_loopback_endpoint(value: &str) -> Option<(String, u16)> {
    let (address, port) = if let Some(rest) = value.strip_prefix('[') {
        let (address, port) = rest.split_once("]:")?;
        (address, port)
    } else {
        value.rsplit_once(':')?
    };
    let canonical = match address {
        "127.0.0.1" => "127.0.0.1",
        "::1" => "::1",
        _ => return None,
    };
    let port = port.parse::<u16>().ok().filter(|port| *port > 0)?;
    Some((canonical.to_owned(), port))
}

fn sanitize_process_name(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_PROCESS_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn process_path(pid: u32) -> Option<PathBuf> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buffer = [0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: proc_pidpath writes at most the supplied fixed buffer size. The
    // API is available before the Monterey deployment floor.
    let length = unsafe {
        proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    let path = std::str::from_utf8(buffer.get(..length)?).ok()?;
    let path = PathBuf::from(path);
    path.is_absolute().then_some(path)
}

fn validate_system_executable(path: &Path) -> Result<(), AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(invalid_data());
    }
    Ok(())
}

const fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "macOS listener enumeration is unavailable.",
        retryable: true,
    }
}

const fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "macOS listener data is invalid.",
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parses_only_loopback_tcp_listeners_and_deduplicates_rows() {
        let fixture = b"p42\ncProxy Client\nf3\nn127.0.0.1:7070\n\
                        f4\nn[::1]:7071\nf5\nn*:8080\n\
                        p43\ncbad\x01name\nf6\nn127.0.0.1:9090\n\
                        f7\nn127.0.0.1:9090\n";
        let listeners = parse_lsof(fixture, |pid| {
            (pid == 42).then(|| PathBuf::from("/Applications/Proxy.app/Contents/MacOS/Proxy"))
        })
        .unwrap();

        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0].port, 7070);
        assert_eq!(listeners[0].process_id, Some(42));
        assert_eq!(listeners[0].process_name.as_deref(), Some("Proxy"));
        assert_eq!(listeners[0].address, "127.0.0.1");
        assert_eq!(listeners[1].address, "::1");
        assert_eq!(listeners[2].port, 9090);
        assert!(listeners[2].process_name.is_none());
        assert!(listeners.iter().all(|row| row.port != 8080));
    }

    #[test]
    fn rejects_invalid_utf8_and_non_ports() {
        assert_eq!(
            parse_lsof(&[0xff], |_| None).unwrap_err().code,
            AdapterErrorCode::InvalidData
        );
        assert!(parse_loopback_endpoint("127.0.0.1:0").is_none());
        assert!(parse_loopback_endpoint("127.0.0.1:65536").is_none());
        assert!(parse_loopback_endpoint("192.0.2.1:80").is_none());
    }

    #[test]
    fn netstat_rows_attribute_listeners_lsof_cannot_see() {
        let monterey = b"Active Internet connections (including servers)\n\
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat shiwat    pid   epid  state    options\n\
tcp4       0      0  127.0.0.1.7897         *.*                    LISTEN      131072 131072  50368      0 0x0180 0x00000006\n\
tcp4       0      0  192.168.1.79.22         192.168.1.28.64111      ESTABLISHED 131072 131768  51226      0 0x0182 0x0000000c\n\
tcp46      0      0  *.8443                 *.*                    LISTEN      131072 131072    700      0 0x0100 0x00000006\n\
tcp6       0      0  ::1.7898               *.*                    LISTEN      131072 131072  50368      0 0x0180 0x00000006\n";
        assert_eq!(
            parse_netstat_listeners(monterey).unwrap(),
            [
                (7897, 50368, "127.0.0.1".to_owned()),
                (7898, 50368, "::1".to_owned()),
            ]
        );

        let sonoma = b"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes      txbytes  rhiwat  shiwat    process:pid    state  options\n\
tcp4       0      0  127.0.0.1.7897         *.*                    LISTEN             0            0  131072  131072  verge-mihom:50368 00102 00000006\n";
        assert_eq!(
            parse_netstat_listeners(sonoma).unwrap(),
            [(7897, 50368, "127.0.0.1".to_owned())]
        );
        assert!(parse_netstat_listeners(b"garbage\n").is_err());

        let mut listeners = parse_lsof(b"p42\ncProxy\nn127.0.0.1:7890\n", |_| None).unwrap();
        merge_unattributed_listeners(
            &mut listeners,
            vec![
                (7890, 99, "127.0.0.1".to_owned()),
                (7897, 50368, "127.0.0.1".to_owned()),
            ],
            |pid| {
                (pid == 50368).then(|| {
                    PathBuf::from("/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo")
                })
            },
        );
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].process_id, Some(42));
        assert_eq!(listeners[1].port, 7897);
        assert_eq!(listeners[1].process_id, Some(50368));
        assert_eq!(listeners[1].process_name.as_deref(), Some("verge-mihomo"));
    }

    #[test]
    fn discovers_the_current_process_loopback_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let current_pid = std::process::id();
        let listeners = MacosProcessDiscovery.loopback_listeners().unwrap();
        let owned = listeners
            .iter()
            .find(|row| row.port == port && row.process_id == Some(current_pid))
            .expect("the fixture listener must be attributed to the current process");
        assert_eq!(owned.address, "127.0.0.1");
        assert!(owned.process_path.as_deref().is_some_and(Path::is_absolute));
    }
}
