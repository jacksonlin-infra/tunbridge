use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use tunbridge_desktop_contract::adapter::{
    AdapterError, AdapterErrorCode, ListenerIdentity, ProcessDiscovery,
};

const PROC_ROOT: &str = "/proc";
const MAX_COMM_BYTES: u64 = 256;
type ProcessOwner = (u32, String, Option<PathBuf>);
type SocketOwners = BTreeMap<u64, Vec<ProcessOwner>>;

pub struct LinuxProcessDiscovery;

impl ProcessDiscovery for LinuxProcessDiscovery {
    fn loopback_listeners(&self) -> Result<Vec<ListenerIdentity>, AdapterError> {
        discover_from(Path::new(PROC_ROOT))
    }
}

fn discover_from(proc_root: &Path) -> Result<Vec<ListenerIdentity>, AdapterError> {
    let mut sockets = BTreeMap::<u64, (String, u16)>::new();
    parse_socket_table(&proc_root.join("net/tcp"), false, &mut sockets)?;
    parse_socket_table(&proc_root.join("net/tcp6"), true, &mut sockets)?;

    let mut owners = SocketOwners::new();
    let entries = fs::read_dir(proc_root).map_err(|_| unavailable())?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        collect_process_sockets(&entry.path(), pid, &sockets, &mut owners);
    }

    let mut listeners = Vec::new();
    for (inode, (address, port)) in sockets {
        match owners.remove(&inode) {
            Some(processes) if !processes.is_empty() => {
                for (process_id, process_name, process_path) in processes {
                    listeners.push(ListenerIdentity {
                        address: address.clone(),
                        port,
                        process_id: Some(process_id),
                        process_name: Some(process_name),
                        process_path,
                    });
                }
            }
            _ => listeners.push(ListenerIdentity {
                address,
                port,
                process_id: None,
                process_name: None,
                process_path: None,
            }),
        }
    }
    listeners.sort_by(|left, right| {
        (left.port, left.process_id, &left.address).cmp(&(
            right.port,
            right.process_id,
            &right.address,
        ))
    });
    Ok(listeners)
}

fn parse_socket_table(
    path: &Path,
    ipv6: bool,
    sockets: &mut BTreeMap<u64, (String, u16)>,
) -> Result<(), AdapterError> {
    let contents = fs::read_to_string(path).map_err(|_| unavailable())?;
    for line in contents.lines().skip(1) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 10 || fields[3] != "0A" {
            continue;
        }
        let Some((address_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let address = if ipv6 {
            if address_hex != "00000000000000000000000001000000" {
                continue;
            }
            "::1"
        } else {
            if address_hex != "0100007F" {
                continue;
            }
            "127.0.0.1"
        };
        let (Ok(port), Ok(inode)) = (u16::from_str_radix(port_hex, 16), fields[9].parse::<u64>())
        else {
            continue;
        };
        if port != 0 && inode != 0 {
            sockets.insert(inode, (address.to_owned(), port));
        }
    }
    Ok(())
}

fn collect_process_sockets(
    process_root: &Path,
    pid: u32,
    sockets: &BTreeMap<u64, (String, u16)>,
    owners: &mut SocketOwners,
) {
    let Ok(file) = fs::File::open(process_root.join("comm")) else {
        return;
    };
    let mut process_name = String::new();
    if file
        .take(MAX_COMM_BYTES + 1)
        .read_to_string(&mut process_name)
        .is_err()
        || process_name.is_empty()
        || process_name.len() as u64 > MAX_COMM_BYTES
    {
        return;
    }
    let process_name = process_name.trim_end_matches('\n');
    if process_name.is_empty() || process_name.chars().any(char::is_control) {
        return;
    }
    let process_path = fs::read_link(process_root.join("exe"))
        .ok()
        .filter(|path| path.is_absolute());
    let Ok(descriptors) = fs::read_dir(process_root.join("fd")) else {
        return;
    };
    let mut seen = BTreeSet::new();
    for descriptor in descriptors.flatten() {
        let Ok(target) = fs::read_link(descriptor.path()) else {
            continue;
        };
        let Some(inode) = socket_inode(&target) else {
            continue;
        };
        if sockets.contains_key(&inode) && seen.insert(inode) {
            owners.entry(inode).or_default().push((
                pid,
                process_name.to_owned(),
                process_path.clone(),
            ));
        }
    }
}

fn socket_inode(target: &Path) -> Option<u64> {
    let target = target.to_str()?;
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

const fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "Linux listener enumeration is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-linux-proc-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fixture(root: &Path) {
        fs::create_dir_all(root.join("net")).unwrap();
        fs::create_dir_all(root.join("42/fd")).unwrap();
        fs::write(
            root.join("net/tcp"),
            "sl local_address rem_address st tx rx tr tm retrnsmt uid timeout inode\n\
             0: 0100007F:1B9E 00000000:0000 0A 0:0 00:0 0 1000 0 12345\n\
             1: 00000000:2382 00000000:0000 0A 0:0 00:0 0 1000 0 99999\n",
        )
        .unwrap();
        fs::write(
            root.join("net/tcp6"),
            "sl local_address rem_address st tx rx tr tm retrnsmt uid timeout inode\n\
             0: 00000000000000000000000001000000:1B9F 0:0 0A 0:0 00:0 0 1000 0 12346\n",
        )
        .unwrap();
        fs::write(root.join("42/comm"), "proxy-client\n").unwrap();
        symlink("/opt/proxy/client", root.join("42/exe")).unwrap();
        symlink("socket:[12345]", root.join("42/fd/3")).unwrap();
        symlink("socket:[12346]", root.join("42/fd/4")).unwrap();
    }

    #[test]
    fn joins_only_loopback_listeners_to_process_identity() {
        let root = root("join");
        fixture(&root);
        let listeners = discover_from(&root).unwrap();

        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].address, "127.0.0.1");
        assert_eq!(listeners[0].port, 7070);
        assert_eq!(listeners[0].process_id, Some(42));
        assert_eq!(listeners[0].process_name.as_deref(), Some("proxy-client"));
        assert_eq!(
            listeners[0].process_path.as_deref(),
            Some(Path::new("/opt/proxy/client"))
        );
        assert_eq!(listeners[1].address, "::1");
        assert_eq!(listeners[1].port, 7071);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_and_non_listening_rows_are_ignored() {
        let root = root("malformed");
        fs::create_dir_all(root.join("net")).unwrap();
        fs::write(
            root.join("net/tcp"),
            "header\n0: 0100007F:1B9E 0:0 01 0:0 00:0 0 1000 0 12345\nbad\n",
        )
        .unwrap();
        fs::write(root.join("net/tcp6"), "header\n").unwrap();

        assert!(discover_from(&root).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_proc_enumeration_is_bounded_and_safe() {
        let listeners = LinuxProcessDiscovery.loopback_listeners().unwrap();
        assert!(listeners.iter().all(|listener| listener.port != 0));
        assert!(listeners
            .iter()
            .all(|listener| matches!(listener.address.as_str(), "127.0.0.1" | "::1")));
    }

    #[test]
    fn actual_proc_joins_a_current_process_loopback_listener() {
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let mut listeners = Vec::new();
        for _ in 0..10 {
            listeners = LinuxProcessDiscovery.loopback_listeners().unwrap();
            if listeners.iter().any(|listener| {
                listener.port == port && listener.process_id == Some(std::process::id())
            }) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!(
            "port={port} pid={} listeners={listeners:?}",
            std::process::id()
        );
    }
}
