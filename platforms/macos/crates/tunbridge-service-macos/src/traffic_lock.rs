//! The traffic lock: while it exists, nothing but the engine may open
//! connections through a physical interface.
//!
//! A socket bound to the physical interface (or its address) would otherwise
//! leave around the tunnel, and a dead engine would otherwise let traffic
//! fall back to the original routes. The lock is a pf anchor under the
//! `com.apple/*` anchor point that the system ruleset already evaluates. It
//! outlives the engine and the helper and is removed only when the user stops
//! or recovers the tunnel.
//!
//! Only new outbound connections are refused: TCP SYNs, UDP and ICMP echo
//! requests. Replies to inbound connections and LAN traffic are untouched.

use std::net::IpAddr;

pub const ANCHOR: &str = "com.apple/tunbridge";

const LOCAL_V4: &str =
    "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }";
const LOCAL_V6: &str = "{ fe80::/10, fc00::/7, ff00::/8 }";
const MAX_INTERFACES: usize = 32;
const MAX_ALLOWED: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficLockError {
    Invalid,
    Unavailable,
}

/// Interfaces the lock closes: everything that is neither loopback nor a
/// tunnel. Their names come from the kernel, never from a caller.
pub fn lockable_interface(name: &str) -> bool {
    let (letters, digits) = name.split_at(
        name.find(|c: char| c.is_ascii_digit())
            .unwrap_or(name.len()),
    );
    !letters.is_empty()
        && !digits.is_empty()
        && name.len() <= 15
        && letters.bytes().all(|byte| byte.is_ascii_lowercase())
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && !matches!(letters, "lo" | "utun" | "ipsec" | "gif" | "stf" | "ppp")
}

/// The anchor ruleset. `engine_gid` is the group only the engine holds;
/// `allowed` are destinations the user's session already sends around the
/// tunnel on purpose (pinned upstream routes and profile bypass CIDRs).
pub fn anchor_rules(
    interfaces: &[String],
    engine_gid: u32,
    allowed: &[(IpAddr, u8)],
) -> Result<String, TrafficLockError> {
    if interfaces.is_empty()
        || interfaces.len() > MAX_INTERFACES
        || !interfaces.iter().all(|name| lockable_interface(name))
        || allowed.len() > MAX_ALLOWED
        || allowed.iter().any(|(address, prefix)| {
            address.is_unspecified()
                || *prefix == 0
                || *prefix > if address.is_ipv4() { 32 } else { 128 }
        })
    {
        return Err(TrafficLockError::Invalid);
    }
    let interfaces = format!("{{ {} }}", interfaces.join(" "));
    let mut rules = vec![
        format!("pass out quick inet to {LOCAL_V4}"),
        format!("pass out quick inet6 to {LOCAL_V6}"),
        "pass out quick proto udp from any port 68 to any port 67".to_owned(),
        "pass out quick inet6 proto udp from any port 546 to any port 547".to_owned(),
        format!("pass out quick group {engine_gid}"),
    ];
    for (address, prefix) in allowed {
        rules.push(format!("pass out quick to {address}/{prefix}"));
    }
    rules.extend([
        format!("block return out quick on {interfaces} proto tcp flags S/SA"),
        format!("block return out quick on {interfaces} proto udp"),
        format!("block return out quick on {interfaces} inet proto icmp icmp-type echoreq"),
        format!("block return out quick on {interfaces} inet6 proto icmp6 icmp6-type echoreq"),
    ]);
    let mut text = rules.join("\n");
    text.push('\n');
    Ok(text)
}

/// The token `pfctl -E` prints for the reference it took on pf.
pub fn parse_enable_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let token = line
            .trim()
            .strip_prefix("Token")?
            .trim()
            .strip_prefix(':')?
            .trim();
        (!token.is_empty() && token.len() <= 24 && token.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| token.to_owned())
    })
}

#[cfg(all(target_os = "macos", feature = "macos-native-lifecycle"))]
pub use native::{install, present, remove};

#[cfg(all(target_os = "macos", feature = "macos-native-lifecycle"))]
mod native {
    use super::{anchor_rules, lockable_interface, parse_enable_token, TrafficLockError, ANCHOR};
    use std::{
        fs,
        io::{Read, Write},
        net::IpAddr,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    const PFCTL: &str = "/sbin/pfctl";
    const TOKEN_FILE: &str = "/Library/Application Support/TunBridge/Runtime/traffic-lock-token";
    const PFCTL_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_OUTPUT_BYTES: u64 = 64 * 1024;

    /// Installs or atomically replaces the lock. The first install takes a
    /// pf enable reference and records its token so a restarted helper can
    /// release exactly that reference later.
    pub fn install(engine_gid: u32, allowed: &[(IpAddr, u8)]) -> Result<(), TrafficLockError> {
        let rules = anchor_rules(&physical_interfaces()?, engine_gid, allowed)?;
        if !system_ruleset_evaluates_anchor()? {
            return Err(TrafficLockError::Unavailable);
        }
        if read_token()?.is_none() {
            let output = pfctl(&["-E"], None)?;
            let token = parse_enable_token(&output.1).or_else(|| parse_enable_token(&output.0));
            let token = token.ok_or(TrafficLockError::Unavailable)?;
            write_token(&token)?;
        }
        let (_, _, ok) = pfctl(&["-a", ANCHOR, "-f", "-"], Some(&rules))?;
        if ok {
            Ok(())
        } else {
            Err(TrafficLockError::Unavailable)
        }
    }

    /// Removes the lock and releases the pf reference it took.
    pub fn remove() -> Result<(), TrafficLockError> {
        let (_, _, flushed) = pfctl(&["-a", ANCHOR, "-F", "rules"], None)?;
        if !flushed {
            return Err(TrafficLockError::Unavailable);
        }
        if let Some(token) = read_token()? {
            // A token that pf no longer knows (after a reboot) is released.
            let _ = pfctl(&["-X", &token], None)?;
            fs::remove_file(TOKEN_FILE).map_err(|_| TrafficLockError::Unavailable)?;
        }
        Ok(())
    }

    /// The lock is in force while its anchor holds rules.
    pub fn present() -> Result<bool, TrafficLockError> {
        let (stdout, _, ok) = pfctl(&["-a", ANCHOR, "-s", "rules"], None)?;
        if !ok {
            return Err(TrafficLockError::Unavailable);
        }
        Ok(stdout
            .lines()
            .any(|line| line.trim_start().starts_with("block")))
    }

    fn system_ruleset_evaluates_anchor() -> Result<bool, TrafficLockError> {
        let (stdout, _, ok) = pfctl(&["-s", "Anchors"], None)?;
        Ok(ok && stdout.lines().any(|line| line.trim() == "com.apple"))
    }

    fn physical_interfaces() -> Result<Vec<String>, TrafficLockError> {
        let mut head = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
            return Err(TrafficLockError::Unavailable);
        }
        let mut names = Vec::new();
        let mut current = head;
        while !current.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr((*current).ifa_name) };
            if let Ok(name) = name.to_str() {
                if lockable_interface(name) && !names.iter().any(|known| known == name) {
                    names.push(name.to_owned());
                }
            }
            current = unsafe { (*current).ifa_next };
        }
        unsafe { libc::freeifaddrs(head) };
        names.sort();
        Ok(names)
    }

    fn read_token() -> Result<Option<String>, TrafficLockError> {
        let path = Path::new(TOKEN_FILE);
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(TrafficLockError::Unavailable),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > 64
        {
            return Err(TrafficLockError::Unavailable);
        }
        let token = fs::read_to_string(path).map_err(|_| TrafficLockError::Unavailable)?;
        parse_enable_token(&format!("Token : {}", token.trim()))
            .map(Some)
            .ok_or(TrafficLockError::Unavailable)
    }

    fn write_token(token: &str) -> Result<(), TrafficLockError> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(TOKEN_FILE)
            .map_err(|_| TrafficLockError::Unavailable)?;
        file.write_all(token.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| TrafficLockError::Unavailable)
    }

    /// Runs the fixed system pfctl with bounded output and time.
    fn pfctl(
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<(String, String, bool), TrafficLockError> {
        let metadata = fs::symlink_metadata(PFCTL).map_err(|_| TrafficLockError::Unavailable)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(TrafficLockError::Unavailable);
        }
        let mut child = Command::new(PFCTL)
            .args(arguments)
            .env_clear()
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| TrafficLockError::Unavailable)?;
        if let Some(input) = input {
            let mut stdin = child.stdin.take().ok_or(TrafficLockError::Unavailable)?;
            stdin
                .write_all(input.as_bytes())
                .map_err(|_| TrafficLockError::Unavailable)?;
        }
        let mut stdout = child.stdout.take().ok_or(TrafficLockError::Unavailable)?;
        let mut stderr = child.stderr.take().ok_or(TrafficLockError::Unavailable)?;
        let readers = (
            std::thread::spawn(move || {
                let mut output = String::new();
                let _ = (&mut stdout)
                    .take(MAX_OUTPUT_BYTES)
                    .read_to_string(&mut output);
                output
            }),
            std::thread::spawn(move || {
                let mut output = String::new();
                let _ = (&mut stderr)
                    .take(MAX_OUTPUT_BYTES)
                    .read_to_string(&mut output);
                output
            }),
        );
        let deadline = Instant::now() + PFCTL_TIMEOUT;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| TrafficLockError::Unavailable)?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(TrafficLockError::Unavailable);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = readers
            .0
            .join()
            .map_err(|_| TrafficLockError::Unavailable)?;
        let stderr = readers
            .1
            .join()
            .map_err(|_| TrafficLockError::Unavailable)?;
        Ok((stdout, stderr, status.success()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_let_the_engine_lan_and_dhcp_out_and_close_new_physical_connections() {
        let rules = anchor_rules(
            &["en0".into(), "en1".into()],
            0x5442,
            &[("116.238.244.28".parse().unwrap(), 32)],
        )
        .unwrap();
        let lines: Vec<_> = rules.lines().collect();
        assert_eq!(
            lines,
            [
                "pass out quick inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }",
                "pass out quick inet6 to { fe80::/10, fc00::/7, ff00::/8 }",
                "pass out quick proto udp from any port 68 to any port 67",
                "pass out quick inet6 proto udp from any port 546 to any port 547",
                "pass out quick group 21570",
                "pass out quick to 116.238.244.28/32",
                "block return out quick on { en0 en1 } proto tcp flags S/SA",
                "block return out quick on { en0 en1 } proto udp",
                "block return out quick on { en0 en1 } inet proto icmp icmp-type echoreq",
                "block return out quick on { en0 en1 } inet6 proto icmp6 icmp6-type echoreq",
            ]
        );
    }

    #[test]
    fn only_kernel_style_physical_interfaces_are_lockable() {
        for name in ["en0", "en12", "bridge0", "awdl0", "llw0", "anpi1"] {
            assert!(lockable_interface(name), "{name}");
        }
        for name in [
            "lo0", "utun3", "ipsec0", "gif0", "stf0", "ppp0", "en", "0", "en0;", "EN0", "en0 en1",
        ] {
            assert!(!lockable_interface(name), "{name}");
        }
        assert_eq!(
            anchor_rules(&["en0; pass all".into()], 1, &[]),
            Err(TrafficLockError::Invalid)
        );
        assert_eq!(anchor_rules(&[], 1, &[]), Err(TrafficLockError::Invalid));
        assert_eq!(
            anchor_rules(&["en0".into()], 1, &[("0.0.0.0".parse().unwrap(), 0)]),
            Err(TrafficLockError::Invalid)
        );
    }

    #[test]
    fn enable_token_is_parsed_from_pfctl_output_only() {
        assert_eq!(
            parse_enable_token("pf enabled\nToken : 18446744073709551615\n").as_deref(),
            Some("18446744073709551615")
        );
        assert_eq!(parse_enable_token("Token : 12ab"), None);
        assert_eq!(parse_enable_token("No ALTQ support in kernel"), None);
    }
}
