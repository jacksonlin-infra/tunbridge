use crate::platform::model::{Listener, NetSnapshot};
use crate::platform::{NetworkInspector, PortProber, Privilege, ProcessLister};
use crate::{CoreError, Result};
use std::io::Read;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const LISTENER_ENUMERATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_POWERSHELL_STDOUT_BYTES: u64 = 1024 * 1024;
const MAX_POWERSHELL_STDERR_BYTES: u64 = 64 * 1024;

fn run_ps(script: &str) -> Result<String> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| CoreError::Io(e.to_string()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let summary = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("unknown PowerShell error")
            .trim();
        return Err(CoreError::Io(format!("powershell failed: {summary}")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn run_ps_bounded(script: &str, timeout: Duration) -> Result<String> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd
        .spawn()
        .map_err(|error| CoreError::Io(error.to_string()))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CoreError::Io("powershell stdout was unavailable".into()));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CoreError::Io("powershell stderr was unavailable".into()));
    };
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_POWERSHELL_STDOUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(MAX_POWERSHELL_STDERR_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });

    let started = Instant::now();
    let (status, deadline_exceeded) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break (None, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CoreError::Io(error.to_string()));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| CoreError::Io("powershell stdout reader failed".into()))?
        .map_err(|error| CoreError::Io(error.to_string()))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| CoreError::Io("powershell stderr reader failed".into()))?
        .map_err(|error| CoreError::Io(error.to_string()))?;

    if deadline_exceeded {
        return Err(CoreError::Io("powershell deadline exceeded".into()));
    }
    if stdout.len() > MAX_POWERSHELL_STDOUT_BYTES as usize
        || stderr.len() > MAX_POWERSHELL_STDERR_BYTES as usize
    {
        return Err(CoreError::Io("powershell output exceeded limit".into()));
    }

    let status = status.ok_or_else(|| CoreError::Io("powershell exited without status".into()))?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let summary = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("unknown PowerShell error")
            .trim();
        return Err(CoreError::Io(format!("powershell failed: {summary}")));
    }
    Ok(String::from_utf8_lossy(&stdout).to_string())
}

/// ConvertTo-Json yields a bare object for a single element and an array for
/// many; normalize both into Vec<Listener>.
pub fn parse_listeners(json: &str) -> Result<Vec<Listener>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).map_err(|e| CoreError::Discovery(e.to_string()))
    } else {
        let one: Listener =
            serde_json::from_str(trimmed).map_err(|e| CoreError::Discovery(e.to_string()))?;
        Ok(vec![one])
    }
}

pub fn parse_netsnapshot(json: &str) -> Result<NetSnapshot> {
    serde_json::from_str(json.trim()).map_err(|e| CoreError::Io(e.to_string()))
}

pub struct WinPrivilege;
impl Privilege for WinPrivilege {
    fn is_elevated(&self) -> bool {
        let script = "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'yes' } else { 'no' }";
        run_ps(script).map(|s| s.trim() == "yes").unwrap_or(false)
    }
}

pub struct TcpPortProber;
impl PortProber for TcpPortProber {
    fn is_open(&self, host: &str, port: u16, timeout: Duration) -> bool {
        match format!("{host}:{port}").parse() {
            Ok(addr) => TcpStream::connect_timeout(&addr, timeout).is_ok(),
            Err(_) => false,
        }
    }
}

pub struct WinProcessLister;
impl ProcessLister for WinProcessLister {
    fn listeners(&self) -> Result<Vec<Listener>> {
        // Join listening TCP endpoints on loopback/any to their owning process.
        let script = r#"
$rows = Get-NetTCPConnection -State Listen -ErrorAction Stop |
  Where-Object { $_.LocalAddress -in '127.0.0.1','::1','0.0.0.0','::' } |
  ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    # process_name is the real on-disk file name (leaf of Path), which is exactly
    # what mihomo's PROCESS-NAME rule matches (e.g. "ExampleProxy_Mix.bin", "mihomo.exe").
    # ProcessName strips/rewrites extensions, so never derive the rule name from it.
    [pscustomobject]@{
      local_port   = [int]$_.LocalPort
      pid          = [int]$_.OwningProcess
      process_name = if ($p -and $p.Path) { Split-Path -Leaf $p.Path } elseif ($p) { $p.ProcessName + '.exe' } else { '' }
      process_path = if ($p) { $p.Path } else { $null }
    }
  } | Sort-Object local_port,pid
ConvertTo-Json -Compress -Depth 3 $rows
"#;
        let json = run_ps_bounded(script, LISTENER_ENUMERATION_TIMEOUT)?;
        parse_listeners(&json)
    }
}

pub struct WinNetworkInspector;
impl NetworkInspector for WinNetworkInspector {
    fn snapshot(&self) -> Result<NetSnapshot> {
        let script = r#"
$routes = Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
  ForEach-Object { '{0}|{1}|{2}' -f $_.DestinationPrefix, $_.InterfaceAlias, $_.NextHop } | Sort-Object
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object
ConvertTo-Json -Compress -Depth 3 ([pscustomobject]@{ routes = @($routes); adapters = @($adapters) })
"#;
        let json = run_ps(script)?;
        parse_netsnapshot(&json)
    }

    fn adapter_exists(&self, name: &str) -> bool {
        let script = format!(
            "if (Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue) {{ 'yes' }} else {{ 'no' }}"
        );
        run_ps(&script).map(|s| s.trim() == "yes").unwrap_or(false)
    }

    fn flush_dns(&self) -> Result<()> {
        run_ps("Clear-DnsClientCache -ErrorAction SilentlyContinue; 'ok'").map(|_| ())
    }

    fn remove_routes_for(&self, tun_name: &str) -> Result<()> {
        let script = format!(
            "Get-NetRoute -InterfaceAlias '{tun_name}' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; 'ok'"
        );
        run_ps(&script).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listeners_reads_ps_json() {
        let json = r#"[
          {"local_port":7078,"pid":47440,"process_name":"ExampleProxy_Mix.bin","process_path":"C:\\a\\ExampleProxy_Mix.bin"},
          {"local_port":25412,"pid":39276,"process_name":"mihomo","process_path":null}
        ]"#;
        let v = parse_listeners(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].local_port, 7078);
        assert_eq!(v[0].process_name, "ExampleProxy_Mix.bin");
        assert_eq!(v[1].process_path, None);
    }

    #[test]
    fn parse_listeners_tolerates_single_object() {
        let json = r#"{"local_port":1080,"pid":10,"process_name":"x","process_path":null}"#;
        let v = parse_listeners(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].local_port, 1080);
    }

    #[test]
    fn parse_netsnapshot_reads_ps_json() {
        let json =
            r#"{"routes":["0.0.0.0/0|Ethernet|192.168.1.1"],"adapters":["Ethernet","tunbridge"]}"#;
        let s = parse_netsnapshot(json).unwrap();
        assert_eq!(s.routes.len(), 1);
        assert!(s.adapters.contains(&"tunbridge".to_string()));
    }

    #[test]
    fn bounded_powershell_terminates_only_its_exact_child_at_deadline() {
        let error = run_ps_bounded(
            "Start-Sleep -Milliseconds 500; [Console]::Out.Write('late')",
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    #[test]
    fn bounded_powershell_captures_fixed_output() {
        assert_eq!(
            run_ps_bounded("[Console]::Out.Write('ok')", Duration::from_secs(2)).unwrap(),
            "ok"
        );
    }
}
