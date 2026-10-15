use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    time::Instant,
};

use serde::{Deserialize, Serialize};

const CURL: &str = "/usr/bin/curl";
const PKEXEC: &str = "/usr/bin/pkexec";
const MAINTENANCE: &str = "/usr/libexec/tunbridge/tunbridge-maintenance-linux";
const ENGINE_MANIFEST: &str = "/usr/share/tunbridge/engine-manifest.json";
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebsiteTarget {
    Apple,
    #[serde(rename = "github")]
    GitHub,
    Google,
    #[serde(rename = "youtube")]
    YouTube,
    #[serde(rename = "chatgpt")]
    ChatGpt,
    Claude,
    Gemini,
    Netflix,
    Spotify,
    #[serde(rename = "tiktok")]
    TikTok,
}

impl WebsiteTarget {
    fn url(self) -> &'static str {
        match self {
            Self::Apple => "https://www.apple.com/library/test/success.html",
            Self::GitHub => "https://github.com/",
            Self::Google => "https://www.google.com/generate_204",
            Self::YouTube => "https://www.youtube.com/generate_204",
            Self::ChatGpt => "https://chatgpt.com/",
            Self::Claude => "https://claude.ai/",
            Self::Gemini => "https://gemini.google.com/",
            Self::Netflix => "https://www.netflix.com/",
            Self::Spotify => "https://open.spotify.com/",
            Self::TikTok => "https://www.tiktok.com/",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebsiteTestInput {
    target: WebsiteTarget,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteTestResult {
    schema_version: u16,
    target: WebsiteTarget,
    reachable: bool,
    latency_ms: u32,
    http_status: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpInformation {
    schema_version: u16,
    ip: String,
    country: String,
    country_code: String,
    region: String,
    city: String,
    timezone: String,
    asn: u64,
    organization: String,
    provider: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInformation {
    schema_version: u16,
    os_name: String,
    display_version: String,
    build_number: String,
    architecture: &'static str,
    auto_launch: bool,
    app_version: &'static str,
    core_version: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreUpdateInformation {
    schema_version: u16,
    current_version: String,
    latest_version: String,
    update_available: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticErrorCode {
    NetworkUnavailable,
    ProviderUnavailable,
    InvalidResponse,
    SystemInfoUnavailable,
    CoreUpdateUnavailable,
    CoreUpdateIdentityFailed,
    CoreUpdateFailed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticError {
    code: DiagnosticErrorCode,
    safe_message: &'static str,
    retryable: bool,
}

pub fn test_website(input: WebsiteTestInput) -> Result<WebsiteTestResult, DiagnosticError> {
    let started = Instant::now();
    let status = curl_status(input.target.url()).unwrap_or(0);
    Ok(WebsiteTestResult {
        schema_version: 1,
        target: input.target,
        reachable: (200..400).contains(&status),
        latency_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        http_status: status,
    })
}

pub fn get_ip_information() -> Result<IpInformation, DiagnosticError> {
    let body = curl_body("https://ipinfo.io/json", 32 * 1024).map_err(|_| provider_error())?;
    parse_ip_information(&body).ok_or_else(invalid_response)
}

pub fn get_system_information() -> Result<SystemInformation, DiagnosticError> {
    let (os_name, display_version) = ["/etc/os-release", "/usr/lib/os-release"]
        .into_iter()
        .find_map(|path| {
            let release = read_root_small(Path::new(path), 16 * 1024)?;
            Some((
                os_release_value(&release, "NAME")?,
                os_release_value(&release, "VERSION_ID")?,
            ))
        })
        .ok_or_else(system_info_error)?;
    let build_number = read_root_small(Path::new("/proc/sys/kernel/osrelease"), 256)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(system_info_error)?;
    Ok(SystemInformation {
        schema_version: 1,
        os_name,
        display_version,
        build_number,
        architecture: std::env::consts::ARCH,
        auto_launch: auto_launch_enabled(),
        app_version: env!("CARGO_PKG_VERSION"),
        core_version: current_core_version(),
    })
}

pub fn set_auto_launch(enabled: bool) -> Result<bool, DiagnosticError> {
    let path = auto_launch_path().ok_or_else(system_info_error)?;
    let parent = path.parent().ok_or_else(system_info_error)?;
    if !enabled && !path.exists() {
        return Ok(false);
    }
    secure_user_directory(parent)?;
    if enabled {
        let executable = std::env::current_exe().map_err(|_| system_info_error())?;
        let executable = executable
            .to_str()
            .filter(|v| !v.contains('\n'))
            .ok_or_else(system_info_error)?;
        let body = format!(
            "[Desktop Entry]\nType=Application\nName=TunBridge\nExec={} --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            desktop_exec_quote(executable)
        );
        atomic_user_file(&path, body.as_bytes())?;
    } else if path.exists() {
        let metadata = fs::symlink_metadata(&path).map_err(|_| system_info_error())?;
        if !valid_user_file(&metadata) {
            return Err(system_info_error());
        }
        fs::remove_file(&path).map_err(|_| system_info_error())?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| system_info_error())?;
    }
    Ok(auto_launch_enabled())
}

pub fn get_core_update_information() -> Result<CoreUpdateInformation, DiagnosticError> {
    let current_version = current_core_version();
    let latest_version = latest_core_version()?;
    Ok(CoreUpdateInformation {
        schema_version: 1,
        update_available: normalize_version(&latest_version) != normalize_version(&current_version),
        current_version,
        latest_version,
    })
}

pub fn install_core_update() -> Result<CoreUpdateInformation, DiagnosticError> {
    let before = get_core_update_information()?;
    if !before.update_available {
        return Ok(before);
    }
    validate_root_executable(Path::new(PKEXEC)).map_err(|_| core_update_identity_error())?;
    validate_root_executable(Path::new(MAINTENANCE)).map_err(|_| core_update_identity_error())?;
    let status = Command::new(PKEXEC)
        .args([MAINTENANCE, "update-core"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| core_update_failed())?;
    if !status.success() {
        return Err(core_update_failed());
    }
    get_core_update_information()
}

fn curl_status(url: &str) -> Result<u16, ()> {
    validate_root_executable(Path::new(CURL))?;
    let output = Command::new(CURL)
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "8",
            "--connect-timeout",
            "5",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            url,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() != 3 {
        return Err(());
    }
    std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|v| v.parse().ok())
        .ok_or(())
}

fn curl_body(url: &str, max: usize) -> Result<Vec<u8>, ()> {
    validate_root_executable(Path::new(CURL))?;
    let output = Command::new(CURL)
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "8",
            "--connect-timeout",
            "5",
            "--max-filesize",
            &max.to_string(),
            url,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > max {
        return Err(());
    }
    Ok(output.stdout)
}

pub(crate) fn fetch_tunbridge_release_asset(path: &str, max: usize) -> Result<Vec<u8>, ()> {
    if !path.starts_with(tunbridge_core::release::RELEASE_ASSET_PATH_PREFIX)
        || path
            .bytes()
            .any(|value| value.is_ascii_control() || value == b'?' || value == b'#')
    {
        return Err(());
    }
    curl_body(&format!("https://github.com{path}"), max)
}

fn latest_core_version() -> Result<String, DiagnosticError> {
    let body = curl_body(
        "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
        MAX_BODY,
    )
    .map_err(|_| core_update_unavailable())?;
    let root: serde_json::Value = serde_json::from_slice(&body).map_err(|_| invalid_response())?;
    bounded_string(root.get("tag_name"), 64).ok_or_else(invalid_response)
}

fn current_core_version() -> String {
    read_small(Path::new(ENGINE_MANIFEST), 4096)
        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
        .and_then(|root| bounded_string(root.get("version"), 64))
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_ip_information(body: &[u8]) -> Option<IpInformation> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let ip = bounded_string(root.get("ip"), 64)?;
    IpAddr::from_str(&ip).ok()?;
    let organization = bounded_string(root.get("org"), 128).unwrap_or_default();
    let asn = organization
        .split_whitespace()
        .next()?
        .strip_prefix("AS")
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    Some(IpInformation {
        schema_version: 1,
        ip,
        country: bounded_string(root.get("country"), 96).unwrap_or_default(),
        country_code: bounded_string(root.get("country"), 2).unwrap_or_default(),
        region: bounded_string(root.get("region"), 96).unwrap_or_default(),
        city: bounded_string(root.get("city"), 96).unwrap_or_default(),
        timezone: bounded_string(root.get("timezone"), 96).unwrap_or_default(),
        asn,
        organization,
        provider: "ipinfo.io",
    })
}

fn auto_launch_path() -> Option<PathBuf> {
    let config = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return None;
            }
            path
        }
        None => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(config.join("autostart/tunbridge.desktop"))
}

fn auto_launch_enabled() -> bool {
    let Some(path) = auto_launch_path() else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    valid_user_file(&metadata)
        && read_small(&path, 4096)
            .is_some_and(|body| body.contains("X-GNOME-Autostart-enabled=true"))
}

fn secure_user_directory(path: &Path) -> Result<(), DiagnosticError> {
    fs::create_dir_all(path).map_err(|_| system_info_error())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| system_info_error())?;
    let metadata = fs::symlink_metadata(path).map_err(|_| system_info_error())?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(system_info_error());
    }
    Ok(())
}

fn atomic_user_file(path: &Path, bytes: &[u8]) -> Result<(), DiagnosticError> {
    let parent = path.parent().ok_or_else(system_info_error)?;
    let candidate = parent.join(format!(".tunbridge.desktop.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&candidate)
        .map_err(|_| system_info_error())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| system_info_error())?;
    fs::rename(&candidate, path).map_err(|_| system_info_error())?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| system_info_error())
}

fn valid_user_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
        && metadata.nlink() == 1
}

fn desktop_exec_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
    )
}

fn validate_root_executable(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.nlink() == 1
    {
        Ok(())
    } else {
        Err(())
    }
}

fn read_small(path: &Path, max: usize) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() as usize > max {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .ok()?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > max {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn read_root_small(path: &Path, max: usize) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
        return None;
    }
    read_small(path, max)
}

fn os_release_value(body: &str, key: &str) -> Option<String> {
    let value = body
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))?;
    let value = value.trim_matches('"');
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn bounded_string(value: Option<&serde_json::Value>, max: usize) -> Option<String> {
    let value = value?.as_str()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_string())
    }
}

fn normalize_version(value: &str) -> &str {
    value.trim().trim_start_matches('v')
}
fn error(
    code: DiagnosticErrorCode,
    safe_message: &'static str,
    retryable: bool,
) -> DiagnosticError {
    DiagnosticError {
        code,
        safe_message,
        retryable,
    }
}
fn invalid_response() -> DiagnosticError {
    error(
        DiagnosticErrorCode::InvalidResponse,
        "The remote information provider returned an invalid response.",
        true,
    )
}
fn provider_error() -> DiagnosticError {
    error(
        DiagnosticErrorCode::ProviderUnavailable,
        "The IP information provider is temporarily unavailable.",
        true,
    )
}
fn system_info_error() -> DiagnosticError {
    error(
        DiagnosticErrorCode::SystemInfoUnavailable,
        "Linux system information is unavailable.",
        false,
    )
}
fn core_update_identity_error() -> DiagnosticError {
    error(
        DiagnosticErrorCode::CoreUpdateIdentityFailed,
        "The Mihomo update failed identity verification.",
        false,
    )
}
fn core_update_unavailable() -> DiagnosticError {
    error(
        DiagnosticErrorCode::CoreUpdateUnavailable,
        "The official Mihomo update package is unavailable.",
        true,
    )
}
pub fn core_update_failed() -> DiagnosticError {
    error(
        DiagnosticErrorCode::CoreUpdateFailed,
        "The Mihomo core update could not be completed safely.",
        true,
    )
}
pub fn worker_error() -> DiagnosticError {
    error(
        DiagnosticErrorCode::NetworkUnavailable,
        "The bounded diagnostics worker could not complete.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parses_ipinfo_contract() {
        let value = parse_ip_information(br#"{"ip":"203.0.113.5","country":"EX","region":"R","city":"C","timezone":"Etc/UTC","org":"AS64500 Example"}"#).unwrap();
        assert_eq!(value.asn, 64500);
    }
    #[test]
    fn rejects_relative_xdg_config() {
        let _guard = ENVIRONMENT_LOCK.lock().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", "relative");
        assert!(auto_launch_path().is_none());
        std::env::remove_var("XDG_CONFIG_HOME");
    }
    #[test]
    fn website_wire_ids_match_ui() {
        assert_eq!(
            serde_json::from_str::<WebsiteTarget>("\"github\"").unwrap(),
            WebsiteTarget::GitHub
        );
        assert!(serde_json::from_str::<WebsiteTarget>("\"git_hub\"").is_err());
    }

    #[test]
    fn real_linux_system_information_and_autostart_round_trip() {
        let _guard = ENVIRONMENT_LOCK.lock().unwrap();
        let root =
            std::env::temp_dir().join(format!("tunbridge-diagnostics-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &root);

        let system = get_system_information().unwrap();
        assert!(!system.os_name.is_empty());
        assert!(!system.display_version.is_empty());
        assert!(set_auto_launch(true).unwrap());
        assert!(auto_launch_enabled());
        assert!(!set_auto_launch(false).unwrap());

        std::env::remove_var("XDG_CONFIG_HOME");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disabling_absent_autostart_does_not_create_user_directory() {
        let _guard = ENVIRONMENT_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "tunbridge-diagnostics-absent-{}",
            std::process::id()
        ));
        std::env::set_var("XDG_CONFIG_HOME", &root);

        assert!(!set_auto_launch(false).unwrap());
        assert!(!root.exists());

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    #[ignore = "requires Linux HTTPS access"]
    fn real_linux_https_diagnostics() {
        let website = test_website(WebsiteTestInput {
            target: WebsiteTarget::GitHub,
        })
        .unwrap();
        assert!(website.reachable);
        assert!(get_ip_information().is_ok());
        assert!(get_core_update_information().is_ok());
        assert!(!install_core_update().unwrap().update_available);
    }
}
