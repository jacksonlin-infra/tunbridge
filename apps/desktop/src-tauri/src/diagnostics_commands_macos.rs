use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
    time::Instant,
};
use tunbridge_desktop_contract::adapter::{AutoLaunch, Diagnostics};

const CURL: &str = "/usr/bin/curl";
const MAX_IP_BODY: usize = 32 * 1024;

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
    architecture: String,
    auto_launch: bool,
    app_version: &'static str,
    core_version: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticErrorCode {
    NetworkUnavailable,
    ProviderUnavailable,
    InvalidResponse,
    SystemInfoUnavailable,
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
    let body = curl_body("https://ipinfo.io/json", MAX_IP_BODY).map_err(|_| provider_error())?;
    parse_ip_information(&body).ok_or_else(invalid_response)
}

pub fn get_system_information() -> Result<SystemInformation, DiagnosticError> {
    let native = tunbridge_platform_macos::MacosDiagnostics
        .system_information()
        .map_err(|_| system_info_error())?;
    Ok(SystemInformation {
        schema_version: 1,
        os_name: native.os_name,
        display_version: native.os_release,
        build_number: native.build,
        architecture: native.architecture,
        auto_launch: tunbridge_platform_macos::MacosAutoLaunch
            .enabled()
            .map_err(|_| system_info_error())?,
        app_version: env!("CARGO_PKG_VERSION"),
        core_version: bundled_engine_version().unwrap_or_else(|| "Not installed".into()),
    })
}

/// The Mihomo version shipped in this App bundle. On macOS the helper only
/// provisions the engine from the signed bundle, so this is the version that
/// runs. The manifest is read with a size bound and the value is accepted only
/// in the `v<major>.<minor>.<patch>` form.
fn bundled_engine_version() -> Option<String> {
    const MAX_MANIFEST_BYTES: u64 = 4096;
    let executable = std::env::current_exe().ok()?;
    let root = executable.parent()?.parent()?.parent()?;
    let manifest = root.join(tunbridge_setup_macos::engine_asset::BUNDLE_ENGINE_MANIFEST_PATH);
    let metadata = fs::symlink_metadata(&manifest).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    parse_engine_manifest_version(&fs::read(manifest).ok()?)
}

fn parse_engine_manifest_version(body: &[u8]) -> Option<String> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let version = bounded_string(root.get("version"), 32)?;
    let digits = version.strip_prefix('v')?;
    let parts: Vec<&str> = digits.split('.').collect();
    (parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 4 && part.bytes().all(|b| b.is_ascii_digit())
        }))
    .then_some(version)
}

pub fn set_auto_launch(enabled: bool) -> Result<bool, DiagnosticError> {
    tunbridge_platform_macos::MacosAutoLaunch
        .set_enabled(enabled)
        .map_err(|_| system_info_error())
}

fn system_info_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::SystemInfoUnavailable,
        safe_message: "macOS system information is unavailable.",
        retryable: true,
    }
}

pub fn worker_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::NetworkUnavailable,
        safe_message: "The diagnostics worker is unavailable.",
        retryable: true,
    }
}

fn provider_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::ProviderUnavailable,
        safe_message: "The IP information provider is unavailable.",
        retryable: true,
    }
}

fn invalid_response() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::InvalidResponse,
        safe_message: "The diagnostics provider returned an invalid response.",
        retryable: true,
    }
}

fn curl_status(url: &str) -> Result<u16, ()> {
    validate_system_curl()?;
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
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;
    parse_http_status(output.status.success(), &output.stdout)
}

fn curl_body(url: &str, max: usize) -> Result<Vec<u8>, ()> {
    validate_system_curl()?;
    let max_text = max.to_string();
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
            &max_text,
            url,
        ])
        .env_clear()
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

fn parse_http_status(success: bool, output: &[u8]) -> Result<u16, ()> {
    if !success || output.len() != 3 {
        return Err(());
    }
    std::str::from_utf8(output)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or(())
}

fn parse_ip_information(body: &[u8]) -> Option<IpInformation> {
    if body.is_empty() || body.len() > MAX_IP_BODY {
        return None;
    }
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let ip = bounded_string(root.get("ip"), 64)?;
    IpAddr::from_str(&ip).ok()?;
    let country_code = bounded_string(root.get("country"), 2).unwrap_or_default();
    let organization = bounded_string(root.get("org"), 128).unwrap_or_default();
    let asn = organization
        .split_whitespace()
        .next()
        .and_then(|value| value.strip_prefix("AS"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    Some(IpInformation {
        schema_version: 1,
        ip,
        country: country_code.clone(),
        country_code,
        region: bounded_string(root.get("region"), 96).unwrap_or_default(),
        city: bounded_string(root.get("city"), 96).unwrap_or_default(),
        timezone: bounded_string(root.get("timezone"), 96).unwrap_or_default(),
        asn,
        organization,
        provider: "ipinfo.io",
    })
}

fn bounded_string(value: Option<&serde_json::Value>, max: usize) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= max)
        .filter(|value| !value.chars().any(char::is_control))
        .map(ToOwned::to_owned)
}

fn validate_system_curl() -> Result<(), ()> {
    let metadata = fs::symlink_metadata(Path::new(CURL)).map_err(|_| ())?;
    if metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.permissions().mode() & 0o022 == 0
        && metadata.nlink() == 1
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn reads_only_well_formed_engine_versions() {
        let manifest =
            br#"{"schemaVersion":1,"version":"v1.19.30","targetTriple":"x86_64-apple-darwin"}"#;
        assert_eq!(
            parse_engine_manifest_version(manifest).as_deref(),
            Some("v1.19.30")
        );
        for invalid in [
            br#"{"version":"1.19.30"}"#.as_slice(),
            br#"{"version":"v1.19"}"#,
            br#"{"version":"v1.19.30-rc1"}"#,
            br#"{"version":"v1.19.30\n"}"#,
            br#"{}"#,
            b"not json",
        ] {
            assert_eq!(parse_engine_manifest_version(invalid), None);
        }
    }
    use super::*;

    #[test]
    fn native_system_information_uses_the_shared_desktop_schema() {
        let information = get_system_information().unwrap();
        let value = serde_json::to_value(information).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["osName"], "macOS");
        assert!(value["displayVersion"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));
        assert!(value["buildNumber"].as_str().is_some_and(|v| !v.is_empty()));
        assert!(value["autoLaunch"].is_boolean());
        assert_eq!(value["appVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["coreVersion"], "Not installed");
        assert_eq!(value.as_object().unwrap().len(), 8);
    }

    #[test]
    fn diagnostic_targets_and_inputs_are_fixed() {
        let input: WebsiteTestInput =
            serde_json::from_value(serde_json::json!({"target":"github"})).unwrap();
        assert_eq!(input.target.url(), "https://github.com/");
        assert!(serde_json::from_value::<WebsiteTestInput>(
            serde_json::json!({"target":"github","url":"https://example.test"})
        )
        .is_err());
        assert!(serde_json::from_value::<WebsiteTestInput>(
            serde_json::json!({"target":"example"})
        )
        .is_err());
    }

    #[test]
    fn status_and_ip_fixtures_are_strict_and_bounded() {
        assert_eq!(parse_http_status(true, b"204"), Ok(204));
        for invalid in [b"99".as_slice(), b"999".as_slice(), b"2x4".as_slice()] {
            assert_eq!(parse_http_status(true, invalid), Err(()));
        }
        let information = parse_ip_information(
            br#"{"ip":"203.0.113.7","country":"SG","region":"Central","city":"Singapore","timezone":"Asia/Singapore","org":"AS64500 Example"}"#,
        )
        .unwrap();
        assert_eq!(information.ip, "203.0.113.7");
        assert_eq!(information.country_code, "SG");
        assert_eq!(information.asn, 64500);
        assert!(parse_ip_information(br#"{"ip":"not-an-ip"}"#).is_none());
        assert!(parse_ip_information(&vec![b'x'; MAX_IP_BODY + 1]).is_none());
    }
}
