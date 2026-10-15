use std::collections::BTreeMap;

use semver::Version;
use serde::{Deserialize, Serialize};

use tunbridge_core::release::{RELEASES_URL, RELEASE_DOWNLOAD_PREFIX, UPDATE_MANIFEST_PATH};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateInformation {
    schema_version: u16,
    current_version: String,
    latest_version: String,
    update_available: bool,
    published_at: String,
    target: String,
    package_kind: String,
    minimum_os: String,
    asset_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppUpdateErrorCode {
    Busy,
    UpdateUnavailable,
    InvalidResponse,
    UnsupportedTarget,
    ReleasePageUnavailable,
    WorkerFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateError {
    code: AppUpdateErrorCode,
    safe_message: &'static str,
    retryable: bool,
}

impl AppUpdateError {
    pub fn busy() -> Self {
        Self {
            code: AppUpdateErrorCode::Busy,
            safe_message: "Another TunBridge network request is active.",
            retryable: true,
        }
    }

    fn update_unavailable() -> Self {
        Self {
            code: AppUpdateErrorCode::UpdateUnavailable,
            safe_message: "The TunBridge release channel is unavailable.",
            retryable: true,
        }
    }

    fn invalid_response() -> Self {
        Self {
            code: AppUpdateErrorCode::InvalidResponse,
            safe_message: "The TunBridge release channel returned an invalid response.",
            retryable: true,
        }
    }

    fn unsupported_target() -> Self {
        Self {
            code: AppUpdateErrorCode::UnsupportedTarget,
            safe_message: "This TunBridge build does not have a compatible release package.",
            retryable: false,
        }
    }

    fn release_page_unavailable() -> Self {
        Self {
            code: AppUpdateErrorCode::ReleasePageUnavailable,
            safe_message: "The TunBridge releases page could not be opened.",
            retryable: true,
        }
    }

    pub fn worker_failed() -> Self {
        Self {
            code: AppUpdateErrorCode::WorkerFailed,
            safe_message: "The TunBridge update worker is unavailable.",
            retryable: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: u16,
    version: String,
    channel: String,
    published_at: String,
    targets: BTreeMap<String, ReleaseTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseTarget {
    package_kind: String,
    minimum_os: String,
    url: String,
    sha256: String,
}

pub fn get_app_update_information() -> Result<AppUpdateInformation, AppUpdateError> {
    let body = crate::diagnostics_commands::fetch_tunbridge_release_asset(
        UPDATE_MANIFEST_PATH,
        MAX_MANIFEST_BYTES,
    )
    .map_err(|_| AppUpdateError::update_unavailable())?;
    parse_release_manifest(&body, current_target()?, env!("CARGO_PKG_VERSION"))
}

fn parse_release_manifest(
    body: &[u8],
    target_name: &str,
    current_version: &str,
) -> Result<AppUpdateInformation, AppUpdateError> {
    if body.is_empty() || body.len() > MAX_MANIFEST_BYTES {
        return Err(AppUpdateError::invalid_response());
    }
    let manifest: ReleaseManifest =
        serde_json::from_slice(body).map_err(|_| AppUpdateError::invalid_response())?;
    if manifest.schema_version != 1
        || manifest.channel != "stable"
        || !valid_published_at(&manifest.published_at)
    {
        return Err(AppUpdateError::invalid_response());
    }
    let latest = parse_version(&manifest.version)?;
    let current = parse_version(current_version)?;
    if !latest.pre.is_empty() {
        return Err(AppUpdateError::invalid_response());
    }
    let target = manifest
        .targets
        .get(target_name)
        .ok_or_else(AppUpdateError::unsupported_target)?;
    validate_target(target_name, &manifest.version, target)?;
    let asset_name = target
        .url
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .ok_or_else(AppUpdateError::invalid_response)?;
    Ok(AppUpdateInformation {
        schema_version: 1,
        current_version: current_version.to_owned(),
        latest_version: manifest.version,
        update_available: latest > current,
        published_at: manifest.published_at,
        target: target_name.to_owned(),
        package_kind: target.package_kind.clone(),
        minimum_os: target.minimum_os.clone(),
        asset_name: asset_name.to_owned(),
    })
}

fn parse_version(value: &str) -> Result<Version, AppUpdateError> {
    let normalized = value.strip_prefix('v').unwrap_or(value);
    Version::parse(normalized).map_err(|_| AppUpdateError::invalid_response())
}

fn validate_target(
    target_name: &str,
    version: &str,
    target: &ReleaseTarget,
) -> Result<(), AppUpdateError> {
    let expected_kind = match target_name {
        name if name.starts_with("windows-") => "nsis",
        name if name.starts_with("darwin-") => "dmg",
        "linux-x86_64-deb" => "deb",
        "linux-x86_64-pacman" => "pacman",
        _ => return Err(AppUpdateError::unsupported_target()),
    };
    let expected_suffix = match expected_kind {
        "nsis" => ".exe",
        "dmg" => ".dmg",
        "deb" => ".deb",
        "pacman" => ".pkg.tar.zst",
        _ => unreachable!(),
    };
    let version = version.strip_prefix('v').unwrap_or(version);
    let expected_prefix = format!("{RELEASE_DOWNLOAD_PREFIX}tunbridge-desktop-v{version}/");
    if target.package_kind != expected_kind
        || target.minimum_os.is_empty()
        || target.minimum_os.len() > 64
        || target.minimum_os.chars().any(char::is_control)
        || !target.url.starts_with(&expected_prefix)
        || target.url.len() > 2048
        || target.url.contains(['?', '#', '\\'])
        || !target.url.ends_with(expected_suffix)
        || !is_lower_hex_256(&target.sha256)
    {
        return Err(AppUpdateError::invalid_response());
    }
    Ok(())
}

fn valid_published_at(value: &str) -> bool {
    (20..=35).contains(&value.len())
        && value.is_ascii()
        && value.contains('T')
        && (value.ends_with('Z') || value.as_bytes().iter().skip(10).any(|value| *value == b'+'))
        && !value.bytes().any(|value| value.is_ascii_control())
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn current_target() -> Result<&'static str, AppUpdateError> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("macos", "aarch64") => Ok("darwin-aarch64"),
        ("macos", "x86_64") => Ok("darwin-x86_64"),
        ("linux", "x86_64") if cfg!(feature = "omarchy-package") => Ok("linux-x86_64-pacman"),
        ("linux", "x86_64") => Ok("linux-x86_64-deb"),
        _ => Err(AppUpdateError::unsupported_target()),
    }
}

pub fn open_releases_page() -> Result<(), AppUpdateError> {
    open_url(RELEASES_URL).map_err(|_| AppUpdateError::release_page_unavailable())
}

#[cfg(windows)]
fn open_url(url: &str) -> Result<(), ()> {
    use std::ptr;
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let operation = "open".encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let url = url.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn open_url(url: &str) -> Result<(), ()> {
    open_with("/usr/bin/open", url)
}

#[cfg(target_os = "linux")]
fn open_url(url: &str) -> Result<(), ()> {
    open_with("/usr/bin/xdg-open", url)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_with(executable: &str, url: &str) -> Result<(), ()> {
    use std::process::{Command, Stdio};

    Command::new(executable)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, target: &str, package_kind: &str, extension: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "version": version,
            "channel": "stable",
            "publishedAt": "2026-08-20T10:00:00Z",
            "targets": {
                target: {
                    "packageKind": package_kind,
                    "minimumOs": "supported",
                    "url": format!(
                        "https://github.com/jacksonlin-infra/tunbridge/releases/download/tunbridge-desktop-v{version}/TunBridge-{version}{extension}"
                    ),
                    "sha256": "a".repeat(64)
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn accepts_one_stable_version_for_each_supported_package_kind() {
        for (target, kind, extension) in [
            ("windows-x86_64", "nsis", ".exe"),
            ("darwin-aarch64", "dmg", ".dmg"),
            ("linux-x86_64-deb", "deb", ".deb"),
            ("linux-x86_64-pacman", "pacman", ".pkg.tar.zst"),
        ] {
            let parsed = parse_release_manifest(
                &manifest("0.3.0", target, kind, extension),
                target,
                "0.2.13",
            )
            .unwrap();
            assert!(parsed.update_available);
            assert_eq!(parsed.latest_version, "0.3.0");
            assert_eq!(parsed.package_kind, kind);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_build_reports_its_package_specific_release_target() {
        assert_eq!(
            current_target().unwrap(),
            if cfg!(feature = "omarchy-package") {
                "linux-x86_64-pacman"
            } else {
                "linux-x86_64-deb"
            }
        );
    }

    #[test]
    fn semver_prevents_downgrades() {
        let parsed = parse_release_manifest(
            &manifest("0.3.0", "windows-x86_64", "nsis", ".exe"),
            "windows-x86_64",
            "0.3.1",
        )
        .unwrap();
        assert!(!parsed.update_available);
    }

    #[test]
    fn rejects_prerelease_or_untrusted_downloads() {
        let prerelease = manifest("0.3.0-beta.1", "windows-x86_64", "nsis", ".exe");
        assert!(parse_release_manifest(&prerelease, "windows-x86_64", "0.2.13").is_err());

        let mut untrusted: serde_json::Value =
            serde_json::from_slice(&manifest("0.3.0", "windows-x86_64", "nsis", ".exe")).unwrap();
        untrusted["targets"]["windows-x86_64"]["url"] =
            serde_json::Value::String("https://example.com/TunBridge.exe".into());
        assert!(parse_release_manifest(
            &serde_json::to_vec(&untrusted).unwrap(),
            "windows-x86_64",
            "0.2.13"
        )
        .is_err());

        untrusted["targets"]["windows-x86_64"]["url"] = serde_json::Value::String(
            "https://github.com/wrong-owner/tunbridge-desktop/releases/download/tunbridge-desktop-v0.3.0/TunBridge-0.3.0.exe".into(),
        );
        assert!(parse_release_manifest(
            &serde_json::to_vec(&untrusted).unwrap(),
            "windows-x86_64",
            "0.2.13"
        )
        .is_err());
    }

    #[test]
    fn errors_are_fixed_and_redacted() {
        for error in [
            AppUpdateError::busy(),
            AppUpdateError::update_unavailable(),
            AppUpdateError::invalid_response(),
            AppUpdateError::unsupported_target(),
            AppUpdateError::release_page_unavailable(),
            AppUpdateError::worker_failed(),
        ] {
            let body = serde_json::to_string(&error).unwrap();
            assert!(!body.contains("github.com"));
            assert!(!body.contains("jacksonlin-infra"));
        }
    }
}
