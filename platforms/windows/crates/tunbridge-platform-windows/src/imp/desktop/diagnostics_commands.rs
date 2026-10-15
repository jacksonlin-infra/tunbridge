use std::{
    ffi::c_void,
    fs,
    io::{Cursor, Read},
    net::IpAddr,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    str::FromStr,
    time::Instant,
};

use flate2::read::DeflateDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
        WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_QUERY_STATUS_CODE,
    },
    System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegSetValueExW,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
        RRF_RT_REG_SZ,
    },
};

const NETWORK_TIMEOUT_MS: i32 = 5_000;
const MAX_IP_BODY_BYTES: usize = 32 * 1024;
const MAX_CORE_RELEASE_BODY_BYTES: usize = 1024 * 1024;
const MAX_CORE_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CORE_EXECUTABLE_BYTES: usize = 128 * 1024 * 1024;
const MIHOMO_ARCHIVE_ENTRY: &str = "mihomo-windows-amd64-v2.exe";
const WINDOWS_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const WINDOWS_RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const AUTO_LAUNCH_VALUE: &str = "TunBridge";

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
    fn endpoint(self) -> (&'static str, &'static str) {
        match self {
            Self::Apple => ("www.apple.com", "/library/test/success.html"),
            Self::GitHub => ("github.com", "/"),
            Self::Google => ("www.google.com", "/generate_204"),
            Self::YouTube => ("www.youtube.com", "/generate_204"),
            Self::ChatGpt => ("chatgpt.com", "/"),
            Self::Claude => ("claude.ai", "/"),
            Self::Gemini => ("gemini.google.com", "/"),
            Self::Netflix => ("www.netflix.com", "/"),
            Self::Spotify => ("open.spotify.com", "/"),
            Self::TikTok => ("www.tiktok.com", "/"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebsiteTestInput {
    target: WebsiteTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteTestResult {
    schema_version: u16,
    target: WebsiteTarget,
    reachable: bool,
    latency_ms: u32,
    http_status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreUpdateInformation {
    schema_version: u16,
    current_version: String,
    latest_version: String,
    update_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticError {
    code: DiagnosticErrorCode,
    safe_message: &'static str,
    retryable: bool,
}

pub fn test_website(input: WebsiteTestInput) -> Result<WebsiteTestResult, DiagnosticError> {
    let (host, path) = input.target.endpoint();
    let started = Instant::now();
    let response = https_get(host, path, 0);
    let (reachable, http_status) = match response {
        Ok(response) => ((200..400).contains(&response.status), response.status),
        Err(()) => (false, 0),
    };
    Ok(WebsiteTestResult {
        schema_version: 1,
        target: input.target,
        reachable,
        latency_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        http_status,
    })
}

pub fn get_ip_information() -> Result<IpInformation, DiagnosticError> {
    let response =
        https_get("ipinfo.io", "/json", MAX_IP_BODY_BYTES).map_err(|_| network_error())?;
    if !(200..300).contains(&response.status) {
        return Err(provider_error());
    }
    parse_ip_information(&response.body).ok_or_else(invalid_response)
}

pub fn get_system_information() -> Result<SystemInformation, DiagnosticError> {
    let registry_name = registry_string("ProductName")?;
    let display_version =
        registry_string("DisplayVersion").or_else(|_| registry_string("ReleaseId"))?;
    let build_number = registry_string("CurrentBuildNumber")?;
    let os_name = corrected_windows_product_name(&registry_name, &build_number);
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
    let key_path = wide(WINDOWS_RUN_KEY);
    let value_name = wide(AUTO_LAUNCH_VALUE);
    let mut key = null_mut();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            null(),
            &mut key,
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(system_info_error());
    }
    let operation = if enabled {
        let executable = std::env::current_exe().map_err(|_| system_info_error())?;
        let command = format!("\"{}\" --background", executable.display());
        let data = wide(&command);
        unsafe {
            RegSetValueExW(
                key,
                value_name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        }
    } else {
        unsafe { RegDeleteValueW(key, value_name.as_ptr()) }
    };
    unsafe { RegCloseKey(key) };
    if enabled && operation != ERROR_SUCCESS {
        return Err(system_info_error());
    }
    Ok(auto_launch_enabled())
}

pub fn get_core_update_information() -> Result<CoreUpdateInformation, DiagnosticError> {
    let current_version = current_core_version();
    let release = load_core_release()?;
    let latest_version = release.version;
    Ok(CoreUpdateInformation {
        schema_version: 1,
        update_available: normalize_version(&latest_version) != normalize_version(&current_version),
        current_version,
        latest_version,
    })
}

pub fn install_core_update() -> Result<CoreUpdateInformation, DiagnosticError> {
    let current_version = current_core_version();
    let release = load_core_release()?;
    if normalize_version(&release.version) == normalize_version(&current_version) {
        return Ok(CoreUpdateInformation {
            schema_version: 1,
            current_version: current_version.clone(),
            latest_version: current_version,
            update_available: false,
        });
    }
    let archive = https_get_url(&release.download_url, MAX_CORE_ARCHIVE_BYTES)
        .map_err(|_| network_error())?;
    if !(200..300).contains(&archive.status) || archive.body.is_empty() {
        return Err(core_update_unavailable());
    }
    if sha256_bytes(&archive.body) != release.archive_sha256 {
        return Err(core_update_identity_error());
    }
    let executable = extract_mihomo(&archive.body)?;
    let stage = stage_core_package(&release, &executable)?;
    let installed = crate::installer_commands::update_core_from(&stage).is_ok();
    let _ = fs::remove_dir_all(&stage);
    if !installed {
        return Err(core_update_failed());
    }
    let installed_version = installed_core_version().ok_or_else(core_update_failed)?;
    if normalize_version(&installed_version) != normalize_version(&release.version) {
        return Err(core_update_failed());
    }
    Ok(CoreUpdateInformation {
        schema_version: 1,
        current_version: installed_version,
        latest_version: release.version,
        update_available: false,
    })
}

struct CoreRelease {
    version: String,
    asset_name: String,
    archive_sha256: String,
    download_url: String,
}

fn load_core_release() -> Result<CoreRelease, DiagnosticError> {
    let response = https_get(
        "api.github.com",
        "/repos/MetaCubeX/mihomo/releases/latest",
        MAX_CORE_RELEASE_BODY_BYTES,
    )
    .map_err(|_| network_error())?;
    if !(200..300).contains(&response.status) {
        return Err(provider_error());
    }
    let root: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| invalid_response())?;
    let version = bounded_string(root.get("tag_name"), 64).ok_or_else(invalid_response)?;
    let asset_name = format!("mihomo-windows-amd64-v2-{version}.zip");
    let asset = root
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .and_then(|assets| {
            assets.iter().find(|asset| {
                asset.get("name").and_then(serde_json::Value::as_str) == Some(&asset_name)
            })
        })
        .ok_or_else(core_update_unavailable)?;
    let digest = bounded_string(asset.get("digest"), 80).ok_or_else(core_update_identity_error)?;
    let archive_sha256 = digest
        .strip_prefix("sha256:")
        .filter(|value| is_lower_hex_256(value))
        .ok_or_else(core_update_identity_error)?
        .to_string();
    let download_url =
        bounded_string(asset.get("browser_download_url"), 2048).ok_or_else(invalid_response)?;
    validate_github_download_url(&download_url)?;
    Ok(CoreRelease {
        version,
        asset_name,
        archive_sha256,
        download_url,
    })
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

struct InternetHandle(*mut c_void);

impl Drop for InternetHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: every handle is returned by WinHTTP and closed exactly once here.
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn https_get(host: &str, path: &str, max_body_bytes: usize) -> Result<HttpResponse, ()> {
    let agent = wide("TunBridge/0.1");
    let host_wide = wide(host);
    let verb = wide("GET");
    let path_wide = wide(path);
    // SAFETY: all strings are terminated UTF-16 buffers and handles are checked before use.
    unsafe {
        let session = InternetHandle(WinHttpOpen(
            agent.as_ptr(),
            // Desktop update traffic must follow the current user's Windows
            // proxy configuration. Forcing a direct connection breaks the
            // update as soon as System TUN is stopped on networks where GitHub
            // is reachable only through the user's local proxy.
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        ));
        if session.0.is_null()
            || WinHttpSetTimeouts(
                session.0,
                NETWORK_TIMEOUT_MS,
                NETWORK_TIMEOUT_MS,
                NETWORK_TIMEOUT_MS,
                NETWORK_TIMEOUT_MS,
            ) == 0
        {
            return Err(());
        }
        let connection = InternetHandle(WinHttpConnect(session.0, host_wide.as_ptr(), 443, 0));
        if connection.0.is_null() {
            return Err(());
        }
        let request = InternetHandle(WinHttpOpenRequest(
            connection.0,
            verb.as_ptr(),
            path_wide.as_ptr(),
            null(),
            null(),
            null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null()
            || WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) == 0
            || WinHttpReceiveResponse(request.0, null_mut()) == 0
        {
            return Err(());
        }
        let mut status = 0_u32;
        let mut status_size = std::mem::size_of::<u32>() as u32;
        if WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast(),
            &mut status_size,
            null_mut(),
        ) == 0
        {
            return Err(());
        }
        let mut body = Vec::new();
        while body.len() < max_body_bytes {
            let remaining = (max_body_bytes - body.len()).min(4096);
            let mut chunk = vec![0_u8; remaining];
            let mut read = 0_u32;
            if WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast(),
                remaining as u32,
                &mut read,
            ) == 0
            {
                return Err(());
            }
            if read == 0 {
                break;
            }
            chunk.truncate(read as usize);
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status: status.min(u16::MAX as u32) as u16,
            body,
        })
    }
}

pub(crate) fn fetch_tunbridge_release_asset(
    path: &str,
    max_body_bytes: usize,
) -> Result<Vec<u8>, ()> {
    if !path.starts_with(tunbridge_core::release::RELEASE_ASSET_PATH_PREFIX)
        || path
            .bytes()
            .any(|value| value.is_ascii_control() || value == b'?' || value == b'#')
    {
        return Err(());
    }
    let response = https_get("github.com", path, max_body_bytes)?;
    if !(200..300).contains(&response.status)
        || response.body.is_empty()
        || response.body.len() > max_body_bytes
    {
        return Err(());
    }
    Ok(response.body)
}

fn parse_ip_information(body: &[u8]) -> Option<IpInformation> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let ip = bounded_string(root.get("ip"), 64)?;
    IpAddr::from_str(&ip).ok()?;
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

fn https_get_url(url: &str, max_body_bytes: usize) -> Result<HttpResponse, ()> {
    let without_scheme = url.strip_prefix("https://").ok_or(())?;
    let (host, remainder) = without_scheme.split_once('/').ok_or(())?;
    if host != "github.com" {
        return Err(());
    }
    https_get(host, &format!("/{remainder}"), max_body_bytes)
}

fn validate_github_download_url(url: &str) -> Result<(), DiagnosticError> {
    let expected = "https://github.com/MetaCubeX/mihomo/releases/download/";
    if !url.starts_with(expected)
        || url.len() > 2048
        || url.chars().any(char::is_control)
        || url.contains('\\')
        || url.contains("..")
    {
        return Err(invalid_response());
    }
    Ok(())
}

fn extract_mihomo(archive: &[u8]) -> Result<Vec<u8>, DiagnosticError> {
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .ok_or_else(core_update_identity_error)?;
    let entries = zip_u16(archive, eocd + 10)? as usize;
    let central_size = zip_u32(archive, eocd + 12)? as usize;
    let central_offset = zip_u32(archive, eocd + 16)? as usize;
    if entries == 0
        || entries > 32
        || central_offset.checked_add(central_size).is_none()
        || central_offset + central_size > archive.len()
    {
        return Err(core_update_identity_error());
    }
    let mut cursor = central_offset;
    for _ in 0..entries {
        if archive.get(cursor..cursor + 4) != Some(b"PK\x01\x02") {
            return Err(core_update_identity_error());
        }
        let method = zip_u16(archive, cursor + 10)?;
        let compressed_size = zip_u32(archive, cursor + 20)? as usize;
        let uncompressed_size = zip_u32(archive, cursor + 24)? as usize;
        let name_len = zip_u16(archive, cursor + 28)? as usize;
        let extra_len = zip_u16(archive, cursor + 30)? as usize;
        let comment_len = zip_u16(archive, cursor + 32)? as usize;
        let local_offset = zip_u32(archive, cursor + 42)? as usize;
        let name_start = cursor + 46;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(core_update_identity_error)?;
        let name = std::str::from_utf8(
            archive
                .get(name_start..name_end)
                .ok_or_else(core_update_identity_error)?,
        )
        .map_err(|_| core_update_identity_error())?;
        cursor = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(core_update_identity_error)?;
        let is_mihomo = name == MIHOMO_ARCHIVE_ENTRY && Path::new(name).components().count() == 1;
        if !is_mihomo {
            continue;
        }
        if !(1024 * 1024..=MAX_CORE_EXECUTABLE_BYTES).contains(&uncompressed_size)
            || archive.get(local_offset..local_offset + 4) != Some(b"PK\x03\x04")
        {
            return Err(core_update_identity_error());
        }
        let local_name_len = zip_u16(archive, local_offset + 26)? as usize;
        let local_extra_len = zip_u16(archive, local_offset + 28)? as usize;
        let data_start = local_offset
            .checked_add(30)
            .and_then(|value| value.checked_add(local_name_len))
            .and_then(|value| value.checked_add(local_extra_len))
            .ok_or_else(core_update_identity_error)?;
        let data_end = data_start
            .checked_add(compressed_size)
            .ok_or_else(core_update_identity_error)?;
        let compressed = archive
            .get(data_start..data_end)
            .ok_or_else(core_update_identity_error)?;
        let executable = match method {
            0 => compressed.to_vec(),
            8 => {
                let mut output = Vec::with_capacity(uncompressed_size);
                DeflateDecoder::new(Cursor::new(compressed))
                    .take(MAX_CORE_EXECUTABLE_BYTES as u64 + 1)
                    .read_to_end(&mut output)
                    .map_err(|_| core_update_identity_error())?;
                output
            }
            _ => return Err(core_update_identity_error()),
        };
        if executable.len() != uncompressed_size || executable.get(..2) != Some(b"MZ") {
            return Err(core_update_identity_error());
        }
        return Ok(executable);
    }
    Err(core_update_identity_error())
}

fn zip_u16(bytes: &[u8], offset: usize) -> Result<u16, DiagnosticError> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(core_update_identity_error)?;
    Ok(u16::from_le_bytes(value))
}

fn zip_u32(bytes: &[u8], offset: usize) -> Result<u32, DiagnosticError> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(core_update_identity_error)?;
    Ok(u32::from_le_bytes(value))
}

fn stage_core_package(
    release: &CoreRelease,
    executable: &[u8],
) -> Result<PathBuf, DiagnosticError> {
    let source_exe = std::env::current_exe().map_err(|_| core_update_failed())?;
    let source = source_exe.parent().ok_or_else(core_update_failed)?;
    let stage = std::env::temp_dir().join(format!("TunBridge-core-update-{}", std::process::id()));
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|_| core_update_failed())?;
    }
    fs::create_dir(&stage).map_err(|_| core_update_failed())?;

    for filename in [
        "tunbridge-desktop.exe",
        "tunbridge-setup.exe",
        "tunbridge-service.exe",
        "tunbridge.exe",
    ] {
        fs::copy(source.join(filename), stage.join(filename))
            .map_err(|_| core_update_unavailable())?;
    }
    fs::write(stage.join("mihomo.exe"), executable).map_err(|_| core_update_failed())?;

    let engine_sha256 = sha256_bytes(executable);
    let engine_lock = serde_json::json!({
        "schema_version": 1,
        "product_version": env!("CARGO_PKG_VERSION"),
        "engine": {
            "filename": "mihomo.exe",
            "version": release.version,
            "asset": release.asset_name,
            "size": executable.len(),
            "sha256": engine_sha256,
        }
    });
    write_json(&stage.join("engines.lock.json"), &engine_lock)?;

    let mut files = Vec::new();
    for filename in [
        "tunbridge-desktop.exe",
        "tunbridge-setup.exe",
        "tunbridge-service.exe",
        "tunbridge.exe",
        "mihomo.exe",
        "engines.lock.json",
    ] {
        let path = stage.join(filename);
        let bytes = fs::read(&path).map_err(|_| core_update_failed())?;
        files.push(serde_json::json!({
            "filename": filename,
            "size": bytes.len(),
            "sha256": sha256_bytes(&bytes),
        }));
    }
    let package = serde_json::json!({
        "schema_version": 1,
        "product_version": env!("CARGO_PKG_VERSION"),
        "service_feature": "production-mihomo-logs-v4",
        "service_protocol_version": 4,
        "service_capabilities": [
            "status",
            "start",
            "stop",
            "recover",
            "lease",
            "observe_local_traffic",
            "close_owned_connections",
            "remote_upstream",
            "observe_mihomo_logs"
        ],
        "files": files,
    });
    write_json(&stage.join("product-package.json"), &package)?;
    Ok(stage)
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), DiagnosticError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| core_update_failed())?;
    fs::write(path, bytes).map_err(|_| core_update_failed())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn installed_core_version() -> Option<String> {
    let program_files = std::env::var_os("ProgramFiles")?;
    let path = PathBuf::from(program_files)
        .join("TunBridge")
        .join("engines.lock.json");
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 32 * 1024 {
        return None;
    }
    let root: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    bounded_string(root.get("engine")?.get("version"), 64)
}

fn bundled_core_version() -> String {
    serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../../../../../engines.lock.json"
    ))
    .ok()
    .and_then(|root| bounded_string(root.get("engine")?.get("version"), 64))
    .unwrap_or_else(|| "unknown".to_string())
}

fn current_core_version() -> String {
    installed_core_version().unwrap_or_else(bundled_core_version)
}

fn normalize_version(value: &str) -> &str {
    value.trim().trim_start_matches('v')
}

fn corrected_windows_product_name(registry_name: &str, build_number: &str) -> String {
    let build = build_number.parse::<u32>().unwrap_or_default();
    if build >= 22_000 && registry_name.contains("Windows 10") {
        registry_name.replacen("Windows 10", "Windows 11", 1)
    } else {
        registry_name.to_string()
    }
}

fn auto_launch_enabled() -> bool {
    let key = wide(WINDOWS_RUN_KEY);
    let value = wide(AUTO_LAUNCH_VALUE);
    let mut bytes = 0_u32;
    unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            null_mut(),
            &mut bytes,
        ) == ERROR_SUCCESS
    }
}

fn bounded_string(value: Option<&serde_json::Value>, max_len: usize) -> Option<String> {
    let value = value?.as_str()?;
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn registry_string(value_name: &str) -> Result<String, DiagnosticError> {
    let subkey = wide(WINDOWS_VERSION_KEY);
    let value_name = wide(value_name);
    let mut buffer = [0_u16; 256];
    let mut bytes = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    // SAFETY: the destination is a fixed writable buffer and byte size is exact.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(system_info_error());
    }
    let units = (bytes as usize / 2).min(buffer.len());
    let end = buffer[..units]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units);
    let value = String::from_utf16(&buffer[..end]).map_err(|_| system_info_error())?;
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(system_info_error());
    }
    Ok(value)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn network_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::NetworkUnavailable,
        safe_message: "The network test could not reach its fixed HTTPS target.",
        retryable: true,
    }
}

fn provider_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::ProviderUnavailable,
        safe_message: "The IP information provider is temporarily unavailable.",
        retryable: true,
    }
}

fn invalid_response() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::InvalidResponse,
        safe_message: "The remote information provider returned an invalid response.",
        retryable: true,
    }
}

fn system_info_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::SystemInfoUnavailable,
        safe_message: "Windows system information is unavailable.",
        retryable: false,
    }
}

fn core_update_unavailable() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::CoreUpdateUnavailable,
        safe_message: "The official Mihomo update package is unavailable.",
        retryable: true,
    }
}

fn core_update_identity_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::CoreUpdateIdentityFailed,
        safe_message:
            "The Mihomo update package failed integrity or archive identity verification.",
        retryable: false,
    }
}

pub fn core_update_failed() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::CoreUpdateFailed,
        safe_message: "The Mihomo core update could not be completed safely.",
        retryable: true,
    }
}

pub fn worker_error() -> DiagnosticError {
    DiagnosticError {
        code: DiagnosticErrorCode::NetworkUnavailable,
        safe_message: "The bounded diagnostics worker could not complete.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn website_target_wire_values_match_the_frontend_ids() {
        for (wire, target) in [
            ("apple", WebsiteTarget::Apple),
            ("github", WebsiteTarget::GitHub),
            ("google", WebsiteTarget::Google),
            ("youtube", WebsiteTarget::YouTube),
            ("chatgpt", WebsiteTarget::ChatGpt),
            ("claude", WebsiteTarget::Claude),
            ("gemini", WebsiteTarget::Gemini),
            ("netflix", WebsiteTarget::Netflix),
            ("spotify", WebsiteTarget::Spotify),
            ("tiktok", WebsiteTarget::TikTok),
        ] {
            assert_eq!(
                serde_json::from_str::<WebsiteTarget>(&format!("\"{wire}\"")).unwrap(),
                target
            );
        }
        assert!(serde_json::from_str::<WebsiteTarget>("\"git_hub\"").is_err());
        assert!(serde_json::from_str::<WebsiteTarget>("\"you_tube\"").is_err());
    }

    #[test]
    fn parses_bounded_ipinfo_shape() {
        let current = br#"{
          "ip": "203.0.113.5",
          "country": "EX",
          "region": "Region",
          "city": "City",
          "timezone": "Etc/UTC",
          "loc": "1.0,2.0",
          "org": "AS64500 Example Org"
        }"#;
        let parsed = parse_ip_information(current).unwrap();
        assert_eq!(parsed.asn, 64500);
        assert_eq!(parsed.organization, "AS64500 Example Org");
        assert_eq!(parsed.provider, "ipinfo.io");
    }

    #[test]
    fn rejects_invalid_ip_and_unbounded_provider_text() {
        let invalid = format!(
            r#"{{"ip":"not-an-ip","country":"{}","timezone":"Etc/UTC","org":"AS1"}}}}"#,
            "x".repeat(200)
        );
        assert!(parse_ip_information(invalid.as_bytes()).is_none());
    }

    #[test]
    fn reads_bounded_real_windows_version_information() {
        let information = get_system_information().unwrap();
        assert!(!information.os_name.is_empty());
        assert!(!information.display_version.is_empty());
        assert!(!information.build_number.is_empty());
    }

    #[test]
    fn corrects_windows_11_registry_compatibility_name() {
        assert_eq!(
            corrected_windows_product_name("Windows 10 Pro", "26200"),
            "Windows 11 Pro"
        );
        assert_eq!(
            corrected_windows_product_name("Windows 10 Pro", "19045"),
            "Windows 10 Pro"
        );
        assert_eq!(
            corrected_windows_product_name("Windows 11 Enterprise", "26200"),
            "Windows 11 Enterprise"
        );
    }

    #[test]
    fn accepts_only_fixed_official_mihomo_download_urls() {
        assert!(validate_github_download_url(
            "https://github.com/MetaCubeX/mihomo/releases/download/v1.2.3/mihomo.zip"
        )
        .is_ok());
        assert!(validate_github_download_url("https://example.com/mihomo.zip").is_err());
        assert!(validate_github_download_url(
            "https://github.com/MetaCubeX/mihomo/releases/download/../asset"
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires live access to the fixed HTTPS website targets and ipinfo.io"]
    fn real_fixed_https_diagnostics_return_bounded_results() {
        for target in [
            WebsiteTarget::Apple,
            WebsiteTarget::GitHub,
            WebsiteTarget::Google,
            WebsiteTarget::YouTube,
        ] {
            let result = test_website(WebsiteTestInput { target }).unwrap();
            assert!(result.reachable);
            assert!(result.http_status >= 200);
        }
        let information = get_ip_information().unwrap();
        assert!(IpAddr::from_str(&information.ip).is_ok());
    }

    #[test]
    #[ignore = "requires downloading the current fixed official Mihomo release asset"]
    fn real_official_mihomo_asset_matches_release_digest_and_extracts() {
        let release = load_core_release().unwrap();
        let archive = https_get_url(&release.download_url, MAX_CORE_ARCHIVE_BYTES).unwrap();
        assert!((200..300).contains(&archive.status));
        assert_eq!(
            sha256_bytes(&archive.body),
            release.archive_sha256,
            "status={}, bytes={}, magic={:02x?}",
            archive.status,
            archive.body.len(),
            archive.body.get(..4).unwrap_or_default(),
        );
        let executable = extract_mihomo(&archive.body).unwrap();
        assert_eq!(executable.get(..2), Some(b"MZ".as_slice()));
    }
}
