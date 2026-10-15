//! Internal Monterey installer used only by the `macos-development-installer`
//! feature. It exercises the real SMJobBless/XPC/bootstrap boundary in the
//! VirtualBuddy VM while leaving the default/release product path fail-closed.

use sha2::{Digest, Sha256};
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    thread,
    time::{Duration, Instant},
};
#[cfg(feature = "macos-development-installer")]
use std::{fs::OpenOptions, io::Write};
#[cfg(not(feature = "macos-development-installer"))]
use tunbridge_desktop_contract::adapter::Diagnostics;
#[cfg(not(feature = "macos-development-installer"))]
use tunbridge_platform_macos::MacosDiagnostics;
use tunbridge_service::protocol::Command;
use tunbridge_service_macos::client_session::MacosServiceClient;
use tunbridge_setup_macos::{
    bundle_inspection::APP_EXECUTABLE_PATH, engine_asset::BUNDLE_ENGINE_MANIFEST_PATH,
    installer_for_major_version, InstallerKind,
};

const APP_IDENTIFIER: &str = "com.tunbridge.desktop";
const HELPER_IDENTIFIER: &str = "com.tunbridge.desktop.helper";
const HELPER_POLICY_FILE: &str = "Contents/Resources/tunbridge-helper-policy.json";
const HELPER_EXECUTABLE: &str = "Contents/Library/LaunchServices/com.tunbridge.desktop.helper";
const MAX_MANIFEST_BYTES: u64 = 4096;
const MAX_ENGINE_BYTES: u64 = 128 * 1024 * 1024;
const SERVICE_WAIT: Duration = Duration::from_secs(40);
const MODERN_UNREGISTER_WAIT: Duration = Duration::from_secs(10);

#[cfg(feature = "macos-development-installer")]
fn installer_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tunbridge-installer-m6f.log")
    {
        let _ = writeln!(file, "{message}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosInstallerError {
    BundleUnavailable,
    BundleIdentity,
    HelperIdentity,
    AuthorizationCancelled,
    AuthorizationFailed,
    Timeout,
    ServiceUnavailable,
    ServiceRejected,
    BootstrapFailed,
    UninstallFailed,
}

pub fn install_or_upgrade() -> Result<(), MacosInstallerError> {
    installer_debug_log("install-start");
    let bundle = Bundle::current()?;
    installer_debug_log("bundle-loaded");
    bundle.verify_layout()?;
    installer_debug_log("bundle-layout-ok");
    let app_cdhash = code_hash(&bundle.executable)?;
    let helper_cdhash = code_hash(&bundle.helper)?;
    installer_debug_log(&format!(
        "bundle-hashes app={} helper={}",
        app_cdhash, helper_cdhash
    ));
    bundle.verify_helper_policy(&helper_cdhash)?;
    installer_debug_log("helper-policy-ok");
    match current_registration_kind()? {
        InstallerKind::SmJobBless => {
            installer_debug_log("smjobbless-start");
            bless_privileged_helper()?;
            installer_debug_log("smjobbless-ok");
        }
        InstallerKind::SmAppService => {
            installer_debug_log("smappservice-replace-start");
            replace_modern_daemon()?;
            installer_debug_log("smappservice-replace-ok");
        }
    }

    let manifest = read_bounded(&bundle.manifest, MAX_MANIFEST_BYTES)?;
    let engine_size = fs::metadata(&bundle.engine)
        .map_err(|_| MacosInstallerError::BundleUnavailable)?
        .len();
    if engine_size == 0 || engine_size > MAX_ENGINE_BYTES {
        return Err(MacosInstallerError::BundleUnavailable);
    }
    let engine_sha256 = sha256_file(&bundle.engine)?;
    let policy_json = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "teamId": "adhoc",
        "appSigningIdentifier": APP_IDENTIFIER,
        "allowedCdhashes": [app_cdhash.clone()]
    }))
    .map_err(|_| MacosInstallerError::BootstrapFailed)?;
    let transaction_id = random_hex(16)?;
    let target_triple = target_triple();
    let command = Command::ProvisionGeneration {
        transaction_id,
        caller_cdhash: app_cdhash,
        policy_json,
        engine_manifest_sha256: sha256_bytes(&manifest),
        engine_sha256,
        engine_size,
        target_triple,
    };

    let deadline = Instant::now() + SERVICE_WAIT;
    loop {
        match MacosServiceClient::connect_system() {
            Ok(mut client) => match client.send(command.clone(), Duration::from_secs(10)) {
                Ok(_) => {
                    installer_debug_log("provision-ok");
                    return Ok(());
                }
                Err(tunbridge_service_macos::client_session::MacosClientError::Service {
                    ..
                }) => {
                    installer_debug_log("provision-service-rejected");
                    return Err(MacosInstallerError::ServiceRejected);
                }
                Err(tunbridge_service_macos::client_session::MacosClientError::Adapter(_))
                    if Instant::now() < deadline =>
                {
                    installer_debug_log("provision-adapter-retry");
                }
                Err(error) => {
                    installer_debug_log(&format!("provision-error={error:?}"));
                    return Err(MacosInstallerError::ServiceUnavailable);
                }
            },
            Err(error) if Instant::now() < deadline => {
                installer_debug_log(&format!("connect-error={error:?}"));
            }
            Err(error) => {
                installer_debug_log(&format!("connect-timeout-error={error:?}"));
                return Err(MacosInstallerError::Timeout);
            }
        }
        thread::sleep(Duration::from_millis(250));
    }
}

pub fn uninstall() -> Result<(), MacosInstallerError> {
    // The first internal milestone only exposes install/upgrade. Keep the
    // destructive removal path fail-closed until the root-side generation
    // removal transaction is wired and tested with exact residue checks.
    Err(MacosInstallerError::UninstallFailed)
}

struct Bundle {
    root: PathBuf,
    executable: PathBuf,
    helper: PathBuf,
    engine: PathBuf,
    manifest: PathBuf,
}

impl Bundle {
    fn current() -> Result<Self, MacosInstallerError> {
        let executable =
            std::env::current_exe().map_err(|_| MacosInstallerError::BundleUnavailable)?;
        let root = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or(MacosInstallerError::BundleUnavailable)?
            .to_owned();
        Ok(Self {
            executable,
            helper: root.join(HELPER_EXECUTABLE),
            engine: root.join("Contents/Resources/tunbridge-engine/mihomo"),
            manifest: root.join(BUNDLE_ENGINE_MANIFEST_PATH),
            root,
        })
    }

    fn verify_layout(&self) -> Result<(), MacosInstallerError> {
        if self.root.extension().and_then(|value| value.to_str()) != Some("app")
            || self
                .executable
                .strip_prefix(&self.root)
                .ok()
                .and_then(|path| path.to_str())
                != Some(APP_EXECUTABLE_PATH)
            || !regular_owned(&self.executable, unsafe { libc::geteuid() })
            || !regular_owned(&self.helper, unsafe { libc::geteuid() })
            || !regular_owned(&self.engine, unsafe { libc::geteuid() })
            || !regular_owned(&self.manifest, unsafe { libc::geteuid() })
        {
            return Err(MacosInstallerError::BundleIdentity);
        }
        Ok(())
    }

    fn verify_helper_policy(&self, helper_cdhash: &str) -> Result<(), MacosInstallerError> {
        let bytes = read_bounded(&self.root.join(HELPER_POLICY_FILE), 4096)?;
        let policy: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| MacosInstallerError::HelperIdentity)?;
        if policy.get("schemaVersion") != Some(&serde_json::json!(1))
            || policy.get("helperSigningIdentifier") != Some(&serde_json::json!(HELPER_IDENTIFIER))
            || policy.get("teamId") != Some(&serde_json::json!("adhoc"))
            || policy.get("allowedCdhashes") != Some(&serde_json::json!([helper_cdhash]))
        {
            return Err(MacosInstallerError::HelperIdentity);
        }
        Ok(())
    }
}

fn regular_owned(path: &Path, uid: u32) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| {
            let gid = unsafe { libc::getegid() };
            let trusted_owner = trusted_bundle_owner(metadata.uid(), metadata.gid(), uid, gid);
            metadata.file_type().is_file()
                && trusted_owner
                && metadata.nlink() == 1
                && metadata.mode() & 0o022 == 0
        })
        .unwrap_or(false)
}

const fn trusted_bundle_owner(owner_uid: u32, owner_gid: u32, uid: u32, gid: u32) -> bool {
    (owner_uid == uid && owner_gid == gid) || (owner_uid == 0 && owner_gid == 0)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, MacosInstallerError> {
    let mut file = File::open(path).map_err(|_| MacosInstallerError::BundleUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| MacosInstallerError::BundleUnavailable)?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(MacosInstallerError::BundleUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| MacosInstallerError::BundleUnavailable)?;
    Ok(bytes)
}

fn sha256_file(path: &Path) -> Result<String, MacosInstallerError> {
    let mut file = File::open(path).map_err(|_| MacosInstallerError::BundleUnavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| MacosInstallerError::BundleUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn code_hash(path: &Path) -> Result<String, MacosInstallerError> {
    let output = ProcessCommand::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|_| MacosInstallerError::BundleIdentity)?;
    if !output.status.success() {
        return Err(MacosInstallerError::BundleIdentity);
    }
    let text = String::from_utf8_lossy(&output.stderr);
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("CDHash="))
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MacosInstallerError::BundleIdentity);
    }
    Ok(value)
}

fn random_hex(bytes: usize) -> Result<String, MacosInstallerError> {
    let mut value = vec![0_u8; bytes];
    if unsafe { libc::getentropy(value.as_mut_ptr().cast(), value.len()) } != 0 {
        return Err(MacosInstallerError::BootstrapFailed);
    }
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn target_triple() -> String {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64-apple-darwin".into(),
        _ => "x86_64-apple-darwin".into(),
    }
}

fn current_registration_kind() -> Result<InstallerKind, MacosInstallerError> {
    #[cfg(feature = "macos-development-installer")]
    {
        // SMAppService requires a production signing identity on macOS 13+.
        // Internal candidates are deliberately ad-hoc signed, so exercise the
        // separately embedded SMJobBless metadata instead. Release builds
        // retain the modern ServiceManagement path below.
        Ok(InstallerKind::SmJobBless)
    }
    #[cfg(not(feature = "macos-development-installer"))]
    {
        let information = MacosDiagnostics
            .system_information()
            .map_err(|_| MacosInstallerError::BundleUnavailable)?;
        registration_kind_for_release(&information.os_release)
    }
}

#[cfg_attr(feature = "macos-development-installer", allow(dead_code))]
fn registration_kind_for_release(release: &str) -> Result<InstallerKind, MacosInstallerError> {
    let major = release
        .split('.')
        .next()
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(MacosInstallerError::BundleUnavailable)?;
    installer_for_major_version(major).ok_or(MacosInstallerError::BundleUnavailable)
}

const fn modern_service_is_registered(status: isize) -> bool {
    status != 0
}

/// Registers the embedded `Contents/Library/LaunchDaemons` component through
/// the macOS 13+ ServiceManagement API.  The dynamic Objective-C boundary
/// keeps the macOS 12 deployment target valid: this function is only reached
/// after the version gate selected `SmAppService`.
fn replace_modern_daemon() -> Result<(), MacosInstallerError> {
    const DAEMON_PLIST: &[u8] = b"com.tunbridge.desktop.helper.plist\0";
    const SM_APP_SERVICE: &[u8] = b"SMAppService\0";
    const NS_STRING: &[u8] = b"NSString\0";
    const DAEMON_SERVICE: &[u8] = b"daemonServiceWithPlistName:\0";
    const STRING_WITH_UTF8: &[u8] = b"stringWithUTF8String:\0";
    const REGISTER: &[u8] = b"registerAndReturnError:\0";
    const UNREGISTER: &[u8] = b"unregisterAndReturnError:\0";
    const STATUS: &[u8] = b"status\0";

    unsafe {
        let service_class = objc_get_class(SM_APP_SERVICE.as_ptr().cast());
        let string_class = objc_get_class(NS_STRING.as_ptr().cast());
        if service_class.is_null() || string_class.is_null() {
            return Err(MacosInstallerError::BootstrapFailed);
        }
        let string_selector = objc_selector(STRING_WITH_UTF8.as_ptr().cast());
        let service_selector = objc_selector(DAEMON_SERVICE.as_ptr().cast());
        let register_selector = objc_selector(REGISTER.as_ptr().cast());
        let unregister_selector = objc_selector(UNREGISTER.as_ptr().cast());
        let status_selector = objc_selector(STATUS.as_ptr().cast());
        if string_selector.is_null()
            || service_selector.is_null()
            || register_selector.is_null()
            || unregister_selector.is_null()
            || status_selector.is_null()
        {
            return Err(MacosInstallerError::BootstrapFailed);
        }
        let make_string: unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *const c_char,
        ) -> *mut c_void = std::mem::transmute(objc_msg_send as *const ());
        let plist_name = make_string(string_class, string_selector, DAEMON_PLIST.as_ptr().cast());
        if plist_name.is_null() {
            return Err(MacosInstallerError::BootstrapFailed);
        }
        let daemon_service: unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            *mut c_void,
        ) -> *mut c_void = std::mem::transmute(objc_msg_send as *const ());
        let service = daemon_service(service_class, service_selector, plist_name);
        if service.is_null() {
            return Err(MacosInstallerError::BootstrapFailed);
        }
        let status: unsafe extern "C" fn(*mut c_void, *const c_void) -> isize =
            std::mem::transmute(objc_msg_send as *const ());
        if modern_service_is_registered(status(service, status_selector)) {
            let unregister: unsafe extern "C" fn(
                *mut c_void,
                *const c_void,
                *mut *mut c_void,
            ) -> c_char = std::mem::transmute(objc_msg_send as *const ());
            let mut error: *mut c_void = std::ptr::null_mut();
            if unregister(service, unregister_selector, &mut error) == 0 {
                log_service_management_error("smappservice-unregister-error", error);
                return Err(MacosInstallerError::AuthorizationFailed);
            }
            installer_debug_log("smappservice-unregister-ok");
            let deadline = Instant::now() + MODERN_UNREGISTER_WAIT;
            while modern_service_is_registered(status(service, status_selector)) {
                if Instant::now() >= deadline {
                    installer_debug_log("smappservice-unregister-timeout");
                    return Err(MacosInstallerError::ServiceUnavailable);
                }
                thread::sleep(Duration::from_millis(100));
            }
            installer_debug_log("smappservice-unregister-settled");
        }
        let register: unsafe extern "C" fn(*mut c_void, *const c_void, *mut *mut c_void) -> c_char =
            std::mem::transmute(objc_msg_send as *const ());
        let mut error: *mut c_void = std::ptr::null_mut();
        if register(service, register_selector, &mut error) == 0 {
            log_service_management_error("smappservice-register-error", error);
            return Err(MacosInstallerError::AuthorizationFailed);
        }
    }
    Ok(())
}

unsafe fn log_service_management_error(prefix: &str, error: *mut c_void) {
    const CODE: &[u8] = b"code\0";
    const LOCALIZED_DESCRIPTION: &[u8] = b"localizedDescription\0";
    const UTF8_STRING: &[u8] = b"UTF8String\0";

    if error.is_null() {
        installer_debug_log(&format!("{prefix}=unknown"));
        return;
    }
    let code_selector = objc_selector(CODE.as_ptr().cast());
    let description_selector = objc_selector(LOCALIZED_DESCRIPTION.as_ptr().cast());
    let utf8_selector = objc_selector(UTF8_STRING.as_ptr().cast());
    if code_selector.is_null() || description_selector.is_null() || utf8_selector.is_null() {
        installer_debug_log(&format!("{prefix}=unreadable"));
        return;
    }
    let code: unsafe extern "C" fn(*mut c_void, *const c_void) -> isize =
        std::mem::transmute(objc_msg_send as *const ());
    let description: unsafe extern "C" fn(*mut c_void, *const c_void) -> *mut c_void =
        std::mem::transmute(objc_msg_send as *const ());
    let utf8: unsafe extern "C" fn(*mut c_void, *const c_void) -> *const c_char =
        std::mem::transmute(objc_msg_send as *const ());
    let description = description(error, description_selector);
    let description = (!description.is_null())
        .then(|| utf8(description, utf8_selector))
        .filter(|value| !value.is_null())
        .map(|value| CStr::from_ptr(value).to_string_lossy().into_owned())
        .unwrap_or_else(|| "unavailable".into());
    installer_debug_log(&format!(
        "{prefix} code={} description={description}",
        code(error, code_selector)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_setup_macos::InstallerKind;

    #[test]
    fn registration_selection_keeps_monterey_on_bless_and_routes_modern_macos_to_smappservice() {
        assert_eq!(
            registration_kind_for_release("12.7.6").unwrap(),
            InstallerKind::SmJobBless
        );
        assert_eq!(
            registration_kind_for_release("26.5.2").unwrap(),
            InstallerKind::SmAppService
        );
    }

    #[test]
    fn only_registered_modern_service_states_require_unregister_before_registration() {
        assert!(!modern_service_is_registered(0));
        assert!(modern_service_is_registered(1));
        assert!(modern_service_is_registered(2));
        assert!(modern_service_is_registered(3));
    }

    #[cfg(feature = "macos-development-installer")]
    #[test]
    fn internal_adhoc_candidate_uses_the_legacy_registration_metadata() {
        assert_eq!(
            current_registration_kind().unwrap(),
            InstallerKind::SmJobBless
        );
    }

    #[test]
    fn bundle_assets_accept_only_the_current_user_or_root_wheel_owner() {
        assert!(trusted_bundle_owner(501, 20, 501, 20));
        assert!(trusted_bundle_owner(0, 0, 501, 20));
        assert!(!trusted_bundle_owner(502, 20, 501, 20));
        assert!(!trusted_bundle_owner(0, 20, 501, 20));
        assert!(!trusted_bundle_owner(501, 0, 501, 20));
    }
}

#[link(name = "objc")]
unsafe extern "C" {
    #[link_name = "objc_getClass"]
    fn objc_get_class(name: *const c_char) -> *mut c_void;
    #[link_name = "sel_registerName"]
    fn objc_selector(name: *const c_char) -> *const c_void;
    #[link_name = "objc_msgSend"]
    fn objc_msg_send();
}

fn bless_privileged_helper() -> Result<(), MacosInstallerError> {
    let mut authorization: AuthorizationRef = std::ptr::null_mut();
    let status =
        unsafe { AuthorizationCreate(std::ptr::null(), std::ptr::null(), 0, &mut authorization) };
    installer_debug_log(&format!("authorization-create-status={status}"));
    if status != 0 || authorization.is_null() {
        return Err(MacosInstallerError::AuthorizationFailed);
    }
    let right_name = b"com.apple.ServiceManagement.blesshelper\0";
    let mut item = AuthorizationItem {
        name: right_name.as_ptr().cast(),
        value_length: 0,
        value: std::ptr::null_mut(),
        flags: 0,
    };
    let rights = AuthorizationRights {
        count: 1,
        items: &mut item,
    };
    let copy_status = unsafe {
        AuthorizationCopyRights(
            authorization,
            &rights,
            std::ptr::null(),
            // kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights.
            // Without InteractionAllowed Monterey returns
            // errAuthorizationInteractionNotAllowed instead of showing the
            // administrator approval prompt required by SMJobBless.
            (1 << 0) | (1 << 1),
            std::ptr::null_mut(),
        )
    };
    installer_debug_log(&format!("authorization-copy-rights-status={copy_status}"));
    if copy_status != 0 {
        unsafe { AuthorizationFree(authorization, 0) };
        return Err(if copy_status == -60006 {
            MacosInstallerError::AuthorizationCancelled
        } else {
            MacosInstallerError::AuthorizationFailed
        });
    }
    let domain = unsafe { kSMDomainSystemLaunchd };
    let label = cf_string(HELPER_IDENTIFIER)?;
    let mut error: *const c_void = std::ptr::null();
    let blessed = unsafe { SMJobBless(domain, label, authorization, &mut error) != 0 };
    installer_debug_log(&format!(
        "smjobbless-result={} error-present={}",
        blessed,
        !error.is_null()
    ));
    if !error.is_null() {
        installer_debug_log(&format!("smjobbless-error {}", describe_cf_error(error)));
        unsafe { CFRelease(error) };
    }
    unsafe {
        CFRelease(label);
        AuthorizationFree(authorization, 0);
    }
    if blessed {
        Ok(())
    } else {
        Err(MacosInstallerError::AuthorizationFailed)
    }
}

type AuthorizationRef = *mut c_void;
type CfStringRef = *const c_void;
type AuthorizationStatus = c_int;

#[repr(C)]
struct AuthorizationItem {
    name: *const c_char,
    value_length: usize,
    value: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct AuthorizationRights {
    count: u32,
    items: *mut AuthorizationItem,
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationRights,
        environment: *const c_void,
        flags: u32,
        authorization: *mut AuthorizationRef,
    ) -> AuthorizationStatus;
    fn AuthorizationCopyRights(
        authorization: AuthorizationRef,
        rights: *const AuthorizationRights,
        environment: *const c_void,
        flags: u32,
        authorized_rights: *mut *mut AuthorizationRights,
    ) -> AuthorizationStatus;
    fn AuthorizationFree(authorization: AuthorizationRef, flags: u32) -> AuthorizationStatus;
}

#[link(name = "ServiceManagement", kind = "framework")]
unsafe extern "C" {
    static kSMDomainSystemLaunchd: CfStringRef;
    fn SMJobBless(
        domain: CfStringRef,
        executable_label: CfStringRef,
        authorization: AuthorizationRef,
        error: *mut *const c_void,
    ) -> u8;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        string: *const c_char,
        encoding: u32,
    ) -> CfStringRef;
    fn CFRelease(value: *const c_void);
    fn CFErrorGetCode(error: *const c_void) -> isize;
    fn CFErrorGetDomain(error: *const c_void) -> CfStringRef;
    fn CFErrorCopyDescription(error: *const c_void) -> CfStringRef;
    fn CFStringGetCString(
        value: CfStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> u8;
}

/// Bounded "domain=<d> code=<n> description=<text>" for development logs.
fn describe_cf_error(error: *const c_void) -> String {
    let code = unsafe { CFErrorGetCode(error) };
    let domain = cf_string_text(unsafe { CFErrorGetDomain(error) });
    let description = unsafe { CFErrorCopyDescription(error) };
    let text = cf_string_text(description);
    if !description.is_null() {
        unsafe { CFRelease(description) };
    }
    format!("domain={domain} code={code} description={text}")
}

fn cf_string_text(value: CfStringRef) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut buffer = [0 as c_char; 512];
    // kCFStringEncodingUTF8; truncation fails and yields an empty string.
    let ok = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            0x0800_0100,
        )
    };
    if ok == 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .replace(['\n', '\r'], " ")
}

fn cf_string(value: &str) -> Result<CfStringRef, MacosInstallerError> {
    let value = CString::new(value).map_err(|_| MacosInstallerError::AuthorizationFailed)?;
    let result =
        unsafe { CFStringCreateWithCString(std::ptr::null(), value.as_ptr(), 0x0800_0100) };
    if result.is_null() {
        Err(MacosInstallerError::AuthorizationFailed)
    } else {
        Ok(result)
    }
}
