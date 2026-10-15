use std::{io, mem::size_of, os::windows::ffi::OsStrExt as _, path::Path, ptr};

use serde::Serialize;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
    System::Threading::{GetExitCodeProcess, WaitForSingleObject},
    UI::{
        Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
        WindowsAndMessaging::{GetForegroundWindow, SW_SHOWNORMAL},
    },
};

const SETUP_FILENAME: &str = "tunbridge-setup.exe";
const SETUP_TIMEOUT_MS: u32 = 180_000;
const EXPECTED_SETUP_SHA256: Option<&str> = option_env!("TUNBRIDGE_SETUP_SHA256");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerCommandErrorCode {
    Busy,
    InstallerUnavailable,
    InstallerIdentityFailed,
    ElevationCancelled,
    InstallerTimeout,
    InstallerFailed,
    WorkerFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallerCommandError {
    code: InstallerCommandErrorCode,
    message: &'static str,
    retryable: bool,
}

impl InstallerCommandError {
    pub fn from(code: InstallerCommandErrorCode) -> Self {
        let (message, retryable) = match code {
            InstallerCommandErrorCode::Busy => ("another TunBridge operation is active", true),
            InstallerCommandErrorCode::InstallerUnavailable => {
                ("the verified TunBridge installer is unavailable", false)
            }
            InstallerCommandErrorCode::InstallerIdentityFailed => (
                "the TunBridge installer failed identity verification",
                false,
            ),
            InstallerCommandErrorCode::ElevationCancelled => {
                ("administrator approval was not granted", true)
            }
            InstallerCommandErrorCode::InstallerTimeout => {
                ("the TunBridge installer exceeded its fixed deadline", true)
            }
            InstallerCommandErrorCode::InstallerFailed => {
                ("the TunBridge installer did not complete", true)
            }
            InstallerCommandErrorCode::WorkerFailed => {
                ("the TunBridge installer worker failed", true)
            }
        };
        Self {
            code,
            message,
            retryable,
        }
    }
}

pub fn install_product() -> Result<(), InstallerCommandError> {
    run_setup("install")
}

pub fn uninstall_product() -> Result<(), InstallerCommandError> {
    run_setup("uninstall")
}

fn run_setup(verb: &'static str) -> Result<(), InstallerCommandError> {
    let current = std::env::current_exe().map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
    })?;
    let root = current.parent().ok_or_else(|| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
    })?;
    run_setup_from(root, verb)
}

pub fn update_core_from(root: &Path) -> Result<(), InstallerCommandError> {
    run_setup_from(root, "update-core")
}

fn run_setup_from(root: &Path, verb: &'static str) -> Result<(), InstallerCommandError> {
    let expected = EXPECTED_SETUP_SHA256
        .filter(|value| is_lower_hex_256(value))
        .ok_or_else(|| {
            InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
        })?;
    reject_reparse(root)?;
    let canonical_root = root.canonicalize().map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerIdentityFailed)
    })?;
    let setup = root.join(SETUP_FILENAME);
    reject_reparse(&setup)?;
    let canonical_setup = setup.canonicalize().map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
    })?;
    let actual_hash = sha256_file(&canonical_setup).map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerIdentityFailed)
    })?;
    if canonical_setup.parent() != Some(canonical_root.as_path())
        || !canonical_setup.is_file()
        || actual_hash != expected
    {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerIdentityFailed,
        ));
    }

    let runas = wide("runas");
    let file = wide_path(&canonical_setup);
    let parameters = wide(verb);
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        // Anchor the elevation request to the foreground TunBridge window so
        // Windows presents UAC on the user's interactive desktop instead of
        // treating an unowned hidden launch as cancelled.
        hwnd: unsafe { GetForegroundWindow() },
        lpVerb: runas.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: ptr::null(),
        nShow: SW_SHOWNORMAL,
        hInstApp: ptr::null_mut(),
        lpIDList: ptr::null_mut(),
        lpClass: ptr::null(),
        hkeyClass: ptr::null_mut(),
        dwHotKey: 0,
        Anonymous: Default::default(),
        hProcess: ptr::null_mut(),
    };
    if unsafe { ShellExecuteExW(&mut execute) } == 0 || execute.hProcess.is_null() {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::ElevationCancelled,
        ));
    }
    let process = OwnedHandle(execute.hProcess);
    if unsafe { WaitForSingleObject(process.0, SETUP_TIMEOUT_MS) } != WAIT_OBJECT_0 {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerTimeout,
        ));
    }
    let mut exit_code = 1_u32;
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 || exit_code != 0 {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerFailed,
        ));
    }
    Ok(())
}

fn reject_reparse(path: &Path) -> Result<(), InstallerCommandError> {
    let metadata = path.symlink_metadata().map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
    })?;
    use std::os::windows::fs::MetadataExt as _;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerIdentityFailed,
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, io::Error> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_hash_is_strict_when_present() {
        assert!(
            EXPECTED_SETUP_SHA256.is_none() || is_lower_hex_256(EXPECTED_SETUP_SHA256.unwrap())
        );
        assert!(!is_lower_hex_256(&"A".repeat(64)));
        assert!(!is_lower_hex_256("../setup"));
    }

    #[test]
    fn errors_are_fixed_and_redacted() {
        for code in [
            InstallerCommandErrorCode::Busy,
            InstallerCommandErrorCode::InstallerUnavailable,
            InstallerCommandErrorCode::InstallerIdentityFailed,
            InstallerCommandErrorCode::ElevationCancelled,
            InstallerCommandErrorCode::InstallerTimeout,
            InstallerCommandErrorCode::InstallerFailed,
            InstallerCommandErrorCode::WorkerFailed,
        ] {
            let json = serde_json::to_string(&InstallerCommandError::from(code)).unwrap();
            assert!(!json.contains("Program Files"));
            assert!(!json.contains(".exe"));
        }
    }
}
