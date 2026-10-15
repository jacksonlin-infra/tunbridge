use std::{io, path::Path, path::PathBuf};

use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE},
    System::{
        ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        },
    },
};

const MAX_PROCESS_PATH_UTF16: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pid: u32,
    image_path: PathBuf,
    process_name: String,
    creation_time: u64,
}

impl ProcessIdentity {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn image_path(&self) -> &Path {
        &self.image_path
    }

    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }
}

pub fn query_process_identity(pid: u32) -> Result<ProcessIdentity, ProcessIdentityError> {
    if pid == 0 {
        return Err(ProcessIdentityError::InvalidPid);
    }
    // SAFETY: access is query-only and pid is nonzero.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(ProcessIdentityError::Windows(io::Error::last_os_error()));
    }
    let process = OwnedHandle(raw);
    query_process_identity_from_handle(pid, process.0)
}

pub(super) fn query_process_working_set(
    pid: u32,
    expected_creation_time: u64,
) -> Result<u64, ProcessIdentityError> {
    if pid == 0 {
        return Err(ProcessIdentityError::InvalidPid);
    }
    // SAFETY: the service opens only the recorded owned engine for read-only
    // identity and memory counters.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if raw.is_null() {
        return Err(ProcessIdentityError::Windows(io::Error::last_os_error()));
    }
    let process = OwnedHandle(raw);
    let identity = query_process_identity_from_handle(pid, process.0)?;
    if identity.creation_time() != expected_creation_time {
        return Err(ProcessIdentityError::IdentityChanged);
    }
    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    // SAFETY: counters is writable for its declared structure size and the
    // handle has query plus VM-read access to the verified owned process.
    if unsafe {
        K32GetProcessMemoryInfo(
            process.0,
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    } == 0
    {
        return Err(ProcessIdentityError::Windows(io::Error::last_os_error()));
    }
    Ok(counters.WorkingSetSize as u64)
}

pub(super) fn query_process_identity_from_handle(
    pid: u32,
    process: HANDLE,
) -> Result<ProcessIdentity, ProcessIdentityError> {
    let image_path = process_image_path(process)?;
    let process_name = image_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| valid_process_name(name))
        .ok_or(ProcessIdentityError::InvalidProcessName)?
        .to_string();
    let creation_time = process_creation_time(process)?;
    Ok(ProcessIdentity {
        pid,
        image_path,
        process_name,
        creation_time,
    })
}

pub(super) fn normalized_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_start_matches("\\\\?\\")
        .to_ascii_lowercase()
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, ProcessIdentityError> {
    let mut buffer = vec![0_u16; MAX_PROCESS_PATH_UTF16];
    let mut length = buffer.len() as u32;
    // SAFETY: process has query rights and buffer is writable for length WCHARs.
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(ProcessIdentityError::Windows(io::Error::last_os_error()));
    }
    if length == 0 || length as usize > buffer.len() {
        return Err(ProcessIdentityError::InvalidProcessPath);
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..length as usize],
    )))
}

fn process_creation_time(process: HANDLE) -> Result<u64, ProcessIdentityError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output structures are writable and process has query rights.
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(ProcessIdentityError::Windows(io::Error::last_os_error()));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn valid_process_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':' | ','))
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle ownership came from OpenProcess.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessIdentityError {
    #[error("process PID must be nonzero")]
    InvalidPid,
    #[error("Windows process identity query failed: {0}")]
    Windows(#[source] io::Error),
    #[error("process image path is invalid")]
    InvalidProcessPath,
    #[error("process image has an invalid file name")]
    InvalidProcessName,
    #[error("process identity changed before the memory sample")]
    IdentityChanged,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_current_process_path_and_creation_time() {
        let identity = query_process_identity(std::process::id()).unwrap();
        assert_eq!(identity.pid(), std::process::id());
        assert!(identity.image_path().is_absolute());
        assert!(!identity.process_name().is_empty());
        assert!(identity.creation_time() > 0);
        assert!(
            query_process_working_set(std::process::id(), identity.creation_time()).unwrap() > 0
        );
    }

    #[test]
    fn normalizes_windows_extended_paths_case_insensitively() {
        assert_eq!(
            normalized_path(Path::new(r"\\?\C:\Program Files\TunBridge\MIHOMO.EXE")),
            normalized_path(Path::new(r"c:\program files\tunbridge\mihomo.exe"))
        );
    }

    #[test]
    fn zero_pid_is_rejected_without_querying_windows() {
        assert!(matches!(
            query_process_identity(0),
            Err(ProcessIdentityError::InvalidPid)
        ));
    }
}
