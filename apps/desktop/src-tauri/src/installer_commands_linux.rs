use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;

const PKEXEC: &str = "/usr/bin/pkexec";
const MAINTENANCE: &str = "/usr/libexec/tunbridge/tunbridge-maintenance-linux";

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

#[derive(Debug, Clone, Serialize)]
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
            InstallerCommandErrorCode::InstallerUnavailable => (
                "the verified TunBridge maintenance helper is unavailable",
                false,
            ),
            InstallerCommandErrorCode::InstallerIdentityFailed => (
                "the TunBridge maintenance helper failed identity verification",
                false,
            ),
            InstallerCommandErrorCode::ElevationCancelled => {
                ("administrator approval was not granted", true)
            }
            InstallerCommandErrorCode::InstallerTimeout => (
                "the TunBridge maintenance operation exceeded its fixed deadline",
                true,
            ),
            InstallerCommandErrorCode::InstallerFailed => {
                ("the TunBridge maintenance operation did not complete", true)
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
    run("repair")
}
pub fn uninstall_product() -> Result<(), InstallerCommandError> {
    crate::diagnostics_commands::set_auto_launch(false).map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerIdentityFailed)
    })?;
    run("uninstall")
}

fn run(verb: &'static str) -> Result<(), InstallerCommandError> {
    validate_root_executable(Path::new(PKEXEC))?;
    validate_root_executable(Path::new(MAINTENANCE))?;
    let mut child = Command::new(PKEXEC)
        .args([MAINTENANCE, verb])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| InstallerCommandError::from(InstallerCommandErrorCode::ElevationCancelled))?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => {
                return Err(InstallerCommandError::from(
                    InstallerCommandErrorCode::InstallerFailed,
                ))
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(InstallerCommandError::from(
                    InstallerCommandErrorCode::InstallerTimeout,
                ));
            }
            Err(_) => {
                return Err(InstallerCommandError::from(
                    InstallerCommandErrorCode::InstallerFailed,
                ))
            }
        }
    }
}

fn validate_root_executable(path: &Path) -> Result<(), InstallerCommandError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        InstallerCommandError::from(InstallerCommandErrorCode::InstallerUnavailable)
    })?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerIdentityFailed,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_are_redacted() {
        let json = serde_json::to_string(&InstallerCommandError::from(
            InstallerCommandErrorCode::InstallerFailed,
        ))
        .unwrap();
        assert!(!json.contains("/usr/"));
    }
}
