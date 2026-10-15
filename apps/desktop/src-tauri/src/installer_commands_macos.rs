use serde::Serialize;

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
                "the verified TunBridge macOS installer is unavailable",
                false,
            ),
            InstallerCommandErrorCode::InstallerIdentityFailed => (
                "the TunBridge macOS bundle identity failed verification",
                false,
            ),
            InstallerCommandErrorCode::ElevationCancelled => {
                ("administrator approval was not granted", true)
            }
            InstallerCommandErrorCode::InstallerTimeout => (
                "the TunBridge macOS helper did not become available before the deadline",
                true,
            ),
            InstallerCommandErrorCode::InstallerFailed => {
                ("the TunBridge macOS installation did not complete", true)
            }
            InstallerCommandErrorCode::WorkerFailed => {
                ("the TunBridge macOS installer worker failed", true)
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
    crate::macos_dev_installer::install_or_upgrade().map_err(map_error)
}

pub fn uninstall_product() -> Result<(), InstallerCommandError> {
    crate::macos_dev_installer::uninstall().map_err(map_error)
}

fn map_error(error: crate::macos_dev_installer::MacosInstallerError) -> InstallerCommandError {
    use crate::macos_dev_installer::MacosInstallerError;
    let code = match error {
        MacosInstallerError::BundleUnavailable => InstallerCommandErrorCode::InstallerUnavailable,
        MacosInstallerError::BundleIdentity | MacosInstallerError::HelperIdentity => {
            InstallerCommandErrorCode::InstallerIdentityFailed
        }
        MacosInstallerError::AuthorizationCancelled => {
            InstallerCommandErrorCode::ElevationCancelled
        }
        MacosInstallerError::Timeout => InstallerCommandErrorCode::InstallerTimeout,
        MacosInstallerError::ServiceUnavailable => InstallerCommandErrorCode::InstallerTimeout,
        MacosInstallerError::ServiceRejected
        | MacosInstallerError::BootstrapFailed
        | MacosInstallerError::AuthorizationFailed
        | MacosInstallerError::UninstallFailed => InstallerCommandErrorCode::InstallerFailed,
    };
    InstallerCommandError::from(code)
}
