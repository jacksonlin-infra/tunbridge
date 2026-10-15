use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterErrorCode {
    NotReady,
    Unavailable,
    InvalidData,
    IdentityRejected,
    PermissionDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterError {
    pub code: AdapterErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
}

impl AdapterError {
    pub const fn not_ready() -> Self {
        Self {
            code: AdapterErrorCode::NotReady,
            safe_message: "This platform adapter is not ready.",
            retryable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerIdentity {
    pub address: String,
    pub port: u16,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<PathBuf>,
}

pub trait ProcessDiscovery: Send + Sync {
    fn loopback_listeners(&self) -> Result<Vec<ListenerIdentity>, AdapterError>;
}

pub trait CredentialStore: Send + Sync {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>, AdapterError>;
    fn write(&self, target: &str, secret: &[u8]) -> Result<(), AdapterError>;
    fn delete(&self, target: &str) -> Result<(), AdapterError>;
}

pub trait ProfileStoreFiles: Send + Sync {
    fn read_bounded(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, AdapterError>;
    fn replace_atomically(&self, path: &Path, contents: &[u8]) -> Result<(), AdapterError>;
    fn remove_exact(&self, path: &Path) -> Result<(), AdapterError>;
}

pub trait ServiceTransport: Send {
    fn transact(
        &mut self,
        request_frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, AdapterError>;
}

pub trait AutoLaunch: Send + Sync {
    fn enabled(&self) -> Result<bool, AdapterError>;
    fn set_enabled(&self, enabled: bool) -> Result<bool, AdapterError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInformation {
    pub os_name: String,
    pub os_release: String,
    pub build: String,
    pub architecture: String,
}

pub trait Diagnostics: Send + Sync {
    fn system_information(&self) -> Result<SystemInformation, AdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOperation {
    InstallOrUpgrade,
    Uninstall,
}

pub trait ProductInstaller: Send + Sync {
    fn run(&self, operation: InstallOperation) -> Result<(), AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_errors_expose_only_stable_safe_fields() {
        assert_eq!(
            serde_json::to_value(AdapterError::not_ready()).unwrap(),
            serde_json::json!({
                "code": "not_ready",
                "safeMessage": "This platform adapter is not ready.",
                "retryable": false
            })
        );
    }
}
