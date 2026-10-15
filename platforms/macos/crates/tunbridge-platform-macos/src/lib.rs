//! Monterey-compatible, unprivileged macOS operating-system adapter boundary.
//!
//! M1 intentionally exposes fail-closed adapters. Later milestones replace
//! these implementations without changing the shared Desktop command surface.

#[cfg(not(target_os = "macos"))]
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use tunbridge_desktop_contract::adapter::{
    AdapterError, AutoLaunch, CredentialStore, Diagnostics, ListenerIdentity, ProcessDiscovery,
    ProfileStoreFiles, SystemInformation,
};
use tunbridge_desktop_contract::PlatformError;

#[cfg(target_os = "macos")]
mod auto_launch;
#[cfg(target_os = "macos")]
mod diagnostics;
#[cfg(target_os = "macos")]
mod keychain;
#[cfg(target_os = "macos")]
mod paths;
#[cfg(target_os = "macos")]
mod process_discovery;
#[cfg(target_os = "macos")]
mod profile_files;

#[cfg(target_os = "macos")]
pub use auto_launch::MacosAutoLaunch;
#[cfg(target_os = "macos")]
pub use diagnostics::MacosDiagnostics;
#[cfg(target_os = "macos")]
pub use keychain::MacosKeychain;
#[cfg(target_os = "macos")]
pub use paths::{MacosUserPaths, PathError};
#[cfg(target_os = "macos")]
pub use process_discovery::MacosProcessDiscovery;
#[cfg(target_os = "macos")]
pub use profile_files::{MacosProfileStoreFiles, MacosProfileStoreLock};

pub const PLATFORM_ID: &str = "macos";
pub const MINIMUM_DEPLOYMENT_TARGET: &str = "12.0";
pub const MINIMUM_VALIDATED_VERSION: &str = "12.7.6";

pub const SCAFFOLDED_CAPABILITIES: [&str; 7] = [
    "process_discovery",
    "profile_files",
    "keychain",
    "system_information",
    "auto_launch",
    "service_transport",
    "product_installer",
];

pub const fn not_ready(capability: &'static str) -> PlatformError {
    PlatformError::not_ready(PLATFORM_ID, capability)
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosProcessDiscovery;

#[cfg(not(target_os = "macos"))]
impl ProcessDiscovery for MacosProcessDiscovery {
    fn loopback_listeners(&self) -> Result<Vec<ListenerIdentity>, AdapterError> {
        Err(AdapterError::not_ready())
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosKeychain;

#[cfg(not(target_os = "macos"))]
impl CredentialStore for MacosKeychain {
    fn read(&self, _target: &str) -> Result<Option<Vec<u8>>, AdapterError> {
        Err(AdapterError::not_ready())
    }

    fn write(&self, _target: &str, _secret: &[u8]) -> Result<(), AdapterError> {
        Err(AdapterError::not_ready())
    }

    fn delete(&self, _target: &str) -> Result<(), AdapterError> {
        Err(AdapterError::not_ready())
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosProfileStoreFiles;

#[cfg(not(target_os = "macos"))]
impl ProfileStoreFiles for MacosProfileStoreFiles {
    fn read_bounded(
        &self,
        _path: &Path,
        _maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, AdapterError> {
        Err(AdapterError::not_ready())
    }

    fn replace_atomically(&self, _path: &Path, _contents: &[u8]) -> Result<(), AdapterError> {
        Err(AdapterError::not_ready())
    }

    fn remove_exact(&self, _path: &Path) -> Result<(), AdapterError> {
        Err(AdapterError::not_ready())
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosAutoLaunch;

#[cfg(not(target_os = "macos"))]
impl AutoLaunch for MacosAutoLaunch {
    fn enabled(&self) -> Result<bool, AdapterError> {
        Err(AdapterError::not_ready())
    }

    fn set_enabled(&self, _enabled: bool) -> Result<bool, AdapterError> {
        Err(AdapterError::not_ready())
    }
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosDiagnostics;

#[cfg(not(target_os = "macos"))]
impl Diagnostics for MacosDiagnostics {
    fn system_information(&self) -> Result<SystemInformation, AdapterError> {
        Err(AdapterError::not_ready())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "macos"))]
    use tunbridge_desktop_contract::adapter::AdapterErrorCode;

    #[test]
    fn deployment_and_validation_floor_are_frozen() {
        assert_eq!(PLATFORM_ID, "macos");
        assert_eq!(MINIMUM_DEPLOYMENT_TARGET, "12.0");
        assert_eq!(MINIMUM_VALIDATED_VERSION, "12.7.6");
        assert_eq!(SCAFFOLDED_CAPABILITIES.len(), 7);
    }

    #[test]
    fn desktop_error_uses_explicit_macos_identity() {
        let error = not_ready("service_lifecycle");
        assert_eq!(error.platform, "macos");
        assert_eq!(error.capability, "service_lifecycle");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn m1_adapters_fail_closed_without_side_effects() {
        assert_eq!(
            MacosProcessDiscovery.loopback_listeners().unwrap_err().code,
            AdapterErrorCode::NotReady
        );
        assert_eq!(
            MacosKeychain.read("fixture").unwrap_err().code,
            AdapterErrorCode::NotReady
        );
        assert_eq!(
            MacosAutoLaunch.enabled().unwrap_err().code,
            AdapterErrorCode::NotReady
        );
        assert_eq!(
            MacosDiagnostics.system_information().unwrap_err().code,
            AdapterErrorCode::NotReady
        );
    }
}
