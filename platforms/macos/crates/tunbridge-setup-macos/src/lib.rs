//! Monterey-compatible privileged helper installation boundary.
//!
//! M1 selects the OS-appropriate ServiceManagement family but deliberately
//! performs no registration or privileged mutation.

use tunbridge_desktop_contract::adapter::{AdapterError, InstallOperation, ProductInstaller};

pub mod bootstrap_assets;
pub mod bootstrap_protocol;
#[cfg(unix)]
pub mod bundle_assets;
pub mod bundle_inspection;
pub mod bundle_metadata;
pub mod engine_asset;
#[cfg(unix)]
pub mod generation_store;
pub mod install_transaction;

pub const MONTEREY_INSTALLER: &str = "smjobbless";
pub const MODERN_INSTALLER: &str = "smappservice";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerKind {
    SmJobBless,
    SmAppService,
}

pub const fn installer_for_major_version(major_version: u16) -> Option<InstallerKind> {
    match major_version {
        0..=11 => None,
        12 => Some(InstallerKind::SmJobBless),
        _ => Some(InstallerKind::SmAppService),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MacosProductInstaller {
    pub kind: InstallerKind,
}

impl ProductInstaller for MacosProductInstaller {
    fn run(&self, _operation: InstallOperation) -> Result<(), AdapterError> {
        let _ = self.kind;
        Err(AdapterError::not_ready())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_desktop_contract::adapter::AdapterErrorCode;

    #[test]
    fn monterey_and_modern_installers_are_selected_without_overlap() {
        assert_eq!(installer_for_major_version(11), None);
        assert_eq!(
            installer_for_major_version(12),
            Some(InstallerKind::SmJobBless)
        );
        assert_eq!(
            installer_for_major_version(13),
            Some(InstallerKind::SmAppService)
        );
        assert_eq!(
            installer_for_major_version(26),
            Some(InstallerKind::SmAppService)
        );
    }

    #[test]
    fn installer_is_fail_closed_until_the_privileged_milestone() {
        let installer = MacosProductInstaller {
            kind: InstallerKind::SmJobBless,
        };
        let error = installer
            .run(InstallOperation::InstallOrUpgrade)
            .unwrap_err();
        assert_eq!(error.code, AdapterErrorCode::NotReady);
    }
}
