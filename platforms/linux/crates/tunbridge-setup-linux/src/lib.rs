//! Fixed Linux package layout and setup policy.

use serde::Deserialize;

#[cfg(not(feature = "pacman-package"))]
pub const INSTALL_MANIFEST_JSON: &str =
    include_str!("../../../packaging/deb/linux-service-layout.json");
#[cfg(feature = "pacman-package")]
pub const INSTALL_MANIFEST_JSON: &str =
    include_str!("../../../packaging/arch/linux-service-layout.json");
#[cfg(not(feature = "pacman-package"))]
pub const PRE_INSTALL_SCRIPT: &str = include_str!("../../../packaging/deb/preinst");
#[cfg(feature = "pacman-package")]
pub const PRE_INSTALL_SCRIPT: &str =
    include_str!("../../../packaging/arch/tunbridge-desktop.install");
#[cfg(not(feature = "pacman-package"))]
pub const POST_INSTALL_SCRIPT: &str = include_str!("../../../packaging/deb/postinst");
#[cfg(feature = "pacman-package")]
pub const POST_INSTALL_SCRIPT: &str =
    include_str!("../../../packaging/arch/tunbridge-desktop.install");
#[cfg(not(feature = "pacman-package"))]
pub const PRE_REMOVE_SCRIPT: &str = include_str!("../../../packaging/deb/prerm");
#[cfg(feature = "pacman-package")]
pub const PRE_REMOVE_SCRIPT: &str =
    include_str!("../../../packaging/arch/tunbridge-desktop.install");
#[cfg(not(feature = "pacman-package"))]
pub const POST_REMOVE_SCRIPT: &str = include_str!("../../../packaging/deb/postrm");
#[cfg(feature = "pacman-package")]
pub const POST_REMOVE_SCRIPT: &str =
    include_str!("../../../packaging/arch/tunbridge-desktop.install");
pub const SERVICE_UNIT: &str = include_str!("../../../packaging/systemd/tunbridge.service");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxInstallManifest {
    pub schema_version: u16,
    pub package_kind: String,
    pub service_user: String,
    pub service_group: String,
    pub membership_policy: String,
    pub engine_path: String,
    pub engine_mode: String,
    pub engine_size: u64,
    pub engine_sha256: String,
    pub binary_path: String,
    pub unit_path: String,
    pub runtime_directory: String,
    pub socket_path: String,
    pub binary_mode: String,
    pub unit_mode: String,
    pub socket_mode: String,
    pub service_protocol_version: u16,
    pub service_capabilities: Vec<String>,
    pub purge_group_only_when_empty: bool,
}

impl LinuxInstallManifest {
    pub fn embedded() -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_json::from_str(INSTALL_MANIFEST_JSON).map_err(|_| ManifestError::InvalidJson)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        let exact = self.schema_version == 2
            && self.package_kind
                == if cfg!(feature = "pacman-package") {
                    "pacman"
                } else {
                    "deb"
                }
            && self.service_user == "root"
            && self.service_group == "root"
            && self.membership_policy == "not-required-kernel-peer-authorization"
            && self.engine_path == "/usr/libexec/tunbridge/mihomo"
            && self.engine_mode == "0755"
            && self.engine_size == 50_999_422
            && self.engine_sha256
                == "8ad44e28fe72be4640254b96741b677f4074991b99186cc4486a1c28ded02b1a"
            && self.binary_path == "/usr/libexec/tunbridge/tunbridge-service-linux"
            && self.unit_path == "/usr/lib/systemd/system/tunbridge.service"
            && self.runtime_directory == "/run/tunbridge"
            && self.socket_path == "/run/tunbridge/service.sock"
            && self.binary_mode == "0755"
            && self.unit_mode == "0644"
            && self.socket_mode == "0666"
            && self.service_protocol_version == 4
            && self.service_capabilities
                == [
                    "status",
                    "start",
                    "stop",
                    "recover",
                    "lease",
                    "observe_local_traffic",
                    "close_owned_connections",
                    "remote_upstream",
                    "observe_mihomo_logs",
                ]
            && !self.purge_group_only_when_empty;
        if exact {
            Ok(())
        } else {
            Err(ManifestError::PolicyMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestError {
    InvalidJson,
    PolicyMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_is_the_fixed_full_function_layout() {
        let manifest = LinuxInstallManifest::embedded().unwrap();
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(
            manifest.package_kind,
            if cfg!(feature = "pacman-package") {
                "pacman"
            } else {
                "deb"
            }
        );
        assert_eq!(manifest.service_group, "root");
        assert_eq!(manifest.service_protocol_version, 4);
        assert!(manifest.service_capabilities.contains(&"start".to_string()));
        assert_eq!(
            manifest.membership_policy,
            "not-required-kernel-peer-authorization"
        );
        assert_eq!(manifest.socket_mode, "0666");
        assert!(!manifest.purge_group_only_when_empty);
    }

    #[test]
    fn capability_or_implicit_membership_changes_fail_closed() {
        let mut manifest = LinuxInstallManifest::embedded().unwrap();
        manifest.service_capabilities.pop();
        assert_eq!(manifest.validate(), Err(ManifestError::PolicyMismatch));

        let mut manifest = LinuxInstallManifest::embedded().unwrap();
        manifest.membership_policy = "explicit-admin-enrollment".into();
        assert_eq!(manifest.validate(), Err(ManifestError::PolicyMismatch));
    }

    #[test]
    fn maintainer_scripts_never_guess_a_desktop_user() {
        for script in [
            PRE_INSTALL_SCRIPT,
            POST_INSTALL_SCRIPT,
            PRE_REMOVE_SCRIPT,
            POST_REMOVE_SCRIPT,
        ] {
            assert!(script.starts_with("#!/bin/sh\nset -eu\n"));
            assert!(!script.contains("SUDO_USER"));
            assert!(!script.contains("$USER"));
            assert!(!script.contains("logname"));
            assert!(!script.contains("usermod"));
            for command in [
                "adduser ",
                "addgroup ",
                "groupadd ",
                "usermod",
                "gpasswd ",
                "delgroup ",
            ] {
                assert!(!script.contains(command));
            }
        }
    }

    #[test]
    fn upgrade_scripts_refuse_a_stale_desktop_or_service_process() {
        assert!(PRE_INSTALL_SCRIPT.contains("/proc/[0-9]*/exe"));
        assert!(PRE_INSTALL_SCRIPT.contains("Quit it from the tray"));
        assert!(
            POST_INSTALL_SCRIPT.contains(if cfg!(feature = "pacman-package") {
                "systemctl --system restart"
            } else {
                "deb-systemd-invoke restart"
            })
        );
        assert!(POST_INSTALL_SCRIPT.contains("is-active --quiet tunbridge.service"));
        assert!(POST_INSTALL_SCRIPT.contains("/proc/$service_pid/exe"));
        assert!(
            !POST_INSTALL_SCRIPT.contains(if cfg!(feature = "pacman-package") {
                "systemctl --system restart tunbridge.service >/dev/null || true"
            } else {
                "deb-systemd-invoke restart tunbridge.service >/dev/null || true"
            })
        );
    }

    #[test]
    fn upgrade_waits_for_systemd_executor_to_exec_the_new_service() {
        assert!(POST_INSTALL_SCRIPT.contains("service_identity_attempts=0"));
        assert!(POST_INSTALL_SCRIPT.contains("[ \"$service_identity_attempts\" -lt 50 ]"));
        assert!(POST_INSTALL_SCRIPT.contains("sleep 0.1"));
        assert!(POST_INSTALL_SCRIPT.contains("service_identity_verified=true"));
        assert!(POST_INSTALL_SCRIPT.contains("[ \"$service_identity_verified\" != true ]"));
    }

    #[test]
    fn service_unit_grants_only_required_runtime_capabilities_and_families() {
        assert!(SERVICE_UNIT.contains(
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE"
        ));
        assert!(SERVICE_UNIT.contains(
            "AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE"
        ));
        assert!(
            SERVICE_UNIT.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK")
        );
        assert!(!SERVICE_UNIT.contains("CAP_SYS_ADMIN"));
    }
}
