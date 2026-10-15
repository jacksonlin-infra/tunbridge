//! Pure validation model for recursive macOS App Bundle inspection.

use std::collections::BTreeSet;

pub const APP_EXECUTABLE_PATH: &str = "Contents/MacOS/tunbridge-desktop";
pub const MONTEREY_HELPER_PATH: &str =
    "Contents/Library/LaunchServices/com.tunbridge.desktop.helper";
pub const MODERN_HELPER_PATH: &str = "Contents/MacOS/tunbridge-helper-macos";
pub const MODERN_DAEMON_PLIST_PATH: &str =
    "Contents/Library/LaunchDaemons/com.tunbridge.desktop.helper.plist";
pub const DESKTOP_HELPER_POLICY_PATH: &str = "Contents/Resources/tunbridge-helper-policy.json";
pub const BOOTSTRAP_APP_POLICY_PATH: &str = "Contents/Resources/tunbridge-app-policy.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Architecture {
    Arm64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFlavor {
    Arm64,
    X86_64,
    Universal2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Unsigned,
    AdHoc,
    DeveloperId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Candidate,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRole {
    App,
    MontereyHelper,
    ModernHelper,
    Engine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOInspection {
    pub role: CodeRole,
    pub relative_path: String,
    pub architectures: Vec<Architecture>,
    pub minimum_system_version: (u16, u16),
    pub dependencies: Vec<String>,
    pub signature: SignatureKind,
    pub hardened_runtime: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleInspection {
    pub bundle_identifier: String,
    pub minimum_system_version: String,
    pub flavor: BundleFlavor,
    pub files: BTreeSet<String>,
    pub code: Vec<MachOInspection>,
    pub notarized: bool,
    pub stapled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleInspectionError {
    InvalidIdentifier,
    InvalidMinimumSystemVersion,
    MissingRequiredFile,
    UnexpectedCodeSet,
    InvalidCodePath,
    InvalidArchitecture,
    InvalidMachOMinimum,
    UnsafeDependency,
    InvalidSignature,
    MissingHardenedRuntime,
    MissingNotarization,
}

impl BundleInspection {
    pub fn validate(&self, mode: ValidationMode) -> Result<(), BundleInspectionError> {
        if self.bundle_identifier != crate::bundle_metadata::APP_BUNDLE_ID {
            return Err(BundleInspectionError::InvalidIdentifier);
        }
        if self.minimum_system_version != "12.0" {
            return Err(BundleInspectionError::InvalidMinimumSystemVersion);
        }
        for path in required_files() {
            if !self.files.contains(*path) {
                return Err(BundleInspectionError::MissingRequiredFile);
            }
        }
        if self.code.len() != 4 {
            return Err(BundleInspectionError::UnexpectedCodeSet);
        }
        let roles = self.code.iter().map(|code| code.role).collect::<Vec<_>>();
        if roles
            .iter()
            .enumerate()
            .any(|(index, role)| roles[..index].contains(role))
            || ![
                CodeRole::App,
                CodeRole::MontereyHelper,
                CodeRole::ModernHelper,
                CodeRole::Engine,
            ]
            .iter()
            .all(|role| roles.contains(role))
        {
            return Err(BundleInspectionError::UnexpectedCodeSet);
        }
        for code in &self.code {
            if code.relative_path != expected_path(code.role) {
                return Err(BundleInspectionError::InvalidCodePath);
            }
            if code.architectures != expected_architectures(self.flavor) {
                return Err(BundleInspectionError::InvalidArchitecture);
            }
            if code.minimum_system_version == (0, 0) || code.minimum_system_version > (12, 0) {
                return Err(BundleInspectionError::InvalidMachOMinimum);
            }
            if code
                .dependencies
                .iter()
                .any(|value| !safe_dependency(value))
            {
                return Err(BundleInspectionError::UnsafeDependency);
            }
            match (mode, code.signature) {
                (ValidationMode::Candidate, SignatureKind::AdHoc | SignatureKind::DeveloperId)
                | (ValidationMode::Release, SignatureKind::DeveloperId) => {}
                _ => return Err(BundleInspectionError::InvalidSignature),
            }
            if matches!(mode, ValidationMode::Release) && !code.hardened_runtime {
                return Err(BundleInspectionError::MissingHardenedRuntime);
            }
        }
        if matches!(mode, ValidationMode::Release) && (!self.notarized || !self.stapled) {
            return Err(BundleInspectionError::MissingNotarization);
        }
        Ok(())
    }
}

pub fn required_files() -> &'static [&'static str] {
    &[
        "Contents/Info.plist",
        APP_EXECUTABLE_PATH,
        MONTEREY_HELPER_PATH,
        MODERN_HELPER_PATH,
        MODERN_DAEMON_PLIST_PATH,
        DESKTOP_HELPER_POLICY_PATH,
        BOOTSTRAP_APP_POLICY_PATH,
        crate::engine_asset::BUNDLE_ENGINE_PATH,
        crate::engine_asset::BUNDLE_ENGINE_MANIFEST_PATH,
    ]
}

fn expected_path(role: CodeRole) -> &'static str {
    match role {
        CodeRole::App => APP_EXECUTABLE_PATH,
        CodeRole::MontereyHelper => MONTEREY_HELPER_PATH,
        CodeRole::ModernHelper => MODERN_HELPER_PATH,
        CodeRole::Engine => crate::engine_asset::BUNDLE_ENGINE_PATH,
    }
}

fn expected_architectures(flavor: BundleFlavor) -> Vec<Architecture> {
    match flavor {
        BundleFlavor::Arm64 => vec![Architecture::Arm64],
        BundleFlavor::X86_64 => vec![Architecture::X86_64],
        BundleFlavor::Universal2 => vec![Architecture::Arm64, Architecture::X86_64],
    }
}

fn safe_dependency(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_control)
        && (value.starts_with("/System/Library/")
            || value.starts_with("/usr/lib/")
            || value.starts_with("@rpath/")
            || value.starts_with("@loader_path/")
            || value.starts_with("@executable_path/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection(flavor: BundleFlavor, signature: SignatureKind) -> BundleInspection {
        let architectures = expected_architectures(flavor);
        let code = [
            CodeRole::App,
            CodeRole::MontereyHelper,
            CodeRole::ModernHelper,
            CodeRole::Engine,
        ]
        .into_iter()
        .map(|role| MachOInspection {
            role,
            relative_path: expected_path(role).into(),
            architectures: architectures.clone(),
            minimum_system_version: (12, 0),
            dependencies: vec!["/usr/lib/libSystem.B.dylib".into()],
            signature,
            hardened_runtime: signature == SignatureKind::DeveloperId,
        })
        .collect();
        BundleInspection {
            bundle_identifier: crate::bundle_metadata::APP_BUNDLE_ID.into(),
            minimum_system_version: "12.0".into(),
            flavor,
            files: required_files()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            code,
            notarized: signature == SignatureKind::DeveloperId,
            stapled: signature == SignatureKind::DeveloperId,
        }
    }

    #[test]
    fn arch_specific_ad_hoc_candidate_and_developer_id_release_are_distinct() {
        for flavor in [BundleFlavor::Arm64, BundleFlavor::X86_64] {
            assert_eq!(
                inspection(flavor, SignatureKind::AdHoc).validate(ValidationMode::Candidate),
                Ok(())
            );
            assert_eq!(
                inspection(flavor, SignatureKind::AdHoc).validate(ValidationMode::Release),
                Err(BundleInspectionError::InvalidSignature)
            );
            assert_eq!(
                inspection(flavor, SignatureKind::DeveloperId).validate(ValidationMode::Release),
                Ok(())
            );
        }
    }

    #[test]
    fn universal_requires_both_slices_in_every_nested_executable() {
        let mut bundle = inspection(BundleFlavor::Universal2, SignatureKind::AdHoc);
        assert_eq!(bundle.validate(ValidationMode::Candidate), Ok(()));
        bundle.code[3].architectures = vec![Architecture::Arm64];
        assert_eq!(
            bundle.validate(ValidationMode::Candidate),
            Err(BundleInspectionError::InvalidArchitecture)
        );
    }

    #[test]
    fn missing_layout_newer_minos_and_developer_paths_fail_closed() {
        let mut missing = inspection(BundleFlavor::Arm64, SignatureKind::AdHoc);
        missing.files.remove(MODERN_DAEMON_PLIST_PATH);
        assert_eq!(
            missing.validate(ValidationMode::Candidate),
            Err(BundleInspectionError::MissingRequiredFile)
        );

        let mut newer = inspection(BundleFlavor::Arm64, SignatureKind::AdHoc);
        newer.code[0].minimum_system_version = (13, 0);
        assert_eq!(
            newer.validate(ValidationMode::Candidate),
            Err(BundleInspectionError::InvalidMachOMinimum)
        );

        let mut dependency = inspection(BundleFlavor::Arm64, SignatureKind::AdHoc);
        dependency.code[0].dependencies = vec!["/opt/build/target/debug/libunsafe.dylib".into()];
        assert_eq!(
            dependency.validate(ValidationMode::Candidate),
            Err(BundleInspectionError::UnsafeDependency)
        );
    }

    #[test]
    fn release_requires_hardened_runtime_notarization_and_staple() {
        let mut bundle = inspection(BundleFlavor::Arm64, SignatureKind::DeveloperId);
        bundle.code[1].hardened_runtime = false;
        assert_eq!(
            bundle.validate(ValidationMode::Release),
            Err(BundleInspectionError::MissingHardenedRuntime)
        );
        bundle.code[1].hardened_runtime = true;
        bundle.stapled = false;
        assert_eq!(
            bundle.validate(ValidationMode::Release),
            Err(BundleInspectionError::MissingNotarization)
        );
    }
}
