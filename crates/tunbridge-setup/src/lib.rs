use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::{Component, Path},
};

#[cfg(any(windows, test))]
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PACKAGE_MANIFEST: &str = "product-package.json";
pub const PACKAGE_SCHEMA_VERSION: u16 = 1;
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SERVICE_PROTOCOL_VERSION: u16 = 4;
pub const SERVICE_FEATURE: &str = "production-mihomo-logs-v4";
#[cfg(any(windows, test))]
const LEGACY_SERVICE_PROTOCOL_VERSION: u16 = 2;
#[cfg(any(windows, test))]
const LEGACY_REMOTE_PROTOCOL_VERSION: u16 = 3;
#[cfg(any(windows, test))]
const LEGACY_REMOTE_FEATURE: &str = "remote-upstream-v3";
#[cfg(any(windows, test))]
const LEGACY_OBSERVABILITY_FEATURE: &str = "production-local-observability";
#[cfg(any(windows, test))]
const LEGACY_APP_LEASE_FEATURE: &str = "production-app-lease";
pub const REQUIRED_CAPABILITIES: [&str; 9] = [
    "status",
    "start",
    "stop",
    "recover",
    "lease",
    "observe_local_traffic",
    "close_owned_connections",
    "remote_upstream",
    "observe_mihomo_logs",
];
#[cfg(any(windows, test))]
const LEGACY_REMOTE_CAPABILITIES: [&str; 8] = [
    "status",
    "start",
    "stop",
    "recover",
    "lease",
    "observe_local_traffic",
    "close_owned_connections",
    "remote_upstream",
];
#[cfg(any(windows, test))]
const LEGACY_OBSERVABILITY_CAPABILITIES: [&str; 7] = [
    "status",
    "start",
    "stop",
    "recover",
    "lease",
    "observe_local_traffic",
    "close_owned_connections",
];
#[cfg(any(windows, test))]
const LEGACY_APP_LEASE_CAPABILITIES: [&str; 5] = ["status", "start", "stop", "recover", "lease"];
pub const PAYLOAD_FILENAMES: [&str; 6] = [
    "tunbridge-desktop.exe",
    "tunbridge-setup.exe",
    "tunbridge-service.exe",
    "tunbridge.exe",
    "mihomo.exe",
    "engines.lock.json",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductPackage {
    pub schema_version: u16,
    pub product_version: String,
    pub service_feature: String,
    pub service_protocol_version: u16,
    pub service_capabilities: Vec<String>,
    pub files: Vec<PackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
}

impl ProductPackage {
    pub fn validate_schema(&self) -> Result<(), PackageError> {
        self.validate_common_schema()?;
        if self.service_feature != SERVICE_FEATURE {
            return Err(PackageError::ServiceFeature);
        }
        if self.service_capabilities != REQUIRED_CAPABILITIES.map(str::to_owned).to_vec() {
            return Err(PackageError::Capabilities);
        }
        Ok(())
    }

    #[cfg(any(windows, test))]
    fn validate_upgrade_schema(&self) -> Result<(), PackageError> {
        self.validate_common_structure()?;
        validate_upgrade_version(&self.product_version)?;
        let current = self.service_protocol_version == SERVICE_PROTOCOL_VERSION
            && self.service_feature == SERVICE_FEATURE
            && self.service_capabilities == REQUIRED_CAPABILITIES.map(str::to_owned).to_vec();
        let legacy_remote = self.service_protocol_version == LEGACY_REMOTE_PROTOCOL_VERSION
            && self.service_feature == LEGACY_REMOTE_FEATURE
            && self.service_capabilities == LEGACY_REMOTE_CAPABILITIES.map(str::to_owned).to_vec();
        let legacy_observability = self.service_protocol_version == LEGACY_SERVICE_PROTOCOL_VERSION
            && self.service_feature == LEGACY_OBSERVABILITY_FEATURE
            && self.service_capabilities
                == LEGACY_OBSERVABILITY_CAPABILITIES
                    .map(str::to_owned)
                    .to_vec();
        let legacy_app_lease = self.service_protocol_version == LEGACY_SERVICE_PROTOCOL_VERSION
            && self.service_feature == LEGACY_APP_LEASE_FEATURE
            && self.service_capabilities
                == LEGACY_APP_LEASE_CAPABILITIES.map(str::to_owned).to_vec();
        if current || legacy_remote || legacy_observability || legacy_app_lease {
            Ok(())
        } else if !matches!(
            self.service_protocol_version,
            SERVICE_PROTOCOL_VERSION
                | LEGACY_REMOTE_PROTOCOL_VERSION
                | LEGACY_SERVICE_PROTOCOL_VERSION
        ) {
            Err(PackageError::ProtocolVersion)
        } else if !matches!(
            self.service_feature.as_str(),
            SERVICE_FEATURE
                | LEGACY_REMOTE_FEATURE
                | LEGACY_OBSERVABILITY_FEATURE
                | LEGACY_APP_LEASE_FEATURE
        ) {
            Err(PackageError::ServiceFeature)
        } else {
            Err(PackageError::Capabilities)
        }
    }

    fn validate_common_schema(&self) -> Result<(), PackageError> {
        self.validate_common_fields()?;
        if self.product_version != PRODUCT_VERSION {
            return Err(PackageError::ProductVersion);
        }
        Ok(())
    }

    fn validate_common_fields(&self) -> Result<(), PackageError> {
        self.validate_common_structure()?;
        if self.service_protocol_version != SERVICE_PROTOCOL_VERSION {
            return Err(PackageError::ProtocolVersion);
        }
        Ok(())
    }

    fn validate_common_structure(&self) -> Result<(), PackageError> {
        if self.schema_version != PACKAGE_SCHEMA_VERSION {
            return Err(PackageError::SchemaVersion);
        }
        if self.files.len() != PAYLOAD_FILENAMES.len() {
            return Err(PackageError::FileSet);
        }

        let mut seen = BTreeSet::new();
        for (entry, expected) in self.files.iter().zip(PAYLOAD_FILENAMES) {
            if entry.filename != expected || !is_plain_filename(&entry.filename) {
                return Err(PackageError::FileSet);
            }
            if !seen.insert(entry.filename.as_str()) {
                return Err(PackageError::DuplicateFile);
            }
            if entry.size == 0 {
                return Err(PackageError::EmptyFile(entry.filename.clone()));
            }
            if !is_lower_hex_256(&entry.sha256) {
                return Err(PackageError::InvalidHash(entry.filename.clone()));
            }
        }
        Ok(())
    }

    pub fn validate_directory(&self, root: &Path) -> Result<(), PackageError> {
        self.validate_schema()?;
        self.validate_assets(root)
    }

    #[cfg(windows)]
    fn validate_upgrade_directory(&self, root: &Path) -> Result<(), PackageError> {
        self.validate_upgrade_schema()?;
        self.validate_assets(root)
    }

    fn validate_assets(&self, root: &Path) -> Result<(), PackageError> {
        for entry in &self.files {
            let path = root.join(&entry.filename);
            let metadata = path.metadata().map_err(PackageError::Io)?;
            if !metadata.is_file() || metadata.len() != entry.size {
                return Err(PackageError::AssetMismatch(entry.filename.clone()));
            }
            if sha256_file(&path)? != entry.sha256 {
                return Err(PackageError::AssetMismatch(entry.filename.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn validate_upgrade_version(value: &str) -> Result<(), PackageError> {
    let installed = Version::parse(value).map_err(|_| PackageError::ProductVersion)?;
    let current = Version::parse(PRODUCT_VERSION).map_err(|_| PackageError::ProductVersion)?;
    if !installed.pre.is_empty() || !installed.build.is_empty() || installed > current {
        return Err(PackageError::ProductVersion);
    }
    Ok(())
}

pub fn read_package(root: &Path) -> Result<ProductPackage, PackageError> {
    read_package_with(root, ProductPackage::validate_schema)
}

#[cfg(windows)]
fn read_package_for_upgrade(root: &Path) -> Result<ProductPackage, PackageError> {
    read_package_with(root, ProductPackage::validate_upgrade_schema)
}

fn read_package_with(
    root: &Path,
    validate: fn(&ProductPackage) -> Result<(), PackageError>,
) -> Result<ProductPackage, PackageError> {
    let path = root.join(PACKAGE_MANIFEST);
    let metadata = path.metadata().map_err(PackageError::Io)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 {
        return Err(PackageError::ManifestSize);
    }
    let file = File::open(path).map_err(PackageError::Io)?;
    let package: ProductPackage = serde_json::from_reader(file).map_err(PackageError::Json)?;
    validate(&package)?;
    Ok(package)
}

pub fn sha256_file(path: &Path) -> Result<String, PackageError> {
    let mut file = File::open(path).map_err(PackageError::Io)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(PackageError::Io)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn is_plain_filename(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn is_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("package I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("package manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("package manifest has an invalid size")]
    ManifestSize,
    #[error("package schema version is not supported")]
    SchemaVersion,
    #[error("package product version is not supported")]
    ProductVersion,
    #[error("package service feature is not authorized")]
    ServiceFeature,
    #[error("package service protocol version is not supported")]
    ProtocolVersion,
    #[error("package service capabilities are not the Gate C set")]
    Capabilities,
    #[error("package file set is not exact")]
    FileSet,
    #[error("package contains a duplicate file")]
    DuplicateFile,
    #[error("package file is empty: {0}")]
    EmptyFile(String),
    #[error("package hash is invalid: {0}")]
    InvalidHash(String),
    #[error("package asset failed size or hash validation: {0}")]
    AssetMismatch(String),
}

#[cfg(windows)]
#[path = "../../../platforms/windows/crates/tunbridge-setup-windows/src/imp/windows.rs"]
pub mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_package() -> ProductPackage {
        ProductPackage {
            schema_version: PACKAGE_SCHEMA_VERSION,
            product_version: PRODUCT_VERSION.into(),
            service_feature: SERVICE_FEATURE.into(),
            service_protocol_version: SERVICE_PROTOCOL_VERSION,
            service_capabilities: REQUIRED_CAPABILITIES.map(str::to_owned).to_vec(),
            files: PAYLOAD_FILENAMES
                .map(|filename| PackageFile {
                    filename: filename.into(),
                    size: 1,
                    sha256: "a".repeat(64),
                })
                .to_vec(),
        }
    }

    #[test]
    fn exact_manifest_is_accepted() {
        valid_package().validate_schema().unwrap();
    }

    #[test]
    fn stable_semver_generations_do_not_require_a_version_allowlist() {
        for version in ["0.0.1", "0.2.16", "0.3.0"] {
            let mut package = valid_package();
            package.product_version = version.into();
            package.validate_upgrade_schema().unwrap();
            if version != PRODUCT_VERSION {
                assert!(package.validate_schema().is_err());
            }
        }

        let mut legacy_observability = valid_package();
        legacy_observability.product_version = "0.3.2".into();
        legacy_observability.service_protocol_version = LEGACY_SERVICE_PROTOCOL_VERSION;
        legacy_observability.service_feature = LEGACY_OBSERVABILITY_FEATURE.into();
        legacy_observability.service_capabilities = LEGACY_OBSERVABILITY_CAPABILITIES
            .map(str::to_owned)
            .to_vec();
        legacy_observability.validate_upgrade_schema().unwrap();
        assert!(legacy_observability.validate_schema().is_err());

        let mut legacy_app_lease = valid_package();
        legacy_app_lease.product_version = "0.1.0".into();
        legacy_app_lease.service_protocol_version = LEGACY_SERVICE_PROTOCOL_VERSION;
        legacy_app_lease.service_feature = LEGACY_APP_LEASE_FEATURE.into();
        legacy_app_lease.service_capabilities =
            LEGACY_APP_LEASE_CAPABILITIES.map(str::to_owned).to_vec();
        legacy_app_lease.validate_upgrade_schema().unwrap();
        assert!(legacy_app_lease.validate_schema().is_err());

        legacy_observability.service_capabilities.swap(0, 1);
        assert!(matches!(
            legacy_observability.validate_upgrade_schema(),
            Err(PackageError::Capabilities)
        ));

        let current = Version::parse(PRODUCT_VERSION).unwrap();
        let future = Version::new(current.major, current.minor, current.patch + 1).to_string();
        for invalid in ["", "0.2", "0.3.0-beta.1", "0.3.0+rebuilt", &future, "1.0.0"] {
            let mut package = valid_package();
            package.product_version = invalid.into();
            assert!(matches!(
                package.validate_upgrade_schema(),
                Err(PackageError::ProductVersion)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "reads the fixed installed Windows product generation for diagnostics"]
    fn real_installed_windows_generation_satisfies_upgrade_contract() {
        read_package_for_upgrade(Path::new(r"C:\Program Files\TunBridge")).unwrap();
    }

    #[test]
    fn path_and_duplicate_substitution_are_rejected() {
        let mut package = valid_package();
        package.files[0].filename = r"..\tunbridge-desktop.exe".into();
        assert!(matches!(
            package.validate_schema(),
            Err(PackageError::FileSet)
        ));

        let mut package = valid_package();
        package.files[1].filename = package.files[0].filename.clone();
        assert!(matches!(
            package.validate_schema(),
            Err(PackageError::FileSet)
        ));
    }

    #[test]
    fn capability_order_and_unknown_fields_are_rejected() {
        let mut package = valid_package();
        package.service_capabilities.swap(0, 1);
        assert!(matches!(
            package.validate_schema(),
            Err(PackageError::Capabilities)
        ));

        let mut json = serde_json::to_value(valid_package()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("command".into(), "x".into());
        assert!(serde_json::from_value::<ProductPackage>(json).is_err());
    }
}
