//! Strict, mutation-free validation of the bundled Darwin engine payload.

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const BUNDLE_ENGINE_PATH: &str = "Contents/Resources/tunbridge-engine/mihomo";
pub const BUNDLE_ENGINE_MANIFEST_PATH: &str = "Contents/Resources/tunbridge-engine/manifest.json";
pub const SYSTEM_ENGINE_PATH: &str = "/Library/Application Support/TunBridge/Engine/mihomo";
pub const SYSTEM_ENGINE_MANIFEST_PATH: &str =
    "/Library/Application Support/TunBridge/Engine/manifest.json";

const MAX_MANIFEST_BYTES: usize = 4096;
pub(crate) const MAX_ENGINE_BYTES: usize = 128 * 1024 * 1024;
const MAX_VERSION_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineAssetError {
    InvalidManifest,
    UnsupportedTarget,
    InvalidPayload,
    IntegrityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEngineAsset {
    version: String,
    target_triple: String,
    binary_size: u64,
    binary_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EngineManifest {
    schema_version: u16,
    version: String,
    target_triple: String,
    binary_size: u64,
    binary_sha256: String,
}

impl ValidatedEngineAsset {
    pub fn validate(
        manifest_bytes: &[u8],
        binary_bytes: &[u8],
        expected_target: &str,
    ) -> Result<Self, EngineAssetError> {
        if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
            return Err(EngineAssetError::InvalidManifest);
        }
        let manifest: EngineManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|_| EngineAssetError::InvalidManifest)?;
        if manifest.schema_version != 1
            || manifest.version.is_empty()
            || manifest.version.len() > MAX_VERSION_BYTES
            || manifest.version.chars().any(char::is_control)
            || !valid_sha256(&manifest.binary_sha256)
            || manifest.binary_size == 0
            || manifest.binary_size > MAX_ENGINE_BYTES as u64
        {
            return Err(EngineAssetError::InvalidManifest);
        }
        if !matches!(
            expected_target,
            "aarch64-apple-darwin" | "x86_64-apple-darwin"
        ) || manifest.target_triple != expected_target
        {
            return Err(EngineAssetError::UnsupportedTarget);
        }
        if binary_bytes.is_empty()
            || binary_bytes.len() > MAX_ENGINE_BYTES
            || binary_bytes.len() as u64 != manifest.binary_size
        {
            return Err(EngineAssetError::InvalidPayload);
        }
        let observed = format!("{:x}", Sha256::digest(binary_bytes));
        if observed != manifest.binary_sha256 {
            return Err(EngineAssetError::IntegrityMismatch);
        }
        Ok(Self {
            version: manifest.version,
            target_triple: manifest.target_triple,
            binary_size: manifest.binary_size,
            binary_sha256: manifest.binary_sha256,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    pub fn binary_size(&self) -> u64 {
        self.binary_size
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(binary: &[u8], target: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "version": "v1.19.28",
            "targetTriple": target,
            "binarySize": binary.len(),
            "binarySha256": format!("{:x}", Sha256::digest(binary))
        }))
        .unwrap()
    }

    #[test]
    fn exact_arch_specific_payload_is_accepted_for_fixed_paths() {
        let binary = b"fixture-mihomo";
        let asset = ValidatedEngineAsset::validate(
            &manifest(binary, "aarch64-apple-darwin"),
            binary,
            "aarch64-apple-darwin",
        )
        .unwrap();
        assert_eq!(asset.version(), "v1.19.28");
        assert_eq!(asset.target_triple(), "aarch64-apple-darwin");
        assert_eq!(asset.binary_size(), binary.len() as u64);
        assert_eq!(asset.binary_sha256().len(), 64);
        assert_eq!(
            BUNDLE_ENGINE_PATH,
            "Contents/Resources/tunbridge-engine/mihomo"
        );
        assert_eq!(
            BUNDLE_ENGINE_MANIFEST_PATH,
            "Contents/Resources/tunbridge-engine/manifest.json"
        );
        assert_eq!(
            SYSTEM_ENGINE_PATH,
            "/Library/Application Support/TunBridge/Engine/mihomo"
        );
        assert_eq!(
            SYSTEM_ENGINE_MANIFEST_PATH,
            "/Library/Application Support/TunBridge/Engine/manifest.json"
        );
    }

    #[test]
    fn target_substitution_size_hash_and_unknown_fields_fail_closed() {
        let binary = b"fixture-mihomo";
        assert_eq!(
            ValidatedEngineAsset::validate(
                &manifest(binary, "x86_64-apple-darwin"),
                binary,
                "aarch64-apple-darwin"
            ),
            Err(EngineAssetError::UnsupportedTarget)
        );
        let mut wrong_size: serde_json::Value =
            serde_json::from_slice(&manifest(binary, "aarch64-apple-darwin")).unwrap();
        wrong_size["binarySize"] = (binary.len() + 1).into();
        assert_eq!(
            ValidatedEngineAsset::validate(
                &serde_json::to_vec(&wrong_size).unwrap(),
                binary,
                "aarch64-apple-darwin"
            ),
            Err(EngineAssetError::InvalidPayload)
        );
        assert_eq!(
            ValidatedEngineAsset::validate(
                &manifest(binary, "aarch64-apple-darwin"),
                b"fixture-mihomx",
                "aarch64-apple-darwin"
            ),
            Err(EngineAssetError::IntegrityMismatch)
        );
        let mut unknown: serde_json::Value =
            serde_json::from_slice(&manifest(binary, "aarch64-apple-darwin")).unwrap();
        unknown["downloadUrl"] = "https://attacker.test".into();
        assert_eq!(
            ValidatedEngineAsset::validate(
                &serde_json::to_vec(&unknown).unwrap(),
                binary,
                "aarch64-apple-darwin"
            ),
            Err(EngineAssetError::InvalidManifest)
        );
    }
}
