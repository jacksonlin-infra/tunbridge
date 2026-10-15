//! Validation boundary between an authenticated bootstrap caller and root-owned
//! generation mutation. The native resolver supplies bytes from fixed locations
//! in that caller's signed App bundle.

use crate::{
    bootstrap_protocol::{BootstrapCaller, GenerationMaterial},
    bundle_metadata::APP_BUNDLE_ID,
    engine_asset::ValidatedEngineAsset,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_POLICY_BYTES: usize = 4096;
const MAX_ALLOWED_CDHASHES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapAssetError {
    InvalidPolicy,
    InvalidManifest,
    IntegrityMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGenerationAssets {
    policy_json: Vec<u8>,
    engine_manifest: Vec<u8>,
    engine_binary: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAppPolicy {
    schema_version: u16,
    team_id: String,
    app_signing_identifier: String,
    allowed_cdhashes: Vec<String>,
}

impl ValidatedGenerationAssets {
    pub fn validate(
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
        policy_json: Vec<u8>,
        engine_manifest: Vec<u8>,
        engine_binary: Vec<u8>,
    ) -> Result<Self, BootstrapAssetError> {
        if policy_json.is_empty()
            || policy_json.len() > MAX_POLICY_BYTES
            || digest(&policy_json) != material.policy_sha256
            || digest(&engine_manifest) != material.engine_manifest_sha256
            || digest(&engine_binary) != material.engine_sha256
            || engine_binary.len() as u64 != material.engine_size
        {
            return Err(BootstrapAssetError::IntegrityMismatch);
        }
        validate_policy(caller, &policy_json)?;
        let engine = ValidatedEngineAsset::validate(
            &engine_manifest,
            &engine_binary,
            &material.target_triple,
        )
        .map_err(|_| BootstrapAssetError::InvalidManifest)?;
        if engine.binary_sha256() != material.engine_sha256
            || engine.binary_size() != material.engine_size
        {
            return Err(BootstrapAssetError::IntegrityMismatch);
        }
        Ok(Self {
            policy_json,
            engine_manifest,
            engine_binary,
        })
    }

    pub fn policy_json(&self) -> &[u8] {
        &self.policy_json
    }

    pub fn engine_manifest(&self) -> &[u8] {
        &self.engine_manifest
    }

    pub fn engine_binary(&self) -> &[u8] {
        &self.engine_binary
    }

    /// Validate an internal ad-hoc generation after the root helper has
    /// already admitted this exact caller over XPC. The installed policy is
    /// still bound to the caller cdhash; only the development `adhoc` team
    /// marker differs from the release Developer ID policy.
    #[cfg(feature = "macos-development-installer")]
    pub fn validate_development(
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
        policy_json: Vec<u8>,
        engine_manifest: Vec<u8>,
        engine_binary: Vec<u8>,
    ) -> Result<Self, BootstrapAssetError> {
        if policy_json.is_empty()
            || policy_json.len() > MAX_POLICY_BYTES
            || digest(&policy_json) != material.policy_sha256
            || digest(&engine_manifest) != material.engine_manifest_sha256
            || digest(&engine_binary) != material.engine_sha256
            || engine_binary.len() as u64 != material.engine_size
        {
            return Err(BootstrapAssetError::IntegrityMismatch);
        }
        // The development bootstrap admits an identifier-only ad-hoc caller,
        // so the engine it provisions for root must be the exact signed
        // payload this helper was built with. A caller-supplied bundle cannot
        // substitute another program; a build without the pin provisions
        // nothing.
        if PINNED_ENGINE_SHA256 != Some(material.engine_sha256.as_str()) {
            return Err(BootstrapAssetError::IntegrityMismatch);
        }
        validate_development_policy(caller, &policy_json)?;
        let engine = ValidatedEngineAsset::validate(
            &engine_manifest,
            &engine_binary,
            &material.target_triple,
        )
        .map_err(|_| BootstrapAssetError::InvalidManifest)?;
        if engine.binary_sha256() != material.engine_sha256
            || engine.binary_size() != material.engine_size
        {
            return Err(BootstrapAssetError::IntegrityMismatch);
        }
        Ok(Self {
            policy_json,
            engine_manifest,
            engine_binary,
        })
    }
}

fn validate_policy(caller: &BootstrapCaller, bytes: &[u8]) -> Result<(), BootstrapAssetError> {
    let policy: StoredAppPolicy =
        serde_json::from_slice(bytes).map_err(|_| BootstrapAssetError::InvalidPolicy)?;
    if policy.schema_version != 1
        || policy.team_id != caller.team_id
        || policy.app_signing_identifier != APP_BUNDLE_ID
        || policy.allowed_cdhashes.is_empty()
        || policy.allowed_cdhashes.len() > MAX_ALLOWED_CDHASHES
        || !policy
            .allowed_cdhashes
            .iter()
            .any(|value| value == &caller.cdhash)
    {
        return Err(BootstrapAssetError::InvalidPolicy);
    }
    let unique = policy.allowed_cdhashes.iter().collect::<BTreeSet<_>>();
    if unique.len() != policy.allowed_cdhashes.len()
        || policy
            .allowed_cdhashes
            .iter()
            .any(|value| !valid_cdhash(value))
    {
        return Err(BootstrapAssetError::InvalidPolicy);
    }
    Ok(())
}

/// Set by scripts/build-macos-desktop-candidate.sh from the signed bundled
/// engine when it builds the internal-installer helper.
#[cfg(feature = "macos-development-installer")]
const PINNED_ENGINE_SHA256: Option<&str> = option_env!("TUNBRIDGE_PINNED_ENGINE_SHA256");

#[cfg(feature = "macos-development-installer")]
fn validate_development_policy(
    caller: &BootstrapCaller,
    bytes: &[u8],
) -> Result<(), BootstrapAssetError> {
    let policy: StoredAppPolicy =
        serde_json::from_slice(bytes).map_err(|_| BootstrapAssetError::InvalidPolicy)?;
    if policy.schema_version != 1
        || policy.team_id != "adhoc"
        || policy.app_signing_identifier != APP_BUNDLE_ID
        || policy.allowed_cdhashes.len() != 1
        || policy.allowed_cdhashes.first() != Some(&caller.cdhash)
    {
        return Err(BootstrapAssetError::InvalidPolicy);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_cdhash(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDHASH: &str = "1111111111111111111111111111111111111111";

    fn caller() -> BootstrapCaller {
        BootstrapCaller {
            pid: 501,
            uid: 502,
            audit_session_id: 42,
            team_id: "ABCDE12345".into(),
            cdhash: CDHASH.into(),
        }
    }

    fn policy() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "teamId": "ABCDE12345",
            "appSigningIdentifier": APP_BUNDLE_ID,
            "allowedCdhashes": [CDHASH]
        }))
        .unwrap()
    }

    fn manifest(engine: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "version": "v1.19.28",
            "targetTriple": "aarch64-apple-darwin",
            "binarySize": engine.len(),
            "binarySha256": digest(engine)
        }))
        .unwrap()
    }

    fn material(policy: &[u8], manifest: &[u8], engine: &[u8]) -> GenerationMaterial {
        GenerationMaterial {
            transaction_id: "0123456789abcdef0123456789abcdef".into(),
            caller_cdhash: CDHASH.into(),
            policy_sha256: digest(policy),
            engine_manifest_sha256: digest(manifest),
            engine_sha256: digest(engine),
            engine_size: engine.len() as u64,
            target_triple: "aarch64-apple-darwin".into(),
        }
    }

    #[cfg(feature = "macos-development-installer")]
    #[test]
    fn development_provisioning_accepts_only_the_pinned_engine() {
        let mut adhoc = caller();
        adhoc.team_id = "adhoc".into();
        let policy = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "teamId": "adhoc",
            "appSigningIdentifier": APP_BUNDLE_ID,
            "allowedCdhashes": [CDHASH]
        }))
        .unwrap();
        let engine = b"caller-supplied-engine".to_vec();
        let manifest = manifest(&engine);
        let result = ValidatedGenerationAssets::validate_development(
            &adhoc,
            &material(&policy, &manifest, &engine),
            policy.clone(),
            manifest.clone(),
            engine.clone(),
        );
        // Test builds carry no pin, and a caller bundle never matches one.
        assert_ne!(PINNED_ENGINE_SHA256, Some(digest(&engine).as_str()));
        assert!(matches!(
            result,
            Err(BootstrapAssetError::IntegrityMismatch)
        ));
    }

    #[test]
    fn exact_policy_manifest_and_engine_are_bound_to_authenticated_caller() {
        let policy = policy();
        let engine = b"signed-engine-fixture".to_vec();
        let manifest = manifest(&engine);
        let assets = ValidatedGenerationAssets::validate(
            &caller(),
            &material(&policy, &manifest, &engine),
            policy.clone(),
            manifest.clone(),
            engine.clone(),
        )
        .unwrap();
        assert_eq!(assets.policy_json(), policy);
        assert_eq!(assets.engine_manifest(), manifest);
        assert_eq!(assets.engine_binary(), engine);
    }

    #[test]
    fn substituted_policy_identity_generation_or_asset_fails_closed() {
        let policy = policy();
        let engine = b"signed-engine-fixture".to_vec();
        let manifest = manifest(&engine);
        let base = material(&policy, &manifest, &engine);

        let mut wrong_team: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        wrong_team["teamId"] = "OTHER12345".into();
        let wrong_team = serde_json::to_vec(&wrong_team).unwrap();
        let wrong_team_material = material(&wrong_team, &manifest, &engine);
        assert_eq!(
            ValidatedGenerationAssets::validate(
                &caller(),
                &wrong_team_material,
                wrong_team,
                manifest.clone(),
                engine.clone()
            ),
            Err(BootstrapAssetError::InvalidPolicy)
        );

        let mut missing_generation: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        missing_generation["allowedCdhashes"] =
            serde_json::json!(["2222222222222222222222222222222222222222"]);
        let missing_generation = serde_json::to_vec(&missing_generation).unwrap();
        let missing_material = material(&missing_generation, &manifest, &engine);
        assert_eq!(
            ValidatedGenerationAssets::validate(
                &caller(),
                &missing_material,
                missing_generation,
                manifest.clone(),
                engine.clone()
            ),
            Err(BootstrapAssetError::InvalidPolicy)
        );

        let mut substituted = engine.clone();
        substituted[0] ^= 1;
        assert_eq!(
            ValidatedGenerationAssets::validate(&caller(), &base, policy, manifest, substituted),
            Err(BootstrapAssetError::IntegrityMismatch)
        );
    }
}
