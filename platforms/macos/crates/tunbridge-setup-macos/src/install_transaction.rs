use crate::{bundle_metadata::APP_BUNDLE_ID, InstallerKind};
use serde::Serialize;
use std::collections::BTreeSet;

pub const SYSTEM_POLICY_PATH: &str =
    "/Library/PrivilegedHelperTools/com.tunbridge.desktop.helper.policy.json";
const POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_ALLOWED_CDHASHES: usize = 4;
const MAX_IDENTIFIER_BYTES: usize = 128;
const CDHASH_HEX_BYTES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMaterialError {
    InvalidTeamId,
    InvalidAppIdentifier,
    InvalidCdhash,
    DuplicateCdhash,
    TooManyCdhashes,
    Serialization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPolicyMaterial {
    team_id: String,
    app_signing_identifier: String,
    allowed_cdhashes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredAppPolicy<'a> {
    schema_version: u16,
    team_id: &'a str,
    app_signing_identifier: &'a str,
    allowed_cdhashes: &'a [String],
}

impl SigningPolicyMaterial {
    pub fn new(
        team_id: impl Into<String>,
        app_signing_identifier: impl Into<String>,
        allowed_cdhashes: impl IntoIterator<Item = String>,
    ) -> Result<Self, InstallMaterialError> {
        let team_id = team_id.into();
        let app_signing_identifier = app_signing_identifier.into();
        let allowed_cdhashes = allowed_cdhashes.into_iter().collect::<Vec<_>>();
        if !valid_identifier(&team_id) {
            return Err(InstallMaterialError::InvalidTeamId);
        }
        if app_signing_identifier != APP_BUNDLE_ID || !valid_identifier(&app_signing_identifier) {
            return Err(InstallMaterialError::InvalidAppIdentifier);
        }
        if allowed_cdhashes.is_empty() || allowed_cdhashes.iter().any(|value| !valid_cdhash(value))
        {
            return Err(InstallMaterialError::InvalidCdhash);
        }
        if allowed_cdhashes.len() > MAX_ALLOWED_CDHASHES {
            return Err(InstallMaterialError::TooManyCdhashes);
        }
        let unique = allowed_cdhashes.iter().collect::<BTreeSet<_>>();
        if unique.len() != allowed_cdhashes.len() {
            return Err(InstallMaterialError::DuplicateCdhash);
        }
        Ok(Self {
            team_id,
            app_signing_identifier,
            allowed_cdhashes,
        })
    }

    pub fn policy_json(&self) -> Result<Vec<u8>, InstallMaterialError> {
        let mut bytes = serde_json::to_vec(&StoredAppPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            team_id: &self.team_id,
            app_signing_identifier: &self.app_signing_identifier,
            allowed_cdhashes: &self.allowed_cdhashes,
        })
        .map_err(|_| InstallMaterialError::Serialization)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn allowed_cdhashes(&self) -> &[String] {
        &self.allowed_cdhashes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStep {
    ValidateBundleLayout,
    ValidateAppAndHelperSignatures,
    ValidateEngineAsset,
    CapturePreviousGeneration,
    CapturePreviousEngineAsset,
    RegisterMontereyHelper,
    UnregisterModernHelperAndWait,
    RegisterModernHelper,
    VerifyHelperIdentity,
    VerifyBootstrapXpcHandshake,
    PrepareGenerationViaBootstrap,
    ReconnectWithGenerationPolicy,
    VerifyXpcHandshake,
    CommitBootstrapGeneration,
    CommitGeneration,
    RestorePreviousGeneration,
    RestorePreviousEngineAsset,
    RequestNetworkRecovery,
    VerifyNetworkRestored,
    UnregisterMontereyHelperAndWait,
    RemoveRootPolicyViaHelper,
    RemoveEngineAssetViaHelper,
    VerifyNoSystemResidue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallTransaction {
    steps: &'static [InstallStep],
    rollback: &'static [InstallStep],
}

const MONTEREY_INSTALL: &[InstallStep] = &[
    InstallStep::ValidateBundleLayout,
    InstallStep::ValidateAppAndHelperSignatures,
    InstallStep::ValidateEngineAsset,
    InstallStep::CapturePreviousGeneration,
    InstallStep::CapturePreviousEngineAsset,
    InstallStep::RegisterMontereyHelper,
    InstallStep::VerifyHelperIdentity,
    InstallStep::VerifyBootstrapXpcHandshake,
    InstallStep::PrepareGenerationViaBootstrap,
    InstallStep::ReconnectWithGenerationPolicy,
    InstallStep::VerifyXpcHandshake,
    InstallStep::CommitBootstrapGeneration,
    InstallStep::CommitGeneration,
];
const MODERN_INSTALL: &[InstallStep] = &[
    InstallStep::ValidateBundleLayout,
    InstallStep::ValidateAppAndHelperSignatures,
    InstallStep::ValidateEngineAsset,
    InstallStep::CapturePreviousGeneration,
    InstallStep::CapturePreviousEngineAsset,
    InstallStep::UnregisterModernHelperAndWait,
    InstallStep::RegisterModernHelper,
    InstallStep::VerifyHelperIdentity,
    InstallStep::VerifyBootstrapXpcHandshake,
    InstallStep::PrepareGenerationViaBootstrap,
    InstallStep::ReconnectWithGenerationPolicy,
    InstallStep::VerifyXpcHandshake,
    InstallStep::CommitBootstrapGeneration,
    InstallStep::CommitGeneration,
];
const INSTALL_ROLLBACK: &[InstallStep] = &[
    InstallStep::RequestNetworkRecovery,
    InstallStep::VerifyNetworkRestored,
    InstallStep::RestorePreviousGeneration,
    InstallStep::RestorePreviousEngineAsset,
];
const MONTEREY_UNINSTALL: &[InstallStep] = &[
    InstallStep::RequestNetworkRecovery,
    InstallStep::VerifyNetworkRestored,
    InstallStep::RemoveEngineAssetViaHelper,
    InstallStep::RemoveRootPolicyViaHelper,
    InstallStep::UnregisterMontereyHelperAndWait,
    InstallStep::VerifyNoSystemResidue,
];
const MODERN_UNINSTALL: &[InstallStep] = &[
    InstallStep::RequestNetworkRecovery,
    InstallStep::VerifyNetworkRestored,
    InstallStep::RemoveEngineAssetViaHelper,
    InstallStep::RemoveRootPolicyViaHelper,
    InstallStep::UnregisterModernHelperAndWait,
    InstallStep::VerifyNoSystemResidue,
];

impl InstallTransaction {
    pub const fn install_or_upgrade(kind: InstallerKind) -> Self {
        Self {
            steps: match kind {
                InstallerKind::SmJobBless => MONTEREY_INSTALL,
                InstallerKind::SmAppService => MODERN_INSTALL,
            },
            rollback: INSTALL_ROLLBACK,
        }
    }

    pub const fn uninstall(kind: InstallerKind) -> Self {
        Self {
            steps: match kind {
                InstallerKind::SmJobBless => MONTEREY_UNINSTALL,
                InstallerKind::SmAppService => MODERN_UNINSTALL,
            },
            rollback: &[],
        }
    }

    pub const fn steps(&self) -> &'static [InstallStep] {
        self.steps
    }

    pub const fn rollback(&self) -> &'static [InstallStep] {
        self.rollback
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_cdhash(value: &str) -> bool {
    value.len() == CDHASH_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "1111111111111111111111111111111111111111";
    const HASH_B: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn policy_material_is_exact_and_preserves_the_upgrade_window_order() {
        let material = SigningPolicyMaterial::new(
            "ABCDE12345",
            APP_BUNDLE_ID,
            [HASH_A.to_owned(), HASH_B.to_owned()],
        )
        .unwrap();
        assert_eq!(material.allowed_cdhashes(), [HASH_A, HASH_B]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&material.policy_json().unwrap()).unwrap(),
            serde_json::json!({
                "schemaVersion": 1,
                "teamId": "ABCDE12345",
                "appSigningIdentifier": "com.tunbridge.desktop",
                "allowedCdhashes": [HASH_A, HASH_B]
            })
        );
        assert_eq!(
            SYSTEM_POLICY_PATH,
            "/Library/PrivilegedHelperTools/com.tunbridge.desktop.helper.policy.json"
        );
    }

    #[test]
    fn malformed_duplicate_and_unbounded_generations_fail_closed() {
        assert_eq!(
            SigningPolicyMaterial::new("TEAM/../../", APP_BUNDLE_ID, [HASH_A.to_owned()]),
            Err(InstallMaterialError::InvalidTeamId)
        );
        assert_eq!(
            SigningPolicyMaterial::new("ABCDE12345", "com.attacker.desktop", [HASH_A.to_owned()]),
            Err(InstallMaterialError::InvalidAppIdentifier)
        );
        assert_eq!(
            SigningPolicyMaterial::new(
                "ABCDE12345",
                APP_BUNDLE_ID,
                [HASH_A.to_owned(), HASH_A.to_owned()]
            ),
            Err(InstallMaterialError::DuplicateCdhash)
        );
        assert_eq!(
            SigningPolicyMaterial::new(
                "ABCDE12345",
                APP_BUNDLE_ID,
                [
                    HASH_A.to_owned(),
                    HASH_B.to_owned(),
                    "3333333333333333333333333333333333333333".to_owned(),
                    "4444444444444444444444444444444444444444".to_owned(),
                    "5555555555555555555555555555555555555555".to_owned(),
                ]
            ),
            Err(InstallMaterialError::TooManyCdhashes)
        );
    }

    #[test]
    fn monterey_and_modern_transactions_never_share_registration_apis() {
        let monterey = InstallTransaction::install_or_upgrade(InstallerKind::SmJobBless);
        assert!(monterey
            .steps()
            .contains(&InstallStep::RegisterMontereyHelper));
        assert!(!monterey
            .steps()
            .contains(&InstallStep::RegisterModernHelper));

        let modern = InstallTransaction::install_or_upgrade(InstallerKind::SmAppService);
        assert!(modern
            .steps()
            .contains(&InstallStep::UnregisterModernHelperAndWait));
        assert!(modern.steps().contains(&InstallStep::RegisterModernHelper));
        assert!(!modern
            .steps()
            .contains(&InstallStep::RegisterMontereyHelper));
    }

    #[test]
    fn uninstall_recovers_network_then_uses_helper_before_unregistering() {
        for kind in [InstallerKind::SmJobBless, InstallerKind::SmAppService] {
            let steps = InstallTransaction::uninstall(kind).steps();
            assert_eq!(steps[0], InstallStep::RequestNetworkRecovery);
            assert_eq!(steps[1], InstallStep::VerifyNetworkRestored);
            let remove_engine = steps
                .iter()
                .position(|step| *step == InstallStep::RemoveEngineAssetViaHelper)
                .unwrap();
            let remove_policy = steps
                .iter()
                .position(|step| *step == InstallStep::RemoveRootPolicyViaHelper)
                .unwrap();
            let unregister = steps
                .iter()
                .position(|step| {
                    matches!(
                        step,
                        InstallStep::UnregisterMontereyHelperAndWait
                            | InstallStep::UnregisterModernHelperAndWait
                    )
                })
                .unwrap();
            assert!(
                1 < remove_engine && remove_engine < remove_policy && remove_policy < unregister
            );
            assert_eq!(steps.last(), Some(&InstallStep::VerifyNoSystemResidue));
        }
    }

    #[test]
    fn engine_asset_is_validated_provisioned_and_rolled_back_with_generation() {
        for kind in [InstallerKind::SmJobBless, InstallerKind::SmAppService] {
            let transaction = InstallTransaction::install_or_upgrade(kind);
            let steps = transaction.steps();
            let validate = steps
                .iter()
                .position(|step| *step == InstallStep::ValidateEngineAsset)
                .unwrap();
            let capture = steps
                .iter()
                .position(|step| *step == InstallStep::CapturePreviousEngineAsset)
                .unwrap();
            let register = steps
                .iter()
                .position(|step| {
                    matches!(
                        step,
                        InstallStep::RegisterMontereyHelper | InstallStep::RegisterModernHelper
                    )
                })
                .unwrap();
            let bootstrap = steps
                .iter()
                .position(|step| *step == InstallStep::VerifyBootstrapXpcHandshake)
                .unwrap();
            let provision = steps
                .iter()
                .position(|step| *step == InstallStep::PrepareGenerationViaBootstrap)
                .unwrap();
            let reconnect = steps
                .iter()
                .position(|step| *step == InstallStep::ReconnectWithGenerationPolicy)
                .unwrap();
            let handshake = steps
                .iter()
                .position(|step| *step == InstallStep::VerifyXpcHandshake)
                .unwrap();
            let bootstrap_commit = steps
                .iter()
                .position(|step| *step == InstallStep::CommitBootstrapGeneration)
                .unwrap();
            let journal_commit = steps
                .iter()
                .position(|step| *step == InstallStep::CommitGeneration)
                .unwrap();
            assert!(
                validate < capture
                    && capture < register
                    && register < bootstrap
                    && bootstrap < provision
                    && provision < reconnect
                    && reconnect < handshake
                    && handshake < bootstrap_commit
                    && bootstrap_commit < journal_commit
            );
            assert_eq!(
                transaction.rollback(),
                [
                    InstallStep::RequestNetworkRecovery,
                    InstallStep::VerifyNetworkRestored,
                    InstallStep::RestorePreviousGeneration,
                    InstallStep::RestorePreviousEngineAsset,
                ]
            );
        }
    }
}
