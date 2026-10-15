#[cfg(target_os = "macos")]
use crate::credential_store::KeychainCredentialVault as PlatformCredentialVault;
#[cfg(target_os = "linux")]
use crate::credential_store::SecretServiceCredentialVault as PlatformCredentialVault;
use crate::{
    credential_store::CredentialVaultError,
    local_proxy::{
        failed_test_response, DesktopProxyProtocol, ProbeFailure, SecretText, TestInput,
        TestResponse,
    },
    local_proxy_platform,
    profile_store_unix::{ProfileCoordinator as LegacyProfileCoordinator, ProtectedStoreError},
    profile_store_v2::{
        CreateProfileInput, DeleteProfileInput, ProfileList, ProfileStoreError, UpdateProfileInput,
    },
    profile_store_v2_unix::{ProfileCoordinatorV2, ProfileCoordinatorV2Error},
};
use serde::{Deserialize, Serialize};
use tunbridge_core::{profile_v2::StoredUpstreamV2, upstream::StandardProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCommandErrorCode {
    InvalidInput,
    Busy,
    ActiveProfileLocked,
    StaleRevision,
    NotFound,
    LimitReached,
    StorageUntrusted,
    CredentialUnavailable,
    TransactionUnknown,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCommandError {
    pub code: ProfileCommandErrorCode,
    pub safe_message: &'static str,
}

impl From<ProfileCommandErrorCode> for ProfileCommandError {
    fn from(code: ProfileCommandErrorCode) -> Self {
        let safe_message = match code {
            ProfileCommandErrorCode::InvalidInput => "The profile input is invalid.",
            ProfileCommandErrorCode::Busy => "Another desktop operation is already active.",
            ProfileCommandErrorCode::ActiveProfileLocked => {
                "The active profile cannot be edited or deleted while System TUN is running."
            }
            ProfileCommandErrorCode::StaleRevision => {
                "The profile list changed. Refresh and try again."
            }
            ProfileCommandErrorCode::NotFound => "The selected profile was not found.",
            ProfileCommandErrorCode::LimitReached => "The profile limit has been reached.",
            ProfileCommandErrorCode::StorageUntrusted => {
                "The profile storage security check failed."
            }
            ProfileCommandErrorCode::CredentialUnavailable => {
                "The saved credential is unavailable or invalid."
            }
            ProfileCommandErrorCode::TransactionUnknown => {
                "The profile transaction could not be safely reconciled."
            }
            ProfileCommandErrorCode::InternalError => "The profile operation failed safely.",
        };
        Self { code, safe_message }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestSavedProfileInput {
    pub profile_id: String,
    pub expected_store_revision: u64,
}

pub fn busy_error() -> ProfileCommandError {
    ProfileCommandErrorCode::Busy.into()
}

pub fn active_profile_locked_error() -> ProfileCommandError {
    ProfileCommandErrorCode::ActiveProfileLocked.into()
}

pub fn internal_error() -> ProfileCommandError {
    ProfileCommandErrorCode::InternalError.into()
}

pub fn list_profiles() -> Result<ProfileList, ProfileCommandError> {
    let legacy = LegacyProfileCoordinator::prepare_production().map_err(map_storage)?;
    let files = ProfileCoordinatorV2::prepare_production().map_err(map_storage)?;
    files
        .list(&legacy, &PlatformCredentialVault, &PlatformCredentialVault)
        .map_err(map_coordinator_v2)
}

pub fn create_profile(input: CreateProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let legacy = LegacyProfileCoordinator::prepare_production().map_err(map_storage)?;
    let files = ProfileCoordinatorV2::prepare_production().map_err(map_storage)?;
    files
        .create_generated(
            &legacy,
            &PlatformCredentialVault,
            &PlatformCredentialVault,
            input,
        )
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn update_profile(input: UpdateProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let legacy = LegacyProfileCoordinator::prepare_production().map_err(map_storage)?;
    let files = ProfileCoordinatorV2::prepare_production().map_err(map_storage)?;
    files
        .update_generated(
            &legacy,
            &PlatformCredentialVault,
            &PlatformCredentialVault,
            input,
        )
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn delete_profile(input: DeleteProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let legacy = LegacyProfileCoordinator::prepare_production().map_err(map_storage)?;
    let files = ProfileCoordinatorV2::prepare_production().map_err(map_storage)?;
    files
        .delete(
            &legacy,
            &PlatformCredentialVault,
            &PlatformCredentialVault,
            input,
        )
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn test_saved_profile(
    input: TestSavedProfileInput,
) -> Result<TestResponse, ProfileCommandError> {
    let legacy = LegacyProfileCoordinator::prepare_production().map_err(map_storage)?;
    let files = ProfileCoordinatorV2::prepare_production().map_err(map_storage)?;
    let saved = files
        .load_saved(
            &legacy,
            &PlatformCredentialVault,
            &PlatformCredentialVault,
            &input.profile_id,
            input.expected_store_revision,
        )
        .map_err(map_coordinator_v2)?;
    match saved.profile.upstream {
        StoredUpstreamV2::LocalListener { port, protocol, .. } => {
            if !local_proxy_platform::local_listener_identity_available(port) {
                return Ok(failed_test_response(ProbeFailure::ConnectFailed));
            }
            let (username, password) = saved
                .secret_material
                .map(|secret| secret.material.into_basic_auth())
                .map_or((None, None), |(username, password)| {
                    (
                        Some(SecretText::from_owned(username)),
                        Some(SecretText::from_owned(password)),
                    )
                });
            local_proxy_platform::test_local_proxy(TestInput {
                port,
                protocol: match protocol {
                    StandardProtocol::Socks5 => DesktopProxyProtocol::Socks5,
                    StandardProtocol::Http => DesktopProxyProtocol::Http,
                },
                username,
                password,
            })
            .map_err(|_| internal_error())
        }
        StoredUpstreamV2::RemoteServer {
            endpoint,
            protocol_config,
            ..
        } => crate::local_proxy::test_remote_profile(
            &endpoint,
            &protocol_config,
            saved.secret_material.as_ref(),
        )
        .map_err(|_| internal_error()),
    }
}

fn map_coordinator_v2(error: ProfileCoordinatorV2Error) -> ProfileCommandError {
    match error {
        ProfileCoordinatorV2Error::Storage(error) => map_storage(error),
        ProfileCoordinatorV2Error::Legacy(error) => match error {
            crate::profile_store_unix::ProfileCoordinatorError::Storage(error) => {
                map_storage(error)
            }
            crate::profile_store_unix::ProfileCoordinatorError::Vault(error) => {
                map_legacy_vault(error)
            }
            crate::profile_store_unix::ProfileCoordinatorError::Model(error) => {
                map_legacy_model(error)
            }
        },
        ProfileCoordinatorV2Error::LegacyVault(error) => map_legacy_vault(error),
        ProfileCoordinatorV2Error::Vault(error) => match error {
            crate::profile_store_v2::SecretVaultV2Error::InvalidInput => {
                ProfileCommandErrorCode::InvalidInput.into()
            }
            crate::profile_store_v2::SecretVaultV2Error::NotFound
            | crate::profile_store_v2::SecretVaultV2Error::InvalidRecord => {
                ProfileCommandErrorCode::CredentialUnavailable.into()
            }
            crate::profile_store_v2::SecretVaultV2Error::AlreadyExists
            | crate::profile_store_v2::SecretVaultV2Error::Unavailable => {
                ProfileCommandErrorCode::InternalError.into()
            }
        },
        ProfileCoordinatorV2Error::Model(error) => map_v2_model(error),
    }
}

fn map_legacy_vault(error: CredentialVaultError) -> ProfileCommandError {
    match error {
        CredentialVaultError::InvalidInput => ProfileCommandErrorCode::InvalidInput.into(),
        CredentialVaultError::NotFound | CredentialVaultError::InvalidRecord => {
            ProfileCommandErrorCode::CredentialUnavailable.into()
        }
        CredentialVaultError::AlreadyExists | CredentialVaultError::Unavailable => {
            ProfileCommandErrorCode::InternalError.into()
        }
    }
}

fn map_v2_model(error: ProfileStoreError) -> ProfileCommandError {
    match error {
        ProfileStoreError::InvalidInput | ProfileStoreError::IdCollision => {
            ProfileCommandErrorCode::InvalidInput.into()
        }
        ProfileStoreError::StaleRevision => ProfileCommandErrorCode::StaleRevision.into(),
        ProfileStoreError::NotFound => ProfileCommandErrorCode::NotFound.into(),
        ProfileStoreError::LimitReached => ProfileCommandErrorCode::LimitReached.into(),
        ProfileStoreError::TransactionUnknown => ProfileCommandErrorCode::TransactionUnknown.into(),
        ProfileStoreError::InvalidStore | ProfileStoreError::InvalidTransaction => {
            ProfileCommandErrorCode::StorageUntrusted.into()
        }
        ProfileStoreError::RevisionOverflow => ProfileCommandErrorCode::InternalError.into(),
    }
}

fn map_legacy_model(error: crate::profile_store::ProfileStoreError) -> ProfileCommandError {
    match error {
        crate::profile_store::ProfileStoreError::InvalidInput
        | crate::profile_store::ProfileStoreError::IdCollision => {
            ProfileCommandErrorCode::InvalidInput.into()
        }
        crate::profile_store::ProfileStoreError::StaleRevision => {
            ProfileCommandErrorCode::StaleRevision.into()
        }
        crate::profile_store::ProfileStoreError::NotFound => {
            ProfileCommandErrorCode::NotFound.into()
        }
        crate::profile_store::ProfileStoreError::LimitReached => {
            ProfileCommandErrorCode::LimitReached.into()
        }
        crate::profile_store::ProfileStoreError::TransactionUnknown => {
            ProfileCommandErrorCode::TransactionUnknown.into()
        }
        crate::profile_store::ProfileStoreError::InvalidStore
        | crate::profile_store::ProfileStoreError::InvalidTransaction => {
            ProfileCommandErrorCode::StorageUntrusted.into()
        }
        crate::profile_store::ProfileStoreError::RevisionOverflow => {
            ProfileCommandErrorCode::InternalError.into()
        }
    }
}

fn map_storage(error: ProtectedStoreError) -> ProfileCommandError {
    match error {
        ProtectedStoreError::Busy => ProfileCommandErrorCode::Busy.into(),
        ProtectedStoreError::UntrustedStorage | ProtectedStoreError::InvalidData => {
            ProfileCommandErrorCode::StorageUntrusted.into()
        }
        ProtectedStoreError::SystemFailure => ProfileCommandErrorCode::InternalError.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_error_messages_are_fixed_and_redacted() {
        for code in [
            ProfileCommandErrorCode::InvalidInput,
            ProfileCommandErrorCode::Busy,
            ProfileCommandErrorCode::ActiveProfileLocked,
            ProfileCommandErrorCode::StaleRevision,
            ProfileCommandErrorCode::NotFound,
            ProfileCommandErrorCode::LimitReached,
            ProfileCommandErrorCode::StorageUntrusted,
            ProfileCommandErrorCode::CredentialUnavailable,
            ProfileCommandErrorCode::TransactionUnknown,
            ProfileCommandErrorCode::InternalError,
        ] {
            let json = serde_json::to_string(&ProfileCommandError::from(code)).unwrap();
            assert!(!json.contains("/home/"));
            assert!(!json.contains("TunBridge.Desktop.Upstream"));
        }
    }
}
