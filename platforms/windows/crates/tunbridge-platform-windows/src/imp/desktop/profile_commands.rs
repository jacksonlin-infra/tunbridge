use crate::{
    local_proxy::{
        failed_test_response, DesktopProxyProtocol, ProbeFailure, SecretText, TestInput,
        TestResponse,
    },
    local_proxy_platform,
    profile_store_files_windows::{ProfileCoordinatorError, ProtectedStoreError},
    profile_store_v2::{
        CreateProfileInput, DeleteProfileInput, ProfileList, ProfileStoreError, UpdateProfileInput,
    },
    profile_store_v2_windows::{ProfileCoordinatorV2Error, ProfileCoordinatorV2Windows},
    profile_store_windows::{CredentialVault, CredentialVaultError},
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
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(map_coordinator_v2)?;
    files.list(&CredentialVault).map_err(map_coordinator_v2)
}

pub fn create_profile(input: CreateProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(map_coordinator_v2)?;
    files
        .create_generated(&CredentialVault, input)
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn update_profile(input: UpdateProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(map_coordinator_v2)?;
    files
        .update_generated(&CredentialVault, input)
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn delete_profile(input: DeleteProfileInput) -> Result<ProfileList, ProfileCommandError> {
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(map_coordinator_v2)?;
    files
        .delete(&CredentialVault, input)
        .map(|store| store.public_view())
        .map_err(map_coordinator_v2)
}

pub fn test_saved_profile(
    input: TestSavedProfileInput,
) -> Result<TestResponse, ProfileCommandError> {
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(map_coordinator_v2)?;
    let saved = files
        .load_saved(
            &CredentialVault,
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
        ProfileCoordinatorV2Error::Legacy(error) => map_coordinator(error),
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
        CredentialVaultError::AlreadyExists | CredentialVaultError::SystemFailure => {
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

pub(crate) fn map_coordinator(error: ProfileCoordinatorError) -> ProfileCommandError {
    match error {
        ProfileCoordinatorError::Storage(error) => map_storage(error),
        ProfileCoordinatorError::Vault(error) => match error {
            CredentialVaultError::InvalidInput => ProfileCommandErrorCode::InvalidInput.into(),
            CredentialVaultError::NotFound | CredentialVaultError::InvalidRecord => {
                ProfileCommandErrorCode::CredentialUnavailable.into()
            }
            CredentialVaultError::AlreadyExists | CredentialVaultError::SystemFailure => {
                ProfileCommandErrorCode::InternalError.into()
            }
        },
        ProfileCoordinatorError::Model(error) => match error {
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
        },
        ProfileCoordinatorError::Interrupted => ProfileCommandErrorCode::InternalError.into(),
    }
}

fn map_storage(error: ProtectedStoreError) -> ProfileCommandError {
    match error {
        ProtectedStoreError::Busy => ProfileCommandErrorCode::Busy.into(),
        ProtectedStoreError::NotFound | ProtectedStoreError::InvalidData => {
            ProfileCommandErrorCode::StorageUntrusted.into()
        }
        ProtectedStoreError::UntrustedStorage => ProfileCommandErrorCode::StorageUntrusted.into(),
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
            assert!(!json.contains("C:\\"));
            assert!(!json.contains("S-1-5-"));
            assert!(!json.contains("TunBridge.Desktop.Upstream"));
        }
    }

    #[test]
    fn saved_test_input_schema_is_strict() {
        let valid = serde_json::json!({
            "profileId": "00112233445566778899aabbccddeeff",
            "expectedStoreRevision": 1
        });
        serde_json::from_value::<TestSavedProfileInput>(valid.clone()).unwrap();
        let mut unknown = valid;
        unknown["path"] = serde_json::json!("C:\\private");
        assert!(serde_json::from_value::<TestSavedProfileInput>(unknown).is_err());
    }
}
