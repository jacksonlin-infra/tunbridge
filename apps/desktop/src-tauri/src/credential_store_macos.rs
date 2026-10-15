use crate::{
    local_proxy::{MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES},
    profile_store::{credential_target, CredentialInput},
    profile_store_v2::{credential_target as credential_target_v2, SecretVaultV2Error},
};
use serde::{Deserialize, Serialize};
use tunbridge_core::upstream::SecretMaterialV2;
use tunbridge_desktop_contract::adapter::{AdapterErrorCode, CredentialStore};
use zeroize::{Zeroize, Zeroizing};

const MAX_SECRET_BYTES: usize = 1024;

// The v1 vault remains readable for profile migration; its write path is only
// exercised by native acceptance/tests now that production writes use v2.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVaultError {
    InvalidInput,
    AlreadyExists,
    NotFound,
    InvalidRecord,
    Unavailable,
}

#[allow(dead_code)]
pub trait CredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        input: &CredentialInput,
    ) -> Result<(), CredentialVaultError>;

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<VaultCredential, CredentialVaultError>;

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), CredentialVaultError>;
}

pub struct KeychainCredentialVault;

impl CredentialVault for KeychainCredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        input: &CredentialInput,
    ) -> Result<(), CredentialVaultError> {
        input
            .validate()
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        let account = account(profile_id, generation)?;
        let payload = SecretPayload {
            schema_version: 1,
            username: input.username.expose(),
            password: input.password.expose(),
        };
        let mut secret = Zeroizing::new(
            serde_json::to_vec(&payload).map_err(|_| CredentialVaultError::InvalidInput)?,
        );
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialVaultError::InvalidInput);
        }
        let result = tunbridge_platform_macos::MacosKeychain.write(&account, &secret);
        secret.zeroize();
        result.map_err(|error| {
            if error.code == AdapterErrorCode::InvalidData {
                CredentialVaultError::AlreadyExists
            } else {
                CredentialVaultError::Unavailable
            }
        })
    }

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<VaultCredential, CredentialVaultError> {
        let account = account(profile_id, generation)?;
        let secret = Zeroizing::new(
            tunbridge_platform_macos::MacosKeychain
                .read(&account)
                .map_err(|_| CredentialVaultError::Unavailable)?
                .ok_or(CredentialVaultError::NotFound)?,
        );
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialVaultError::InvalidRecord);
        }
        let payload: OwnedSecretPayload =
            serde_json::from_slice(&secret).map_err(|_| CredentialVaultError::InvalidRecord)?;
        payload.validate()?;
        Ok(VaultCredential {
            username: Zeroizing::new(payload.username),
            password: Zeroizing::new(payload.password),
        })
    }

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), CredentialVaultError> {
        let account = account(profile_id, generation)?;
        tunbridge_platform_macos::MacosKeychain
            .delete(&account)
            .map_err(|_| CredentialVaultError::Unavailable)
    }
}

impl crate::profile_store_v2::SecretVaultV2 for KeychainCredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        material: &SecretMaterialV2,
    ) -> Result<(), SecretVaultV2Error> {
        material
            .validate()
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        let account = account_v2(profile_id, generation)?;
        match <Self as crate::profile_store_v2::SecretVaultV2>::read(self, profile_id, generation) {
            Ok(_) => return Err(SecretVaultV2Error::AlreadyExists),
            Err(SecretVaultV2Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        let mut secret = Zeroizing::new(
            serde_json::to_vec(material).map_err(|_| SecretVaultV2Error::InvalidInput)?,
        );
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SecretVaultV2Error::InvalidInput);
        }
        let result = tunbridge_platform_macos::MacosKeychain.write(&account, &secret);
        secret.zeroize();
        result.map_err(|error| {
            if error.code == AdapterErrorCode::InvalidData {
                SecretVaultV2Error::AlreadyExists
            } else {
                SecretVaultV2Error::Unavailable
            }
        })
    }

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<SecretMaterialV2, SecretVaultV2Error> {
        let account = account_v2(profile_id, generation)?;
        let secret = Zeroizing::new(
            tunbridge_platform_macos::MacosKeychain
                .read(&account)
                .map_err(|_| SecretVaultV2Error::Unavailable)?
                .ok_or(SecretVaultV2Error::NotFound)?,
        );
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SecretVaultV2Error::InvalidRecord);
        }
        let material: SecretMaterialV2 =
            serde_json::from_slice(&secret).map_err(|_| SecretVaultV2Error::InvalidRecord)?;
        material
            .validate()
            .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
        Ok(material)
    }

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), SecretVaultV2Error> {
        let account = account_v2(profile_id, generation)?;
        tunbridge_platform_macos::MacosKeychain
            .delete(&account)
            .map_err(|_| SecretVaultV2Error::Unavailable)
    }
}

pub struct VaultCredential {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl VaultCredential {
    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut *self.username),
            std::mem::take(&mut *self.password),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(username: String, password: String) -> Self {
        Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        }
    }
}

impl std::fmt::Debug for VaultCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultCredential([REDACTED])")
    }
}

#[allow(dead_code)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretPayload<'a> {
    schema_version: u16,
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedSecretPayload {
    schema_version: u16,
    username: String,
    password: String,
}

impl OwnedSecretPayload {
    fn validate(&self) -> Result<(), CredentialVaultError> {
        if self.schema_version == 1
            && valid_secret(&self.username, MAX_USERNAME_BYTES)
            && valid_secret(&self.password, MAX_PASSWORD_BYTES)
        {
            Ok(())
        } else {
            Err(CredentialVaultError::InvalidRecord)
        }
    }
}

fn account(profile_id: &str, generation: &str) -> Result<String, CredentialVaultError> {
    credential_target(profile_id, generation).map_err(|_| CredentialVaultError::InvalidInput)
}

fn account_v2(profile_id: &str, generation: &str) -> Result<String, SecretVaultV2Error> {
    credential_target_v2(profile_id, generation).map_err(|_| SecretVaultV2Error::InvalidInput)
}

fn valid_secret(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(|character| character.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_proxy::SecretText;

    #[test]
    #[ignore = "requires an unlocked macOS login Keychain; run as an explicit native acceptance test"]
    fn keychain_round_trip_uses_exact_random_account_and_cleans_up() {
        let profile_id = format!("{:032x}", std::process::id());
        let generation = format!(
            "{:032x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let vault = KeychainCredentialVault;
        let input = CredentialInput {
            username: SecretText::from_owned("macos-test-user".to_owned()),
            password: SecretText::from_owned("macos-test-password".to_owned()),
        };
        vault.delete_exact(&profile_id, &generation).unwrap();
        vault.write_new(&profile_id, &generation, &input).unwrap();
        assert_eq!(
            vault.write_new(&profile_id, &generation, &input),
            Err(CredentialVaultError::AlreadyExists)
        );
        let (username, password) = vault.read(&profile_id, &generation).unwrap().into_parts();
        assert_eq!(username, "macos-test-user");
        assert_eq!(password, "macos-test-password");
        vault.delete_exact(&profile_id, &generation).unwrap();
        assert!(matches!(
            vault.read(&profile_id, &generation),
            Err(CredentialVaultError::NotFound)
        ));
    }

    #[test]
    fn keychain_errors_and_debug_output_are_redacted() {
        assert_eq!(
            account("bad/profile", "generation"),
            Err(CredentialVaultError::InvalidInput)
        );
        let credential = VaultCredential::new_for_test("user".into(), "password".into());
        assert_eq!(format!("{credential:?}"), "VaultCredential([REDACTED])");
    }
}
