use crate::local_proxy::{
    DesktopProxyProtocol, SecretText, MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const PROFILE_SCHEMA_VERSION: u16 = 1;
pub const TRANSACTION_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROFILES: usize = 64;
pub const MAX_PROFILE_STORE_BYTES: usize = 64 * 1024;
pub const MAX_TRANSACTION_BYTES: usize = 8 * 1024;
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;
pub const IDENTIFIER_HEX_BYTES: usize = 32;
pub const DIGEST_HEX_BYTES: usize = 64;
pub const CREDENTIAL_TARGET_PREFIX: &str = "TunBridge.Desktop.Upstream/v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileStore {
    pub schema_version: u16,
    pub store_revision: u64,
    pub profiles: Vec<StoredProfile>,
}

impl fmt::Debug for ProfileStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStore")
            .field("schema_version", &self.schema_version)
            .field("store_revision", &self.store_revision)
            .field("profile_count", &self.profiles.len())
            .finish()
    }
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            store_revision: 0,
            profiles: Vec::new(),
        }
    }
}

impl ProfileStore {
    pub fn validate(&self) -> Result<(), ProfileStoreError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION || self.profiles.len() > MAX_PROFILES {
            return Err(ProfileStoreError::InvalidStore);
        }

        let mut previous_id: Option<&str> = None;
        for profile in &self.profiles {
            profile.validate()?;
            if previous_id.is_some_and(|previous| previous >= profile.profile_id.as_str()) {
                return Err(ProfileStoreError::InvalidStore);
            }
            previous_id = Some(&profile.profile_id);
        }

        if canonical_store_bytes(self)?.len() > MAX_PROFILE_STORE_BYTES {
            return Err(ProfileStoreError::InvalidStore);
        }
        Ok(())
    }

    pub fn public_view(&self) -> ProfileList {
        ProfileList {
            schema_version: PROFILE_SCHEMA_VERSION,
            store_revision: self.store_revision,
            profiles: self
                .profiles
                .iter()
                .map(|profile| PublicProfile {
                    profile_id: profile.profile_id.clone(),
                    display_name: profile.display_name.clone(),
                    port: profile.port,
                    protocol: profile.protocol,
                    has_credential: profile.credential_generation.is_some(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredProfile {
    pub profile_id: String,
    pub display_name: String,
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    pub credential_generation: Option<String>,
}

impl fmt::Debug for StoredProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredProfile")
            .field("display_name", &self.display_name)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("has_credential", &self.credential_generation.is_some())
            .finish()
    }
}

impl StoredProfile {
    fn validate(&self) -> Result<(), ProfileStoreError> {
        if !valid_identifier(&self.profile_id)
            || !valid_display_name(&self.display_name)
            || self.port == 0
            || self
                .credential_generation
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(ProfileStoreError::InvalidStore);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileList {
    pub schema_version: u16,
    pub store_revision: u64,
    pub profiles: Vec<PublicProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfile {
    pub profile_id: String,
    pub display_name: String,
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    pub has_credential: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialInput {
    pub username: SecretText,
    pub password: SecretText,
}

impl fmt::Debug for CredentialInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialInput")
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

impl CredentialInput {
    pub(crate) fn validate(&self) -> Result<(), ProfileStoreError> {
        if !valid_credential(self.username.expose(), MAX_USERNAME_BYTES)
            || !valid_credential(self.password.expose(), MAX_PASSWORD_BYTES)
        {
            return Err(ProfileStoreError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateProfileInput {
    pub expected_store_revision: u64,
    pub display_name: String,
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    pub credential: Option<CredentialInput>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialAction {
    Keep,
    Remove,
    Replace {
        username: SecretText,
        password: SecretText,
    },
}

impl CredentialAction {
    fn into_replacement(self) -> Result<CredentialChange, ProfileStoreError> {
        match self {
            Self::Keep => Ok(CredentialChange::Keep),
            Self::Remove => Ok(CredentialChange::Remove),
            Self::Replace { username, password } => {
                let input = CredentialInput { username, password };
                input.validate()?;
                Ok(CredentialChange::Replace(input))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateProfileInput {
    pub expected_store_revision: u64,
    pub profile_id: String,
    pub display_name: String,
    pub port: u16,
    pub protocol: DesktopProxyProtocol,
    pub credential_action: CredentialAction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteProfileInput {
    pub expected_store_revision: u64,
    pub profile_id: String,
}

#[derive(Debug)]
enum CredentialChange {
    Keep,
    Remove,
    Replace(CredentialInput),
}

pub struct PendingCredential {
    pub target: String,
    pub credential: CredentialInput,
}

impl fmt::Debug for PendingCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingCredential")
            .field("target", &"[REDACTED]")
            .field("credential", &self.credential)
            .finish()
    }
}

pub struct MutationPlan {
    pub new_store: ProfileStore,
    pub journal: Option<ProfileTransaction>,
    pub write_credential: Option<PendingCredential>,
    pub post_publish_delete_target: Option<String>,
}

impl fmt::Debug for MutationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationPlan")
            .field("new_store", &self.new_store)
            .field("has_journal", &self.journal.is_some())
            .field("write_credential", &self.write_credential)
            .field(
                "post_publish_delete_target",
                &self
                    .post_publish_delete_target
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOperation {
    Create,
    Update,
    Delete,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileTransaction {
    pub schema_version: u16,
    pub operation: ProfileOperation,
    pub profile_id: String,
    pub base_revision: u64,
    pub next_revision: u64,
    pub old_credential_generation: Option<String>,
    pub new_credential_generation: Option<String>,
    pub old_store_sha256: String,
    pub new_store_sha256: String,
}

impl fmt::Debug for ProfileTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileTransaction")
            .field("schema_version", &self.schema_version)
            .field("operation", &self.operation)
            .field("base_revision", &self.base_revision)
            .field("next_revision", &self.next_revision)
            .field("identifiers", &"[REDACTED]")
            .finish()
    }
}

impl ProfileTransaction {
    pub fn validate(&self) -> Result<(), ProfileStoreError> {
        let generation_relation_valid = match self.operation {
            ProfileOperation::Create => {
                self.old_credential_generation.is_none() && self.new_credential_generation.is_some()
            }
            ProfileOperation::Update => {
                self.old_credential_generation != self.new_credential_generation
                    && (self.old_credential_generation.is_some()
                        || self.new_credential_generation.is_some())
            }
            ProfileOperation::Delete => {
                self.old_credential_generation.is_some() && self.new_credential_generation.is_none()
            }
        };
        if self.schema_version != TRANSACTION_SCHEMA_VERSION
            || !valid_identifier(&self.profile_id)
            || self.base_revision.checked_add(1) != Some(self.next_revision)
            || self
                .old_credential_generation
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || self
                .new_credential_generation
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_lower_hex(&self.old_store_sha256, DIGEST_HEX_BYTES)
            || !valid_lower_hex(&self.new_store_sha256, DIGEST_HEX_BYTES)
            || self.old_store_sha256 == self.new_store_sha256
            || !generation_relation_valid
        {
            return Err(ProfileStoreError::InvalidTransaction);
        }
        if serde_json::to_vec(self)
            .map_err(|_| ProfileStoreError::InvalidTransaction)?
            .len()
            > MAX_TRANSACTION_BYTES
        {
            return Err(ProfileStoreError::InvalidTransaction);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileDisposition {
    RollBack,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub disposition: ReconcileDisposition,
    pub delete_target: Option<String>,
    pub clear_journal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileStoreError {
    InvalidStore,
    InvalidTransaction,
    InvalidInput,
    StaleRevision,
    NotFound,
    LimitReached,
    RevisionOverflow,
    IdCollision,
    TransactionUnknown,
}

pub fn parse_store(bytes: &[u8]) -> Result<ProfileStore, ProfileStoreError> {
    if bytes.len() > MAX_PROFILE_STORE_BYTES {
        return Err(ProfileStoreError::InvalidStore);
    }
    let store: ProfileStore =
        serde_json::from_slice(bytes).map_err(|_| ProfileStoreError::InvalidStore)?;
    store.validate()?;
    Ok(store)
}

pub fn parse_transaction(bytes: &[u8]) -> Result<ProfileTransaction, ProfileStoreError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(ProfileStoreError::InvalidTransaction);
    }
    let transaction: ProfileTransaction =
        serde_json::from_slice(bytes).map_err(|_| ProfileStoreError::InvalidTransaction)?;
    transaction.validate()?;
    Ok(transaction)
}

pub fn canonical_store_bytes(store: &ProfileStore) -> Result<Vec<u8>, ProfileStoreError> {
    serde_json::to_vec(store).map_err(|_| ProfileStoreError::InvalidStore)
}

pub fn create_profile(
    current: Option<&ProfileStore>,
    input: CreateProfileInput,
    profile_id: String,
    credential_generation: Option<String>,
) -> Result<MutationPlan, ProfileStoreError> {
    let empty_store = ProfileStore::default();
    let working_store = current.unwrap_or(&empty_store);
    if let Some(current) = current {
        current.validate()?;
    }
    expect_revision(working_store, input.expected_store_revision)?;
    validate_profile_fields(&profile_id, &input.display_name, input.port)?;
    if working_store.profiles.len() >= MAX_PROFILES {
        return Err(ProfileStoreError::LimitReached);
    }
    if working_store
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&profile_id))
        .is_ok()
    {
        return Err(ProfileStoreError::IdCollision);
    }

    let (generation, pending) = match (input.credential, credential_generation) {
        (None, None) => (None, None),
        (Some(credential), Some(generation)) if valid_identifier(&generation) => {
            credential.validate()?;
            let target = credential_target(&profile_id, &generation)?;
            (
                Some(generation),
                Some(PendingCredential { target, credential }),
            )
        }
        _ => return Err(ProfileStoreError::InvalidInput),
    };

    let next_revision = next_revision(working_store)?;
    let mut new_store = working_store.clone();
    new_store.store_revision = next_revision;
    let insert_at = new_store
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&profile_id))
        .unwrap_err();
    new_store.profiles.insert(
        insert_at,
        StoredProfile {
            profile_id: profile_id.clone(),
            display_name: normalize_display_name(input.display_name)?,
            port: input.port,
            protocol: input.protocol,
            credential_generation: generation.clone(),
        },
    );
    new_store.validate()?;

    let journal = generation.map(|new_generation| {
        build_transaction(
            ProfileOperation::Create,
            &profile_id,
            current,
            &new_store,
            None,
            Some(new_generation),
        )
    });
    Ok(MutationPlan {
        new_store,
        journal: transpose_transaction(journal)?,
        write_credential: pending,
        post_publish_delete_target: None,
    })
}

pub fn update_profile(
    current: &ProfileStore,
    input: UpdateProfileInput,
    replacement_generation: Option<String>,
) -> Result<MutationPlan, ProfileStoreError> {
    current.validate()?;
    expect_revision(current, input.expected_store_revision)?;
    validate_profile_fields(&input.profile_id, &input.display_name, input.port)?;
    let index = current
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&input.profile_id))
        .map_err(|_| ProfileStoreError::NotFound)?;
    let old_generation = current.profiles[index].credential_generation.clone();
    let change = input.credential_action.into_replacement()?;

    let (new_generation, pending) = match (change, replacement_generation) {
        (CredentialChange::Keep, None) => (old_generation.clone(), None),
        (CredentialChange::Remove, None) => (None, None),
        (CredentialChange::Replace(credential), Some(generation))
            if valid_identifier(&generation) && Some(&generation) != old_generation.as_ref() =>
        {
            let target = credential_target(&input.profile_id, &generation)?;
            (
                Some(generation),
                Some(PendingCredential { target, credential }),
            )
        }
        _ => return Err(ProfileStoreError::InvalidInput),
    };

    let next_revision = next_revision(current)?;
    let mut new_store = current.clone();
    new_store.store_revision = next_revision;
    new_store.profiles[index] = StoredProfile {
        profile_id: input.profile_id.clone(),
        display_name: normalize_display_name(input.display_name)?,
        port: input.port,
        protocol: input.protocol,
        credential_generation: new_generation.clone(),
    };
    new_store.validate()?;

    let credential_changed = old_generation != new_generation;
    let journal = credential_changed.then(|| {
        build_transaction(
            ProfileOperation::Update,
            &input.profile_id,
            Some(current),
            &new_store,
            old_generation.clone(),
            new_generation,
        )
    });
    let post_publish_delete_target = if credential_changed {
        old_generation
            .as_deref()
            .map(|generation| credential_target(&input.profile_id, generation))
            .transpose()?
    } else {
        None
    };

    Ok(MutationPlan {
        new_store,
        journal: transpose_transaction(journal)?,
        write_credential: pending,
        post_publish_delete_target,
    })
}

pub fn delete_profile(
    current: &ProfileStore,
    input: DeleteProfileInput,
) -> Result<MutationPlan, ProfileStoreError> {
    current.validate()?;
    expect_revision(current, input.expected_store_revision)?;
    if !valid_identifier(&input.profile_id) {
        return Err(ProfileStoreError::InvalidInput);
    }
    let index = current
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&input.profile_id))
        .map_err(|_| ProfileStoreError::NotFound)?;
    let old_generation = current.profiles[index].credential_generation.clone();

    let mut new_store = current.clone();
    new_store.store_revision = next_revision(current)?;
    new_store.profiles.remove(index);
    new_store.validate()?;

    let journal = old_generation.clone().map(|old_generation| {
        build_transaction(
            ProfileOperation::Delete,
            &input.profile_id,
            Some(current),
            &new_store,
            Some(old_generation),
            None,
        )
    });
    let post_publish_delete_target = old_generation
        .as_deref()
        .map(|generation| credential_target(&input.profile_id, generation))
        .transpose()?;
    Ok(MutationPlan {
        new_store,
        journal: transpose_transaction(journal)?,
        write_credential: None,
        post_publish_delete_target,
    })
}

pub fn reconcile_transaction(
    transaction: &ProfileTransaction,
    current: Option<&ProfileStore>,
) -> Result<ReconcilePlan, ProfileStoreError> {
    transaction.validate()?;
    if let Some(store) = current {
        store.validate()?;
    }
    let digest = store_digest(current)?;
    let (disposition, generation) = if digest == transaction.old_store_sha256 {
        (
            ReconcileDisposition::RollBack,
            transaction.new_credential_generation.as_deref(),
        )
    } else if digest == transaction.new_store_sha256 {
        (
            ReconcileDisposition::Commit,
            transaction.old_credential_generation.as_deref(),
        )
    } else {
        return Err(ProfileStoreError::TransactionUnknown);
    };
    validate_transaction_store_relation(transaction, current, disposition)?;
    let delete_target = generation
        .map(|generation| credential_target(&transaction.profile_id, generation))
        .transpose()?;
    Ok(ReconcilePlan {
        disposition,
        delete_target,
        clear_journal: true,
    })
}

fn validate_transaction_store_relation(
    transaction: &ProfileTransaction,
    current: Option<&ProfileStore>,
    disposition: ReconcileDisposition,
) -> Result<(), ProfileStoreError> {
    let profile = current.and_then(|store| {
        store
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(&transaction.profile_id))
            .ok()
            .map(|index| &store.profiles[index])
    });
    let current_generation = profile.and_then(|profile| profile.credential_generation.as_ref());
    let relation_valid = match (transaction.operation, disposition) {
        (ProfileOperation::Create, ReconcileDisposition::RollBack) => profile.is_none(),
        (ProfileOperation::Create, ReconcileDisposition::Commit) => {
            current_generation == transaction.new_credential_generation.as_ref()
        }
        (ProfileOperation::Update, ReconcileDisposition::RollBack)
        | (ProfileOperation::Delete, ReconcileDisposition::RollBack) => {
            profile.is_some()
                && current_generation == transaction.old_credential_generation.as_ref()
        }
        (ProfileOperation::Update, ReconcileDisposition::Commit) => {
            profile.is_some()
                && current_generation == transaction.new_credential_generation.as_ref()
        }
        (ProfileOperation::Delete, ReconcileDisposition::Commit) => profile.is_none(),
    };
    if relation_valid {
        Ok(())
    } else {
        Err(ProfileStoreError::TransactionUnknown)
    }
}

pub fn credential_target(profile_id: &str, generation: &str) -> Result<String, ProfileStoreError> {
    if !valid_identifier(profile_id) || !valid_identifier(generation) {
        return Err(ProfileStoreError::InvalidInput);
    }
    Ok(format!(
        "{CREDENTIAL_TARGET_PREFIX}/{profile_id}/{generation}"
    ))
}

fn expect_revision(store: &ProfileStore, expected: u64) -> Result<(), ProfileStoreError> {
    if store.store_revision == expected {
        Ok(())
    } else {
        Err(ProfileStoreError::StaleRevision)
    }
}

fn next_revision(store: &ProfileStore) -> Result<u64, ProfileStoreError> {
    store
        .store_revision
        .checked_add(1)
        .ok_or(ProfileStoreError::RevisionOverflow)
}

fn validate_profile_fields(
    profile_id: &str,
    display_name: &str,
    port: u16,
) -> Result<(), ProfileStoreError> {
    if !valid_identifier(profile_id) || port == 0 {
        return Err(ProfileStoreError::InvalidInput);
    }
    normalize_display_name(display_name.to_owned()).map(|_| ())
}

fn normalize_display_name(value: String) -> Result<String, ProfileStoreError> {
    let trimmed = value.trim();
    if !valid_display_name(trimmed) {
        return Err(ProfileStoreError::InvalidInput);
    }
    Ok(trimmed.to_owned())
}

fn valid_display_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISPLAY_NAME_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn valid_credential(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str) -> bool {
    valid_lower_hex(value, IDENTIFIER_HEX_BYTES)
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn build_transaction(
    operation: ProfileOperation,
    profile_id: &str,
    old_store: Option<&ProfileStore>,
    new_store: &ProfileStore,
    old_credential_generation: Option<String>,
    new_credential_generation: Option<String>,
) -> Result<ProfileTransaction, ProfileStoreError> {
    let transaction = ProfileTransaction {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        operation,
        profile_id: profile_id.to_owned(),
        base_revision: old_store.map_or(0, |store| store.store_revision),
        next_revision: new_store.store_revision,
        old_credential_generation,
        new_credential_generation,
        old_store_sha256: store_digest(old_store)?,
        new_store_sha256: store_digest(Some(new_store))?,
    };
    transaction.validate()?;
    Ok(transaction)
}

fn transpose_transaction(
    value: Option<Result<ProfileTransaction, ProfileStoreError>>,
) -> Result<Option<ProfileTransaction>, ProfileStoreError> {
    value.transpose()
}

fn store_digest(store: Option<&ProfileStore>) -> Result<String, ProfileStoreError> {
    let bytes = match store {
        Some(store) => canonical_store_bytes(store)?,
        None => Vec::new(),
    };
    let digest = Sha256::digest(bytes);
    Ok(lower_hex(&digest))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "00112233445566778899aabbccddeeff";
    const ID_B: &str = "10112233445566778899aabbccddeeff";
    const GEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn create_input(revision: u64, credential: bool) -> CreateProfileInput {
        let value = if credential {
            serde_json::json!({
                "expectedStoreRevision": revision,
                "displayName": "Local proxy",
                "port": 7078,
                "protocol": "socks5",
                "credential": {"username": "private-user", "password": "private-password"}
            })
        } else {
            serde_json::json!({
                "expectedStoreRevision": revision,
                "displayName": "Local proxy",
                "port": 7078,
                "protocol": "socks5",
                "credential": null
            })
        };
        serde_json::from_value(value).unwrap()
    }

    fn create_one(credential: bool) -> MutationPlan {
        create_profile(
            None,
            create_input(0, credential),
            ID_A.into(),
            credential.then(|| GEN_A.into()),
        )
        .unwrap()
    }

    #[test]
    fn strict_store_and_input_schema_reject_unknown_or_noncanonical_data() {
        let valid = serde_json::to_vec(&create_one(false).new_store).unwrap();
        assert_eq!(parse_store(&valid).unwrap().profiles.len(), 1);

        let mut unknown: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        unknown["path"] = serde_json::json!("C:\\private");
        assert_eq!(
            parse_store(&serde_json::to_vec(&unknown).unwrap()).unwrap_err(),
            ProfileStoreError::InvalidStore
        );

        let reversed = ProfileStore {
            schema_version: PROFILE_SCHEMA_VERSION,
            store_revision: 2,
            profiles: vec![
                StoredProfile {
                    profile_id: ID_B.into(),
                    display_name: "B".into(),
                    port: 1,
                    protocol: DesktopProxyProtocol::Http,
                    credential_generation: None,
                },
                StoredProfile {
                    profile_id: ID_A.into(),
                    display_name: "A".into(),
                    port: 2,
                    protocol: DesktopProxyProtocol::Socks5,
                    credential_generation: None,
                },
            ],
        };
        assert_eq!(reversed.validate(), Err(ProfileStoreError::InvalidStore));

        let input = serde_json::json!({
            "expectedStoreRevision": 0,
            "displayName": "x",
            "port": 7078,
            "protocol": "socks5",
            "host": "example.com",
            "credential": null
        });
        assert!(serde_json::from_value::<CreateProfileInput>(input).is_err());
    }

    #[test]
    fn create_uses_injected_ids_and_public_view_hides_generation_and_secrets() {
        let plan = create_one(true);
        assert_eq!(plan.new_store.store_revision, 1);
        assert_eq!(plan.new_store.profiles[0].profile_id, ID_A);
        assert_eq!(
            plan.write_credential.as_ref().unwrap().target,
            format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}")
        );
        let public = serde_json::to_string(&plan.new_store.public_view()).unwrap();
        assert!(public.contains("hasCredential"));
        for forbidden in [GEN_A, "private-user", "private-password", "target"] {
            assert!(!public.contains(forbidden));
        }
        let debug = format!("{plan:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
        assert!(!debug.contains(ID_A));
        assert!(!debug.contains(GEN_A));
    }

    #[test]
    fn stale_revision_collision_limits_and_revision_overflow_fail_closed() {
        let existing = create_one(false).new_store;
        assert_eq!(
            create_profile(Some(&existing), create_input(0, false), ID_B.into(), None,)
                .unwrap_err(),
            ProfileStoreError::StaleRevision
        );
        assert_eq!(
            create_profile(Some(&existing), create_input(1, false), ID_A.into(), None,)
                .unwrap_err(),
            ProfileStoreError::IdCollision
        );

        let full = ProfileStore {
            profiles: (0..MAX_PROFILES)
                .map(|value| StoredProfile {
                    profile_id: format!("{value:032x}"),
                    display_name: "x".into(),
                    port: 1,
                    protocol: DesktopProxyProtocol::Http,
                    credential_generation: None,
                })
                .collect(),
            ..ProfileStore::default()
        };
        assert_eq!(
            create_profile(Some(&full), create_input(0, false), "f".repeat(32), None,).unwrap_err(),
            ProfileStoreError::LimitReached
        );

        let overflow = ProfileStore {
            schema_version: PROFILE_SCHEMA_VERSION,
            store_revision: u64::MAX,
            profiles: Vec::new(),
        };
        assert_eq!(
            create_profile(
                Some(&overflow),
                create_input(u64::MAX, false),
                ID_A.into(),
                None,
            )
            .unwrap_err(),
            ProfileStoreError::RevisionOverflow
        );
    }

    #[test]
    fn update_keep_replace_remove_and_delete_have_exact_effects() {
        let initial = create_one(true).new_store;
        let keep: UpdateProfileInput = serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": 1,
            "profileId": ID_A,
            "displayName": " Renamed ",
            "port": 7079,
            "protocol": "http",
            "credentialAction": {"action": "keep"}
        }))
        .unwrap();
        let kept = update_profile(&initial, keep, None).unwrap();
        assert_eq!(kept.new_store.profiles[0].display_name, "Renamed");
        assert_eq!(
            kept.new_store.profiles[0].credential_generation.as_deref(),
            Some(GEN_A)
        );
        assert!(kept.journal.is_none());

        let replace: UpdateProfileInput = serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": 2,
            "profileId": ID_A,
            "displayName": "Renamed",
            "port": 7079,
            "protocol": "http",
            "credentialAction": {
                "action": "replace",
                "username": "new-user",
                "password": "new-password"
            }
        }))
        .unwrap();
        let replaced = update_profile(&kept.new_store, replace, Some(GEN_B.into())).unwrap();
        assert_eq!(
            replaced.post_publish_delete_target.as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}").as_str())
        );
        assert_eq!(
            replaced.write_credential.as_ref().unwrap().target,
            format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_B}")
        );

        let remove: UpdateProfileInput = serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": 3,
            "profileId": ID_A,
            "displayName": "Renamed",
            "port": 7079,
            "protocol": "http",
            "credentialAction": {"action": "remove"}
        }))
        .unwrap();
        let removed = update_profile(&replaced.new_store, remove, None).unwrap();
        assert!(removed.new_store.profiles[0]
            .credential_generation
            .is_none());
        assert_eq!(
            removed.post_publish_delete_target.as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_B}").as_str())
        );

        let deleted = delete_profile(
            &removed.new_store,
            DeleteProfileInput {
                expected_store_revision: 4,
                profile_id: ID_A.into(),
            },
        )
        .unwrap();
        assert!(deleted.new_store.profiles.is_empty());
        assert!(deleted.journal.is_none());
        assert!(deleted.post_publish_delete_target.is_none());
        assert_eq!(
            delete_profile(
                &deleted.new_store,
                DeleteProfileInput {
                    expected_store_revision: 5,
                    profile_id: ID_A.into(),
                }
            )
            .unwrap_err(),
            ProfileStoreError::NotFound
        );
    }

    #[test]
    fn every_credential_crash_side_reconciles_only_one_exact_target() {
        let create = create_one(true);
        let journal = create.journal.as_ref().unwrap();
        let old = reconcile_transaction(journal, None).unwrap();
        assert_eq!(old.disposition, ReconcileDisposition::RollBack);
        assert_eq!(
            old.delete_target.as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}").as_str())
        );
        let new = reconcile_transaction(journal, Some(&create.new_store)).unwrap();
        assert_eq!(new.disposition, ReconcileDisposition::Commit);
        assert!(new.delete_target.is_none());

        let mut unknown = create.new_store.clone();
        unknown.store_revision = 9;
        assert_eq!(
            reconcile_transaction(journal, Some(&unknown)).unwrap_err(),
            ProfileStoreError::TransactionUnknown
        );
        assert_eq!(
            reconcile_transaction(journal, Some(&ProfileStore::default())).unwrap_err(),
            ProfileStoreError::TransactionUnknown
        );

        let mut forged = journal.clone();
        forged.profile_id = ID_B.into();
        assert_eq!(
            reconcile_transaction(&forged, Some(&create.new_store)).unwrap_err(),
            ProfileStoreError::TransactionUnknown
        );
    }

    #[test]
    fn replace_and_delete_reconcile_keep_targets_isolated() {
        let initial = create_one(true).new_store;
        let replace: UpdateProfileInput = serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": 1,
            "profileId": ID_A,
            "displayName": "Local proxy",
            "port": 7078,
            "protocol": "socks5",
            "credentialAction": {
                "action": "replace",
                "username": "new-user",
                "password": "new-password"
            }
        }))
        .unwrap();
        let replaced = update_profile(&initial, replace, Some(GEN_B.into())).unwrap();
        let replace_journal = replaced.journal.as_ref().unwrap();
        assert_eq!(
            reconcile_transaction(replace_journal, Some(&initial))
                .unwrap()
                .delete_target
                .as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_B}").as_str())
        );
        assert_eq!(
            reconcile_transaction(replace_journal, Some(&replaced.new_store))
                .unwrap()
                .delete_target
                .as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}").as_str())
        );

        let deleted = delete_profile(
            &initial,
            DeleteProfileInput {
                expected_store_revision: 1,
                profile_id: ID_A.into(),
            },
        )
        .unwrap();
        let delete_journal = deleted.journal.as_ref().unwrap();
        assert!(reconcile_transaction(delete_journal, Some(&initial))
            .unwrap()
            .delete_target
            .is_none());
        assert_eq!(
            reconcile_transaction(delete_journal, Some(&deleted.new_store))
                .unwrap()
                .delete_target
                .as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}").as_str())
        );

        let other_target = credential_target(ID_B, GEN_A).unwrap();
        assert_ne!(
            other_target,
            format!("{CREDENTIAL_TARGET_PREFIX}/{ID_A}/{GEN_A}")
        );
    }

    #[test]
    fn transaction_schema_is_strict_and_never_contains_credentials() {
        let plan = create_one(true);
        let bytes = serde_json::to_vec(plan.journal.as_ref().unwrap()).unwrap();
        let parsed = parse_transaction(&bytes).unwrap();
        assert_eq!(parsed.operation, ProfileOperation::Create);
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in ["private-user", "private-password", "displayName", "port"] {
            assert!(!text.contains(forbidden));
        }

        let mut value = serde_json::to_value(parsed).unwrap();
        value["target"] = serde_json::json!("*");
        assert_eq!(
            parse_transaction(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            ProfileStoreError::InvalidTransaction
        );
    }

    #[test]
    fn credential_and_identifier_validation_rejects_control_oversize_and_forgery() {
        for (username, password) in [
            ("", "p"),
            ("u", ""),
            ("user\nname", "p"),
            ("u", "pass\0word"),
        ] {
            let input: CreateProfileInput = serde_json::from_value(serde_json::json!({
                "expectedStoreRevision": 0,
                "displayName": "x",
                "port": 7078,
                "protocol": "socks5",
                "credential": {"username": username, "password": password}
            }))
            .unwrap();
            assert_eq!(
                create_profile(None, input, ID_A.into(), Some(GEN_A.into())).unwrap_err(),
                ProfileStoreError::InvalidInput
            );
        }
        assert_eq!(
            credential_target("../outside", GEN_A).unwrap_err(),
            ProfileStoreError::InvalidInput
        );
        assert_eq!(
            credential_target(ID_A, "A".repeat(32).as_str()).unwrap_err(),
            ProfileStoreError::InvalidInput
        );
    }
}
