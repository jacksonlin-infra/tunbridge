use crate::local_proxy::{SecretText, MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tunbridge_core::{
    profile_v2::{
        parse_v2, ProfileListV2, ProfileStoreV2, ProfileV2Error, StoredProfileV2, StoredUpstreamV2,
        MAX_PROFILES,
    },
    upstream::{Endpoint, RemoteProtocolConfig, SecretMaterialV2, StandardProtocol},
};

pub const TRANSACTION_SCHEMA_VERSION_V2: u16 = 2;
pub const MAX_TRANSACTION_BYTES_V2: usize = 8 * 1024;
pub const CREDENTIAL_TARGET_PREFIX_V2: &str = "TunBridge.Desktop.Upstream/v2";
const IDENTIFIER_HEX_BYTES: usize = 32;
const DIGEST_HEX_BYTES: usize = 64;

pub type ProfileStore = ProfileStoreV2;
pub type ProfileList = ProfileListV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultV2Error {
    InvalidInput,
    AlreadyExists,
    NotFound,
    InvalidRecord,
    Unavailable,
}

pub trait SecretVaultV2 {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        material: &SecretMaterialV2,
    ) -> Result<(), SecretVaultV2Error>;

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<SecretMaterialV2, SecretVaultV2Error>;

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), SecretVaultV2Error>;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateProfileInput {
    pub expected_store_revision: u64,
    pub display_name: String,
    pub upstream: ProfileUpstreamInput,
    pub credential: Option<CredentialInput>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProfileUpstreamInput {
    LocalListener {
        port: u16,
        protocol: StandardProtocol,
    },
    RemoteServer {
        endpoint: Endpoint,
        protocol_config: RemoteProtocolConfig,
    },
}

impl fmt::Debug for ProfileUpstreamInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalListener { port, protocol } => formatter
                .debug_struct("LocalListener")
                .field("port", port)
                .field("protocol", protocol)
                .finish(),
            Self::RemoteServer {
                endpoint,
                protocol_config,
            } => formatter
                .debug_struct("RemoteServer")
                .field("endpoint", endpoint)
                .field("protocol_config", protocol_config)
                .finish(),
        }
    }
}

impl ProfileUpstreamInput {
    fn into_stored(
        self,
        generation: Option<String>,
    ) -> Result<StoredUpstreamV2, ProfileStoreError> {
        Ok(match self {
            Self::LocalListener { port, protocol } => StoredUpstreamV2::LocalListener {
                port,
                protocol,
                credential_generation: generation,
            },
            Self::RemoteServer {
                endpoint,
                protocol_config,
            } => StoredUpstreamV2::RemoteServer {
                endpoint: endpoint
                    .canonicalized()
                    .map_err(|_| ProfileStoreError::InvalidInput)?,
                protocol_config: protocol_config
                    .canonicalized()
                    .map_err(|_| ProfileStoreError::InvalidInput)?,
                secret_generation: generation,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialInput {
    pub username: SecretText,
    pub password: SecretText,
}

impl CredentialInput {
    pub fn validate(&self) -> Result<(), ProfileStoreError> {
        if valid_credential(self.username.expose(), MAX_USERNAME_BYTES)
            && valid_credential(self.password.expose(), MAX_PASSWORD_BYTES)
        {
            Ok(())
        } else {
            Err(ProfileStoreError::InvalidInput)
        }
    }

    fn into_material(self) -> Result<SecretMaterialV2, ProfileStoreError> {
        self.validate()?;
        let material = SecretMaterialV2::basic_auth(
            self.username.expose().to_owned(),
            self.password.expose().to_owned(),
        );
        material
            .validate()
            .map_err(|_| ProfileStoreError::InvalidInput)?;
        Ok(material)
    }
}

impl fmt::Debug for CredentialInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialInput([REDACTED])")
    }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateProfileInput {
    pub expected_store_revision: u64,
    pub profile_id: String,
    pub display_name: String,
    pub upstream: ProfileUpstreamInput,
    pub credential_action: CredentialAction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteProfileInput {
    pub expected_store_revision: u64,
    pub profile_id: String,
}

pub struct PendingCredential {
    pub target: String,
    pub material: SecretMaterialV2,
}

impl fmt::Debug for PendingCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingCredential([REDACTED])")
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
            .debug_struct("MutationPlanV2")
            .field("new_store", &self.new_store)
            .field("has_journal", &self.journal.is_some())
            .field("has_write_credential", &self.write_credential.is_some())
            .field(
                "has_post_publish_delete",
                &self.post_publish_delete_target.is_some(),
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
            .debug_struct("ProfileTransactionV2")
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
        if self.schema_version != TRANSACTION_SCHEMA_VERSION_V2
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
            > MAX_TRANSACTION_BYTES_V2
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
    parse_v2(bytes).map_err(map_profile_error)
}

pub fn canonical_store_bytes(store: &ProfileStore) -> Result<Vec<u8>, ProfileStoreError> {
    store.canonical_bytes().map_err(map_profile_error)
}

pub fn parse_transaction(bytes: &[u8]) -> Result<ProfileTransaction, ProfileStoreError> {
    if bytes.len() > MAX_TRANSACTION_BYTES_V2 {
        return Err(ProfileStoreError::InvalidTransaction);
    }
    let transaction: ProfileTransaction =
        serde_json::from_slice(bytes).map_err(|_| ProfileStoreError::InvalidTransaction)?;
    transaction.validate()?;
    Ok(transaction)
}

pub fn create_profile(
    current: Option<&ProfileStore>,
    input: CreateProfileInput,
    profile_id: String,
    credential_generation: Option<String>,
) -> Result<MutationPlan, ProfileStoreError> {
    let empty = ProfileStore::default();
    let working = current.unwrap_or(&empty);
    working.validate().map_err(map_profile_error)?;
    expect_revision(working, input.expected_store_revision)?;
    if working.profiles.len() >= MAX_PROFILES {
        return Err(ProfileStoreError::LimitReached);
    }
    if !valid_identifier(&profile_id)
        || working
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(&profile_id))
            .is_ok()
    {
        return Err(ProfileStoreError::IdCollision);
    }

    let (generation, pending) =
        prepare_new_credential(&profile_id, input.credential, credential_generation)?;
    let next_revision = next_revision(working)?;
    let mut new_store = working.clone();
    new_store.store_revision = next_revision;
    let profile = StoredProfileV2 {
        profile_id: profile_id.clone(),
        display_name: normalize_display_name(input.display_name)?,
        upstream: input.upstream.into_stored(generation.clone())?,
    };
    profile
        .validate()
        .map_err(|_| ProfileStoreError::InvalidInput)?;
    let insert_at = new_store
        .profiles
        .binary_search_by(|stored| stored.profile_id.as_str().cmp(&profile_id))
        .unwrap_err();
    new_store.profiles.insert(insert_at, profile);
    new_store.validate().map_err(map_profile_error)?;

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
        journal: journal.transpose()?,
        write_credential: pending,
        post_publish_delete_target: None,
    })
}

pub fn update_profile(
    current: &ProfileStore,
    input: UpdateProfileInput,
    replacement_generation: Option<String>,
) -> Result<MutationPlan, ProfileStoreError> {
    current.validate().map_err(map_profile_error)?;
    expect_revision(current, input.expected_store_revision)?;
    if !valid_identifier(&input.profile_id) {
        return Err(ProfileStoreError::InvalidInput);
    }
    let index = current
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&input.profile_id))
        .map_err(|_| ProfileStoreError::NotFound)?;
    let old_generation = current.profiles[index]
        .upstream
        .secret_generation()
        .map(str::to_owned);
    let (new_generation, pending) = match (input.credential_action, replacement_generation) {
        (CredentialAction::Keep, None) => (old_generation.clone(), None),
        (CredentialAction::Remove, None) => (None, None),
        (CredentialAction::Replace { username, password }, Some(generation))
            if valid_identifier(&generation) && Some(&generation) != old_generation.as_ref() =>
        {
            let material = CredentialInput { username, password }.into_material()?;
            let target = credential_target(&input.profile_id, &generation)?;
            (
                Some(generation),
                Some(PendingCredential { target, material }),
            )
        }
        _ => return Err(ProfileStoreError::InvalidInput),
    };

    let mut new_store = current.clone();
    new_store.store_revision = next_revision(current)?;
    let profile = StoredProfileV2 {
        profile_id: input.profile_id.clone(),
        display_name: normalize_display_name(input.display_name)?,
        upstream: input.upstream.into_stored(new_generation.clone())?,
    };
    profile
        .validate()
        .map_err(|_| ProfileStoreError::InvalidInput)?;
    new_store.profiles[index] = profile;
    new_store.validate().map_err(map_profile_error)?;

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
        journal: journal.transpose()?,
        write_credential: pending,
        post_publish_delete_target,
    })
}

pub fn delete_profile(
    current: &ProfileStore,
    input: DeleteProfileInput,
) -> Result<MutationPlan, ProfileStoreError> {
    current.validate().map_err(map_profile_error)?;
    expect_revision(current, input.expected_store_revision)?;
    if !valid_identifier(&input.profile_id) {
        return Err(ProfileStoreError::InvalidInput);
    }
    let index = current
        .profiles
        .binary_search_by(|profile| profile.profile_id.as_str().cmp(&input.profile_id))
        .map_err(|_| ProfileStoreError::NotFound)?;
    let old_generation = current.profiles[index]
        .upstream
        .secret_generation()
        .map(str::to_owned);
    let mut new_store = current.clone();
    new_store.store_revision = next_revision(current)?;
    new_store.profiles.remove(index);
    new_store.validate().map_err(map_profile_error)?;

    let journal = old_generation.clone().map(|generation| {
        build_transaction(
            ProfileOperation::Delete,
            &input.profile_id,
            Some(current),
            &new_store,
            Some(generation),
            None,
        )
    });
    let post_publish_delete_target = old_generation
        .as_deref()
        .map(|generation| credential_target(&input.profile_id, generation))
        .transpose()?;
    Ok(MutationPlan {
        new_store,
        journal: journal.transpose()?,
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
        store.validate().map_err(map_profile_error)?;
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
    validate_transaction_relation(transaction, current, disposition)?;
    Ok(ReconcilePlan {
        disposition,
        delete_target: generation
            .map(|generation| credential_target(&transaction.profile_id, generation))
            .transpose()?,
        clear_journal: true,
    })
}

pub fn credential_target(profile_id: &str, generation: &str) -> Result<String, ProfileStoreError> {
    if !valid_identifier(profile_id) || !valid_identifier(generation) {
        return Err(ProfileStoreError::InvalidInput);
    }
    Ok(format!(
        "{CREDENTIAL_TARGET_PREFIX_V2}/{profile_id}/{generation}"
    ))
}

fn prepare_new_credential(
    profile_id: &str,
    credential: Option<CredentialInput>,
    generation: Option<String>,
) -> Result<(Option<String>, Option<PendingCredential>), ProfileStoreError> {
    match (credential, generation) {
        (None, None) => Ok((None, None)),
        (Some(credential), Some(generation)) if valid_identifier(&generation) => {
            let material = credential.into_material()?;
            let target = credential_target(profile_id, &generation)?;
            Ok((
                Some(generation),
                Some(PendingCredential { target, material }),
            ))
        }
        _ => Err(ProfileStoreError::InvalidInput),
    }
}

fn validate_transaction_relation(
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
    let current_generation = profile.and_then(|profile| profile.upstream.secret_generation());
    let relation_valid = match (transaction.operation, disposition) {
        (ProfileOperation::Create, ReconcileDisposition::RollBack) => profile.is_none(),
        (ProfileOperation::Create, ReconcileDisposition::Commit) => {
            current_generation == transaction.new_credential_generation.as_deref()
        }
        (ProfileOperation::Update, ReconcileDisposition::RollBack)
        | (ProfileOperation::Delete, ReconcileDisposition::RollBack) => {
            profile.is_some()
                && current_generation == transaction.old_credential_generation.as_deref()
        }
        (ProfileOperation::Update, ReconcileDisposition::Commit) => {
            profile.is_some()
                && current_generation == transaction.new_credential_generation.as_deref()
        }
        (ProfileOperation::Delete, ReconcileDisposition::Commit) => profile.is_none(),
    };
    if relation_valid {
        Ok(())
    } else {
        Err(ProfileStoreError::TransactionUnknown)
    }
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
        schema_version: TRANSACTION_SCHEMA_VERSION_V2,
        operation,
        profile_id: profile_id.into(),
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

fn store_digest(store: Option<&ProfileStore>) -> Result<String, ProfileStoreError> {
    let bytes = match store {
        Some(store) => canonical_store_bytes(store)?,
        None => Vec::new(),
    };
    Ok(lower_hex(&Sha256::digest(bytes)))
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

fn normalize_display_name(value: String) -> Result<String, ProfileStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_control) {
        return Err(ProfileStoreError::InvalidInput);
    }
    Ok(trimmed.into())
}

fn valid_credential(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn map_profile_error(_: ProfileV2Error) -> ProfileStoreError {
    ProfileStoreError::InvalidStore
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_core::upstream::{CertificatePolicy, IpPreference};

    const ID_A: &str = "00112233445566778899aabbccddeeff";
    const GEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const GEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn local_input(revision: u64) -> CreateProfileInput {
        serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": revision,
            "displayName": "Local proxy",
            "upstream": {"kind": "local_listener", "port": 7078, "protocol": "socks5"},
            "credential": {"username": "private-user", "password": "private-password"}
        }))
        .unwrap()
    }

    fn remote_input(revision: u64) -> CreateProfileInput {
        serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": revision,
            "displayName": "Remote gateway",
            "upstream": {
                "kind": "remote_server",
                "endpoint": {
                    "host": "proxy.example.com",
                    "port": 8443,
                    "ipPreference": "ipv4_prefer"
                },
                "protocolConfig": {
                    "protocol": "http",
                    "tls": true,
                    "sni": "proxy.example.com",
                    "certificatePolicy": "strict"
                }
            },
            "credential": null
        }))
        .unwrap()
    }

    #[test]
    fn create_local_and_remote_profiles_use_one_strict_v2_union() {
        let local = create_profile(None, local_input(0), ID_A.into(), Some(GEN_A.into())).unwrap();
        let remote = create_profile(
            Some(&local.new_store),
            remote_input(1),
            "10112233445566778899aabbccddeeff".into(),
            None,
        )
        .unwrap();
        assert_eq!(remote.new_store.schema_version, 2);
        assert!(matches!(
            remote.new_store.profiles[0].upstream,
            StoredUpstreamV2::LocalListener { .. }
        ));
        assert!(matches!(
            remote.new_store.profiles[1].upstream,
            StoredUpstreamV2::RemoteServer { .. }
        ));
        let public = serde_json::to_string(&remote.new_store.public_view()).unwrap();
        assert!(public.contains("local_listener"));
        assert!(public.contains("remote_server"));
        assert!(!public.contains(GEN_A));
        assert!(!public.contains("private-user"));
    }

    #[test]
    fn remote_input_rejects_routes_urls_loopback_and_unknown_fields() {
        let mut value = serde_json::to_value(remote_input(0).upstream).unwrap();
        value["route"] = serde_json::json!("default");
        assert!(serde_json::from_value::<ProfileUpstreamInput>(value).is_err());

        for host in ["http://proxy.example.com", "127.0.0.1"] {
            let input: CreateProfileInput = serde_json::from_value(serde_json::json!({
                "expectedStoreRevision": 0,
                "displayName": "Remote",
                "upstream": {
                    "kind": "remote_server",
                    "endpoint": {"host": host, "port": 443, "ipPreference": "ipv4_prefer"},
                    "protocolConfig": {
                        "protocol": "http",
                        "tls": true,
                        "sni": "proxy.example.com",
                        "certificatePolicy": "strict"
                    }
                },
                "credential": null
            }))
            .unwrap();
            assert_eq!(
                create_profile(None, input, ID_A.into(), None).unwrap_err(),
                ProfileStoreError::InvalidInput
            );
        }
    }

    #[test]
    fn update_and_reconcile_preserve_exact_secret_ownership() {
        let initial = create_profile(None, local_input(0), ID_A.into(), Some(GEN_A.into()))
            .unwrap()
            .new_store;
        let update: UpdateProfileInput = serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": 1,
            "profileId": ID_A,
            "displayName": "Remote gateway",
            "upstream": {
                "kind": "remote_server",
                "endpoint": {"host": "10.0.0.4", "port": 1080, "ipPreference": "ipv4"},
                "protocolConfig": {
                    "protocol": "socks5",
                    "tls": false,
                    "sni": null,
                    "udp": true,
                    "certificatePolicy": "strict"
                }
            },
            "credentialAction": {
                "action": "replace",
                "username": "new-user",
                "password": "new-password"
            }
        }))
        .unwrap();
        let plan = update_profile(&initial, update, Some(GEN_B.into())).unwrap();
        let transaction = plan.journal.as_ref().unwrap();
        assert_eq!(
            reconcile_transaction(transaction, Some(&initial))
                .unwrap()
                .delete_target
                .as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX_V2}/{ID_A}/{GEN_B}").as_str())
        );
        assert_eq!(
            reconcile_transaction(transaction, Some(&plan.new_store))
                .unwrap()
                .delete_target
                .as_deref(),
            Some(format!("{CREDENTIAL_TARGET_PREFIX_V2}/{ID_A}/{GEN_A}").as_str())
        );
    }

    #[test]
    fn debug_and_transaction_never_contain_endpoint_or_secret_values() {
        let plan = create_profile(None, local_input(0), ID_A.into(), Some(GEN_A.into())).unwrap();
        let debug = format!("{plan:?}");
        for forbidden in [ID_A, GEN_A, "private-user", "private-password"] {
            assert!(!debug.contains(forbidden));
        }
        let transaction = serde_json::to_string(plan.journal.as_ref().unwrap()).unwrap();
        assert!(!transaction.contains("private-user"));
        assert!(!transaction.contains("displayName"));
    }

    #[test]
    fn typed_remote_protocol_is_canonical() {
        let input = ProfileUpstreamInput::RemoteServer {
            endpoint: Endpoint {
                host: "Proxy.Example.COM.".into(),
                port: 443,
                ip_preference: IpPreference::Ipv4Prefer,
            },
            protocol_config: RemoteProtocolConfig::Http {
                tls: true,
                sni: Some("Proxy.Example.COM.".into()),
                certificate_policy: CertificatePolicy::Strict,
            },
        };
        let stored = input.into_stored(None).unwrap();
        stored.validate().unwrap();
        let StoredUpstreamV2::RemoteServer {
            endpoint,
            protocol_config,
            ..
        } = stored
        else {
            panic!("remote input changed variant")
        };
        assert_eq!(endpoint.host, "proxy.example.com");
        assert_eq!(protocol_config.sni(), Some("proxy.example.com"));
    }
}
