use crate::{
    credential_store::{
        CredentialVault as LegacyCredentialVault, CredentialVaultError as LegacyVaultError,
    },
    profile_store_unix::{
        ProfileCoordinator as LegacyProfileCoordinator,
        ProfileCoordinatorError as LegacyCoordinatorError, ProtectedStoreError,
    },
    profile_store_v2::{
        canonical_store_bytes, create_profile, credential_target, delete_profile, parse_store,
        parse_transaction, reconcile_transaction, update_profile, CreateProfileInput,
        DeleteProfileInput, MutationPlan, ProfileList, ProfileStore, ProfileStoreError,
        ProfileTransaction, ReconcileDisposition, SecretVaultV2, SecretVaultV2Error,
        UpdateProfileInput, MAX_TRANSACTION_BYTES_V2,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tunbridge_core::{
    profile_v2::{migrate_v1, StoredProfileV2, MAX_PROFILE_STORE_BYTES},
    upstream::SecretMaterialV2,
};
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ProfileStoreFiles};
#[cfg(target_os = "linux")]
use tunbridge_platform_linux::{
    LinuxProfileStoreFiles as PlatformProfileStoreFiles,
    LinuxProfileStoreLock as PlatformProfileStoreLock, LinuxUserPaths as PlatformUserPaths,
};
#[cfg(target_os = "macos")]
use tunbridge_platform_macos::{
    MacosProfileStoreFiles as PlatformProfileStoreFiles,
    MacosProfileStoreLock as PlatformProfileStoreLock, MacosUserPaths as PlatformUserPaths,
};

const STORE_FILENAME: &str = "profiles-v1.json";
const LOCK_FILENAME: &str = "profile-store-v1.lock";
const TRANSACTION_FILENAME_V2: &str = "profile-txn-v2.json";
const MIGRATION_FILENAME: &str = "profile-migration-v1-v2.json";
const MIGRATION_SCHEMA_VERSION: u16 = 1;
const MAX_MIGRATION_BYTES: usize = 16 * 1024;
const MAX_RANDOM_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCoordinatorV2Error {
    Storage(ProtectedStoreError),
    Legacy(LegacyCoordinatorError),
    Vault(SecretVaultV2Error),
    LegacyVault(LegacyVaultError),
    Model(ProfileStoreError),
}

impl From<ProtectedStoreError> for ProfileCoordinatorV2Error {
    fn from(error: ProtectedStoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<LegacyCoordinatorError> for ProfileCoordinatorV2Error {
    fn from(error: LegacyCoordinatorError) -> Self {
        Self::Legacy(error)
    }
}

impl From<SecretVaultV2Error> for ProfileCoordinatorV2Error {
    fn from(error: SecretVaultV2Error) -> Self {
        Self::Vault(error)
    }
}

impl From<LegacyVaultError> for ProfileCoordinatorV2Error {
    fn from(error: LegacyVaultError) -> Self {
        Self::LegacyVault(error)
    }
}

impl From<ProfileStoreError> for ProfileCoordinatorV2Error {
    fn from(error: ProfileStoreError) -> Self {
        Self::Model(error)
    }
}

pub struct SavedProfileMaterial {
    pub profile: StoredProfileV2,
    pub secret_material: Option<SecretMaterialV2>,
}

impl std::fmt::Debug for SavedProfileMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SavedProfileMaterial")
            .field("profile", &self.profile)
            .field("has_secret_material", &self.secret_material.is_some())
            .finish()
    }
}

pub struct ProfileCoordinatorV2 {
    files: PlatformProfileStoreFiles,
}

impl ProfileCoordinatorV2 {
    pub fn prepare_production() -> Result<Self, ProtectedStoreError> {
        let paths = PlatformUserPaths::from_environment()
            .map_err(|_| ProtectedStoreError::UntrustedStorage)?;
        Self::open(paths.profile_root())
    }

    fn open(root: PathBuf) -> Result<Self, ProtectedStoreError> {
        Ok(Self {
            files: PlatformProfileStoreFiles::open(root).map_err(map_adapter)?,
        })
    }

    fn acquire_lock(&self) -> Result<PlatformProfileStoreLock, ProtectedStoreError> {
        self.files
            .acquire_lock(LOCK_FILENAME)
            .map_err(map_lock_adapter)
    }

    fn fixed_path(&self, filename: &str) -> PathBuf {
        self.files.root().join(filename)
    }

    pub fn list(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
    ) -> Result<ProfileList, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_if_needed(legacy, legacy_vault)?;
        let _lock = self.acquire_lock()?;
        Ok(self.ensure_ready_locked(legacy_vault, vault)?.public_view())
    }

    pub fn create_generated(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
        input: CreateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_if_needed(legacy, legacy_vault)?;
        let _lock = self.acquire_lock()?;
        let current = self.ensure_ready_locked(legacy_vault, vault)?;
        let needs_credential = input.credential.is_some();
        let profile_id = self.unused_profile_id(&current)?;
        let generation = if needs_credential {
            Some(self.unused_generation(vault, &profile_id)?)
        } else {
            None
        };
        let plan = create_profile(Some(&current), input, profile_id, generation)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn update_generated(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
        input: UpdateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_if_needed(legacy, legacy_vault)?;
        let _lock = self.acquire_lock()?;
        let current = self.ensure_ready_locked(legacy_vault, vault)?;
        let generation = if matches!(
            &input.credential_action,
            crate::profile_store_v2::CredentialAction::Replace { .. }
        ) {
            Some(self.unused_generation(vault, &input.profile_id)?)
        } else {
            None
        };
        let plan = update_profile(&current, input, generation)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn delete(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
        input: DeleteProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_if_needed(legacy, legacy_vault)?;
        let _lock = self.acquire_lock()?;
        let current = self.ensure_ready_locked(legacy_vault, vault)?;
        let plan = delete_profile(&current, input)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn load_saved(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
        profile_id: &str,
        expected_store_revision: u64,
    ) -> Result<SavedProfileMaterial, ProfileCoordinatorV2Error> {
        credential_target(profile_id, "00000000000000000000000000000000")?;
        self.reconcile_legacy_if_needed(legacy, legacy_vault)?;
        let _lock = self.acquire_lock()?;
        let current = self.ensure_ready_locked(legacy_vault, vault)?;
        if current.store_revision != expected_store_revision {
            return Err(ProfileStoreError::StaleRevision.into());
        }
        let index = current
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(profile_id))
            .map_err(|_| ProfileStoreError::NotFound)?;
        let profile = current.profiles[index].clone();
        let secret_material = profile
            .upstream
            .secret_generation()
            .map(|generation| vault.read(profile_id, generation))
            .transpose()?;
        Ok(SavedProfileMaterial {
            profile,
            secret_material,
        })
    }

    fn ensure_ready_locked(
        &self,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_migration_locked(legacy_vault, vault)?;
        let raw = self.read_raw_store()?;
        let mut store = match raw {
            None => ProfileStore::default(),
            Some(bytes) => match schema_version(&bytes)? {
                1 => self.migrate_locked(&bytes, legacy_vault, vault)?,
                2 => parse_store(&bytes)?,
                _ => return Err(ProfileStoreError::InvalidStore.into()),
            },
        };
        self.reconcile_transaction_locked(vault, Some(&store))?;
        if let Some(bytes) = self.read_raw_store()? {
            store = parse_store(&bytes)?;
        }
        Ok(store)
    }

    fn reconcile_legacy_if_needed(
        &self,
        legacy: &LegacyProfileCoordinator,
        legacy_vault: &dyn LegacyCredentialVault,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        let raw = self.read_raw_store()?;
        if raw
            .as_deref()
            .map(schema_version)
            .transpose()?
            .is_none_or(|version| version == 1)
        {
            legacy.list(legacy_vault)?;
        }
        Ok(())
    }

    fn migrate_locked(
        &self,
        source_bytes: &[u8],
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        let migration = migrate_v1(source_bytes)
            .map_err(|_| ProfileCoordinatorV2Error::Model(ProfileStoreError::InvalidStore))?;
        let references: Vec<MigrationCredentialReference> = migration
            .credential_references
            .iter()
            .map(|reference| MigrationCredentialReference {
                profile_id: reference.profile_id.clone(),
                generation: reference.generation.clone(),
            })
            .collect();
        let journal = MigrationJournal {
            schema_version: MIGRATION_SCHEMA_VERSION,
            source_sha256: migration.source_sha256,
            target_sha256: migration.target_sha256,
            credentials: references,
        };
        journal.validate()?;
        if !journal.credentials.is_empty() {
            self.publish_migration(&journal)?;
        }

        for reference in &journal.credentials {
            let (username, password) = legacy_vault
                .read(&reference.profile_id, &reference.generation)?
                .into_parts();
            let material = SecretMaterialV2::basic_auth(username, password);
            material
                .validate()
                .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
            match vault.write_new(&reference.profile_id, &reference.generation, &material) {
                Ok(()) => {}
                Err(SecretVaultV2Error::AlreadyExists) => {
                    if vault.read(&reference.profile_id, &reference.generation)? != material {
                        return Err(SecretVaultV2Error::InvalidRecord.into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.publish_store(&migration.store)?;
        for reference in &journal.credentials {
            legacy_vault.delete_exact(&reference.profile_id, &reference.generation)?;
        }
        if !journal.credentials.is_empty() {
            self.clear_migration()?;
        }
        Ok(migration.store)
    }

    fn reconcile_migration_locked(
        &self,
        legacy_vault: &dyn LegacyCredentialVault,
        vault: &dyn SecretVaultV2,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        let Some(journal) = self.read_migration()? else {
            return Ok(());
        };
        let digest = self
            .read_raw_store()?
            .map_or_else(|| raw_digest(&[]), |bytes| raw_digest(&bytes));
        if digest == journal.source_sha256 {
            for reference in &journal.credentials {
                vault.delete_exact(&reference.profile_id, &reference.generation)?;
            }
        } else if digest == journal.target_sha256 {
            for reference in &journal.credentials {
                legacy_vault.delete_exact(&reference.profile_id, &reference.generation)?;
            }
        } else {
            return Err(ProfileStoreError::TransactionUnknown.into());
        }
        self.clear_migration()?;
        Ok(())
    }

    fn reconcile_transaction_locked(
        &self,
        vault: &dyn SecretVaultV2,
        current: Option<&ProfileStore>,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        let Some(transaction) = self.read_transaction()? else {
            return Ok(());
        };
        let plan = reconcile_transaction(&transaction, current)?;
        if let Some(expected_target) = plan.delete_target {
            let generation = match plan.disposition {
                ReconcileDisposition::RollBack => transaction.new_credential_generation.as_ref(),
                ReconcileDisposition::Commit => transaction.old_credential_generation.as_ref(),
            }
            .ok_or(ProfileStoreError::TransactionUnknown)?;
            if credential_target(&transaction.profile_id, generation)? != expected_target {
                return Err(ProfileStoreError::TransactionUnknown.into());
            }
            vault.delete_exact(&transaction.profile_id, generation)?;
        }
        self.clear_transaction()?;
        Ok(())
    }

    fn execute_plan(
        &self,
        vault: &dyn SecretVaultV2,
        plan: MutationPlan,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        if let Some(transaction) = plan.journal.as_ref() {
            self.publish_transaction(transaction)?;
        }
        if let Some(pending) = plan.write_credential.as_ref() {
            let transaction = plan
                .journal
                .as_ref()
                .ok_or(ProfileStoreError::TransactionUnknown)?;
            let generation = transaction
                .new_credential_generation
                .as_ref()
                .ok_or(ProfileStoreError::TransactionUnknown)?;
            if credential_target(&transaction.profile_id, generation)? != pending.target {
                return Err(ProfileStoreError::TransactionUnknown.into());
            }
            vault.write_new(&transaction.profile_id, generation, &pending.material)?;
        }
        self.publish_store(&plan.new_store)?;
        if let Some(expected_target) = plan.post_publish_delete_target.as_ref() {
            let transaction = plan
                .journal
                .as_ref()
                .ok_or(ProfileStoreError::TransactionUnknown)?;
            let generation = transaction
                .old_credential_generation
                .as_ref()
                .ok_or(ProfileStoreError::TransactionUnknown)?;
            if credential_target(&transaction.profile_id, generation)? != *expected_target {
                return Err(ProfileStoreError::TransactionUnknown.into());
            }
            vault.delete_exact(&transaction.profile_id, generation)?;
        }
        if plan.journal.is_some() {
            self.clear_transaction()?;
        }
        Ok(())
    }

    fn read_raw_store(&self) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
        self.files
            .read_bounded(&self.fixed_path(STORE_FILENAME), MAX_PROFILE_STORE_BYTES)
            .map_err(map_adapter)
    }

    fn publish_store(&self, store: &ProfileStore) -> Result<(), ProtectedStoreError> {
        let bytes = canonical_store_bytes(store).map_err(|_| ProtectedStoreError::InvalidData)?;
        self.files
            .replace_atomically(&self.fixed_path(STORE_FILENAME), &bytes)
            .map_err(map_adapter)
    }

    fn read_transaction(&self) -> Result<Option<ProfileTransaction>, ProtectedStoreError> {
        self.files
            .read_bounded(
                &self.fixed_path(TRANSACTION_FILENAME_V2),
                MAX_TRANSACTION_BYTES_V2,
            )
            .map_err(map_adapter)?
            .map(|bytes| parse_transaction(&bytes).map_err(|_| ProtectedStoreError::InvalidData))
            .transpose()
    }

    fn publish_transaction(
        &self,
        transaction: &ProfileTransaction,
    ) -> Result<(), ProtectedStoreError> {
        transaction
            .validate()
            .map_err(|_| ProtectedStoreError::InvalidData)?;
        let bytes =
            serde_json::to_vec(transaction).map_err(|_| ProtectedStoreError::InvalidData)?;
        self.files
            .replace_atomically(&self.fixed_path(TRANSACTION_FILENAME_V2), &bytes)
            .map_err(map_adapter)
    }

    fn clear_transaction(&self) -> Result<(), ProtectedStoreError> {
        self.files
            .remove_exact(&self.fixed_path(TRANSACTION_FILENAME_V2))
            .map_err(map_adapter)
    }

    fn read_migration(&self) -> Result<Option<MigrationJournal>, ProtectedStoreError> {
        self.files
            .read_bounded(&self.fixed_path(MIGRATION_FILENAME), MAX_MIGRATION_BYTES)
            .map_err(map_adapter)?
            .map(|bytes| {
                let journal: MigrationJournal =
                    serde_json::from_slice(&bytes).map_err(|_| ProtectedStoreError::InvalidData)?;
                journal
                    .validate()
                    .map_err(|_| ProtectedStoreError::InvalidData)?;
                Ok(journal)
            })
            .transpose()
    }

    fn publish_migration(&self, journal: &MigrationJournal) -> Result<(), ProtectedStoreError> {
        journal
            .validate()
            .map_err(|_| ProtectedStoreError::InvalidData)?;
        let bytes = serde_json::to_vec(journal).map_err(|_| ProtectedStoreError::InvalidData)?;
        self.files
            .replace_atomically(&self.fixed_path(MIGRATION_FILENAME), &bytes)
            .map_err(map_adapter)
    }

    fn clear_migration(&self) -> Result<(), ProtectedStoreError> {
        self.files
            .remove_exact(&self.fixed_path(MIGRATION_FILENAME))
            .map_err(map_adapter)
    }

    fn unused_profile_id(
        &self,
        current: &ProfileStore,
    ) -> Result<String, ProfileCoordinatorV2Error> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let candidate = random_hex_16()?;
            if current
                .profiles
                .binary_search_by(|profile| profile.profile_id.as_str().cmp(&candidate))
                .is_err()
            {
                return Ok(candidate);
            }
        }
        Err(ProfileStoreError::IdCollision.into())
    }

    fn unused_generation(
        &self,
        vault: &dyn SecretVaultV2,
        profile_id: &str,
    ) -> Result<String, ProfileCoordinatorV2Error> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let generation = random_hex_16()?;
            match vault.read(profile_id, &generation) {
                Err(SecretVaultV2Error::NotFound) => return Ok(generation),
                Ok(_) | Err(SecretVaultV2Error::AlreadyExists) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ProfileStoreError::IdCollision.into())
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(root: &std::path::Path) -> Result<Self, ProtectedStoreError> {
        Self::open(root.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationJournal {
    schema_version: u16,
    source_sha256: String,
    target_sha256: String,
    credentials: Vec<MigrationCredentialReference>,
}

impl MigrationJournal {
    fn validate(&self) -> Result<(), ProfileStoreError> {
        if self.schema_version != MIGRATION_SCHEMA_VERSION
            || !valid_digest(&self.source_sha256)
            || !valid_digest(&self.target_sha256)
            || self.source_sha256 == self.target_sha256
            || self.credentials.len() > 64
        {
            return Err(ProfileStoreError::InvalidTransaction);
        }
        let mut previous: Option<(&str, &str)> = None;
        for reference in &self.credentials {
            credential_target(&reference.profile_id, &reference.generation)?;
            let current = (reference.profile_id.as_str(), reference.generation.as_str());
            if previous.is_some_and(|value| value >= current) {
                return Err(ProfileStoreError::InvalidTransaction);
            }
            previous = Some(current);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ProfileStoreError::InvalidTransaction)?;
        if bytes.len() > MAX_MIGRATION_BYTES {
            return Err(ProfileStoreError::InvalidTransaction);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationCredentialReference {
    profile_id: String,
    generation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaHeader {
    schema_version: u16,
}

fn schema_version(bytes: &[u8]) -> Result<u16, ProfileStoreError> {
    if bytes.len() > MAX_PROFILE_STORE_BYTES {
        return Err(ProfileStoreError::InvalidStore);
    }
    serde_json::from_slice::<SchemaHeader>(bytes)
        .map(|header| header.schema_version)
        .map_err(|_| ProfileStoreError::InvalidStore)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn raw_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn random_hex_16() -> Result<String, ProtectedStoreError> {
    let mut bytes = [0_u8; 16];
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    #[cfg(target_os = "linux")]
    if result != bytes.len() as isize {
        return Err(ProtectedStoreError::SystemFailure);
    }
    #[cfg(target_os = "macos")]
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let mut value = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| ProtectedStoreError::SystemFailure)?;
    }
    Ok(value)
}

fn map_lock_adapter(error: AdapterError) -> ProtectedStoreError {
    if error.retryable {
        ProtectedStoreError::Busy
    } else {
        map_adapter(error)
    }
}

fn map_adapter(error: AdapterError) -> ProtectedStoreError {
    match error.code {
        AdapterErrorCode::InvalidData => ProtectedStoreError::InvalidData,
        AdapterErrorCode::IdentityRejected | AdapterErrorCode::PermissionDenied => {
            ProtectedStoreError::UntrustedStorage
        }
        AdapterErrorCode::NotReady | AdapterErrorCode::Unavailable => {
            ProtectedStoreError::SystemFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_store::VaultCredential,
        local_proxy::{DesktopProxyProtocol, SecretText},
        profile_store::CreateProfileInput as LegacyCreateProfileInput,
    };
    use std::{
        collections::BTreeMap,
        fs,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    struct MemoryVault {
        legacy: Mutex<BTreeMap<(String, String), (String, String)>>,
        v2: Mutex<BTreeMap<(String, String), SecretMaterialV2>>,
    }

    impl LegacyCredentialVault for MemoryVault {
        fn write_new(
            &self,
            profile_id: &str,
            generation: &str,
            input: &crate::profile_store::CredentialInput,
        ) -> Result<(), LegacyVaultError> {
            let mut values = self.legacy.lock().unwrap();
            let key = (profile_id.into(), generation.into());
            if values.contains_key(&key) {
                return Err(LegacyVaultError::AlreadyExists);
            }
            values.insert(
                key,
                (
                    input.username.expose().into(),
                    input.password.expose().into(),
                ),
            );
            Ok(())
        }

        fn read(
            &self,
            profile_id: &str,
            generation: &str,
        ) -> Result<VaultCredential, LegacyVaultError> {
            self.legacy
                .lock()
                .unwrap()
                .get(&(profile_id.into(), generation.into()))
                .cloned()
                .map(|(username, password)| VaultCredential::new_for_test(username, password))
                .ok_or(LegacyVaultError::NotFound)
        }

        fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), LegacyVaultError> {
            self.legacy
                .lock()
                .unwrap()
                .remove(&(profile_id.into(), generation.into()));
            Ok(())
        }
    }

    impl SecretVaultV2 for MemoryVault {
        fn write_new(
            &self,
            profile_id: &str,
            generation: &str,
            material: &SecretMaterialV2,
        ) -> Result<(), SecretVaultV2Error> {
            let mut values = self.v2.lock().unwrap();
            let key = (profile_id.into(), generation.into());
            if values.contains_key(&key) {
                return Err(SecretVaultV2Error::AlreadyExists);
            }
            values.insert(key, material.clone());
            Ok(())
        }

        fn read(
            &self,
            profile_id: &str,
            generation: &str,
        ) -> Result<SecretMaterialV2, SecretVaultV2Error> {
            self.v2
                .lock()
                .unwrap()
                .get(&(profile_id.into(), generation.into()))
                .cloned()
                .ok_or(SecretVaultV2Error::NotFound)
        }

        fn delete_exact(
            &self,
            profile_id: &str,
            generation: &str,
        ) -> Result<(), SecretVaultV2Error> {
            self.v2
                .lock()
                .unwrap()
                .remove(&(profile_id.into(), generation.into()));
            Ok(())
        }
    }

    struct TempRoot(PathBuf);

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_root() -> TempRoot {
        let path = std::env::temp_dir().join(format!(
            "tunbridge-profile-v2-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        TempRoot(path)
    }

    #[test]
    fn v1_store_and_credential_migrate_once_to_explicit_local_v2() {
        let root = temp_root();
        let legacy = LegacyProfileCoordinator::open_for_test(&root.0).unwrap();
        let coordinator = ProfileCoordinatorV2::open_for_test(&root.0).unwrap();
        let vault = MemoryVault::default();
        let input = LegacyCreateProfileInput {
            expected_store_revision: 0,
            display_name: "Local proxy".into(),
            port: 7078,
            protocol: DesktopProxyProtocol::Socks5,
            credential: Some(crate::profile_store::CredentialInput {
                username: SecretText::from_owned("private-user".into()),
                password: SecretText::from_owned("private-password".into()),
            }),
        };
        let legacy_store = legacy.create_generated(&vault, input).unwrap();
        let profile_id = legacy_store.profiles[0].profile_id.clone();
        let generation = legacy_store.profiles[0]
            .credential_generation
            .clone()
            .unwrap();

        let list = coordinator.list(&legacy, &vault, &vault).unwrap();
        assert_eq!(list.schema_version, 2);
        assert!(matches!(
            list.profiles[0].upstream,
            tunbridge_core::profile_v2::PublicUpstreamV2::LocalListener { .. }
        ));
        assert!(
            <MemoryVault as LegacyCredentialVault>::read(&vault, &profile_id, &generation).is_err()
        );
        let material =
            <MemoryVault as SecretVaultV2>::read(&vault, &profile_id, &generation).unwrap();
        assert_eq!(
            material.material.basic_auth(),
            ("private-user", "private-password")
        );

        let raw = fs::read(root.0.join(STORE_FILENAME)).unwrap();
        assert_eq!(schema_version(&raw).unwrap(), 2);
        assert!(!root.0.join(MIGRATION_FILENAME).exists());
        assert_eq!(coordinator.list(&legacy, &vault, &vault).unwrap(), list);
    }
}
