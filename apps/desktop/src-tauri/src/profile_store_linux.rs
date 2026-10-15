use crate::{
    credential_store::{CredentialVault, CredentialVaultError},
    local_proxy::{SecretText, TestInput},
    profile_store::{
        canonical_store_bytes, create_profile, credential_target, delete_profile, parse_store,
        parse_transaction, reconcile_transaction, update_profile, CreateProfileInput,
        DeleteProfileInput, MutationPlan, ProfileList, ProfileStore, ProfileStoreError,
        ProfileTransaction, ReconcileDisposition, UpdateProfileInput, MAX_PROFILE_STORE_BYTES,
        MAX_TRANSACTION_BYTES,
    },
};
use std::path::PathBuf;
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
const JOURNAL_FILENAME: &str = "profile-txn-v1.json";
const LOCK_FILENAME: &str = "profile-store-v1.lock";
// Legacy v1 mutation helpers are retained for migration acceptance and tests;
// production profile writes use ProfileCoordinatorV2.
#[allow(dead_code)]
const MAX_RANDOM_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedStoreError {
    Busy,
    UntrustedStorage,
    InvalidData,
    SystemFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCoordinatorError {
    Storage(ProtectedStoreError),
    Vault(CredentialVaultError),
    Model(ProfileStoreError),
}

impl From<ProtectedStoreError> for ProfileCoordinatorError {
    fn from(error: ProtectedStoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<CredentialVaultError> for ProfileCoordinatorError {
    fn from(error: CredentialVaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<ProfileStoreError> for ProfileCoordinatorError {
    fn from(error: ProfileStoreError) -> Self {
        Self::Model(error)
    }
}

pub struct ProfileCoordinator {
    files: PlatformProfileStoreFiles,
}

#[allow(dead_code)]
impl ProfileCoordinator {
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

    fn read_store(&self) -> Result<Option<ProfileStore>, ProtectedStoreError> {
        self.files
            .read_bounded(&self.fixed_path(STORE_FILENAME), MAX_PROFILE_STORE_BYTES)
            .map_err(map_adapter)?
            .map(|bytes| parse_store(&bytes).map_err(|_| ProtectedStoreError::InvalidData))
            .transpose()
    }

    fn publish_store(&self, store: &ProfileStore) -> Result<(), ProtectedStoreError> {
        let bytes = canonical_store_bytes(store).map_err(|_| ProtectedStoreError::InvalidData)?;
        self.files
            .replace_atomically(&self.fixed_path(STORE_FILENAME), &bytes)
            .map_err(map_adapter)
    }

    fn read_transaction(&self) -> Result<Option<ProfileTransaction>, ProtectedStoreError> {
        self.files
            .read_bounded(&self.fixed_path(JOURNAL_FILENAME), MAX_TRANSACTION_BYTES)
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
            .replace_atomically(&self.fixed_path(JOURNAL_FILENAME), &bytes)
            .map_err(map_adapter)
    }

    fn clear_transaction(&self) -> Result<(), ProtectedStoreError> {
        self.files
            .remove_exact(&self.fixed_path(JOURNAL_FILENAME))
            .map_err(map_adapter)
    }

    pub fn list(
        &self,
        vault: &dyn CredentialVault,
    ) -> Result<ProfileList, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        Ok(self.read_store()?.unwrap_or_default().public_view())
    }

    pub fn create_generated(
        &self,
        vault: &dyn CredentialVault,
        input: CreateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        let current = self.read_store()?;
        let needs_credential = input.credential.is_some();
        let profile_id = self.unused_profile_id(current.as_ref())?;
        let generation = if needs_credential {
            Some(self.unused_generation(vault, &profile_id)?)
        } else {
            None
        };
        let plan = create_profile(current.as_ref(), input, profile_id, generation)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn update_generated(
        &self,
        vault: &dyn CredentialVault,
        input: UpdateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        let current = self
            .read_store()?
            .ok_or(ProfileCoordinatorError::Model(ProfileStoreError::NotFound))?;
        let generation = if matches!(
            &input.credential_action,
            crate::profile_store::CredentialAction::Replace { .. }
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
        vault: &dyn CredentialVault,
        input: DeleteProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        let current = self
            .read_store()?
            .ok_or(ProfileCoordinatorError::Model(ProfileStoreError::NotFound))?;
        let plan = delete_profile(&current, input)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn load_saved_test(
        &self,
        vault: &dyn CredentialVault,
        profile_id: &str,
        expected_store_revision: u64,
    ) -> Result<TestInput, ProfileCoordinatorError> {
        credential_target(profile_id, "00000000000000000000000000000000")?;
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        let current = self
            .read_store()?
            .ok_or(ProfileCoordinatorError::Model(ProfileStoreError::NotFound))?;
        if current.store_revision != expected_store_revision {
            return Err(ProfileCoordinatorError::Model(
                ProfileStoreError::StaleRevision,
            ));
        }
        let index = current
            .profiles
            .binary_search_by(|profile| profile.profile_id.as_str().cmp(profile_id))
            .map_err(|_| ProfileCoordinatorError::Model(ProfileStoreError::NotFound))?;
        let profile = &current.profiles[index];
        let (username, password) = if let Some(generation) = &profile.credential_generation {
            let (username, password) = vault.read(profile_id, generation)?.into_parts();
            (
                Some(SecretText::from_owned(username)),
                Some(SecretText::from_owned(password)),
            )
        } else {
            (None, None)
        };
        Ok(TestInput {
            port: profile.port,
            protocol: profile.protocol,
            username,
            password,
        })
    }

    fn unused_profile_id(
        &self,
        current: Option<&ProfileStore>,
    ) -> Result<String, ProfileCoordinatorError> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let candidate = random_hex_16()?;
            if current.is_none_or(|store| {
                store
                    .profiles
                    .binary_search_by(|profile| profile.profile_id.as_str().cmp(&candidate))
                    .is_err()
            }) {
                return Ok(candidate);
            }
        }
        Err(ProfileStoreError::IdCollision.into())
    }

    fn unused_generation(
        &self,
        vault: &dyn CredentialVault,
        profile_id: &str,
    ) -> Result<String, ProfileCoordinatorError> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let generation = random_hex_16()?;
            match vault.read(profile_id, &generation) {
                Err(CredentialVaultError::NotFound) => return Ok(generation),
                Ok(_) | Err(CredentialVaultError::AlreadyExists) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ProfileStoreError::IdCollision.into())
    }

    fn reconcile_locked(&self, vault: &dyn CredentialVault) -> Result<(), ProfileCoordinatorError> {
        let Some(transaction) = self.read_transaction()? else {
            return Ok(());
        };
        let current = self.read_store()?;
        let plan = reconcile_transaction(&transaction, current.as_ref())?;
        if let Some(expected_target) = plan.delete_target {
            let generation = match plan.disposition {
                ReconcileDisposition::RollBack => transaction.new_credential_generation.as_ref(),
                ReconcileDisposition::Commit => transaction.old_credential_generation.as_ref(),
            }
            .ok_or(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown,
            ))?;
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
        vault: &dyn CredentialVault,
        plan: MutationPlan,
    ) -> Result<(), ProfileCoordinatorError> {
        if let Some(transaction) = plan.journal.as_ref() {
            self.publish_transaction(transaction)?;
        }
        if let Some(pending) = plan.write_credential.as_ref() {
            let transaction = plan.journal.as_ref().ok_or(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown,
            ))?;
            let generation = transaction.new_credential_generation.as_ref().ok_or(
                ProfileCoordinatorError::Model(ProfileStoreError::TransactionUnknown),
            )?;
            if credential_target(&transaction.profile_id, generation)? != pending.target {
                return Err(ProfileStoreError::TransactionUnknown.into());
            }
            vault.write_new(&transaction.profile_id, generation, &pending.credential)?;
        }
        self.publish_store(&plan.new_store)?;
        if let Some(expected_target) = plan.post_publish_delete_target.as_ref() {
            let transaction = plan.journal.as_ref().ok_or(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown,
            ))?;
            let generation = transaction.old_credential_generation.as_ref().ok_or(
                ProfileCoordinatorError::Model(ProfileStoreError::TransactionUnknown),
            )?;
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

    #[cfg(test)]
    pub(crate) fn open_for_test(root: &std::path::Path) -> Result<Self, ProtectedStoreError> {
        Self::open(root.to_owned())
    }
}

#[allow(dead_code)]
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
        local_proxy::{DesktopProxyProtocol, SecretText},
        profile_store::CredentialInput,
    };
    use std::{
        collections::BTreeMap,
        fs,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    struct MemoryVault {
        entries: Mutex<BTreeMap<(String, String), (String, String)>>,
    }

    impl CredentialVault for MemoryVault {
        fn write_new(
            &self,
            profile_id: &str,
            generation: &str,
            input: &CredentialInput,
        ) -> Result<(), CredentialVaultError> {
            let mut entries = self.entries.lock().unwrap();
            let key = (profile_id.to_owned(), generation.to_owned());
            if entries.contains_key(&key) {
                return Err(CredentialVaultError::AlreadyExists);
            }
            entries.insert(
                key,
                (
                    input.username.expose().to_owned(),
                    input.password.expose().to_owned(),
                ),
            );
            Ok(())
        }

        fn read(
            &self,
            profile_id: &str,
            generation: &str,
        ) -> Result<crate::credential_store::VaultCredential, CredentialVaultError> {
            let entries = self.entries.lock().unwrap();
            let (username, password) = entries
                .get(&(profile_id.to_owned(), generation.to_owned()))
                .cloned()
                .ok_or(CredentialVaultError::NotFound)?;
            Ok(crate::credential_store::VaultCredential::new_for_test(
                username, password,
            ))
        }

        fn delete_exact(
            &self,
            profile_id: &str,
            generation: &str,
        ) -> Result<(), CredentialVaultError> {
            self.entries
                .lock()
                .unwrap()
                .remove(&(profile_id.to_owned(), generation.to_owned()));
            Ok(())
        }
    }

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-profile-coordinator-{}-{name}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn credential(username: &str, password: &str) -> CredentialInput {
        CredentialInput {
            username: SecretText::from_owned(username.to_owned()),
            password: SecretText::from_owned(password.to_owned()),
        }
    }

    #[test]
    fn profile_crud_and_saved_test_preserve_credentials() {
        let root = root("crud");
        let coordinator = ProfileCoordinator::open_for_test(&root).unwrap();
        let vault = MemoryVault::default();
        let created = coordinator
            .create_generated(
                &vault,
                CreateProfileInput {
                    expected_store_revision: 0,
                    display_name: "Local SOCKS".into(),
                    port: 7891,
                    protocol: DesktopProxyProtocol::Socks5,
                    credential: Some(credential("alice", "private")),
                },
            )
            .unwrap();
        let profile_id = created.profiles[0].profile_id.clone();
        let test = coordinator
            .load_saved_test(&vault, &profile_id, created.store_revision)
            .unwrap();
        assert_eq!(test.port, 7891);
        assert_eq!(test.username.unwrap().expose(), "alice");
        assert_eq!(test.password.unwrap().expose(), "private");

        let updated = coordinator
            .update_generated(
                &vault,
                UpdateProfileInput {
                    expected_store_revision: created.store_revision,
                    profile_id: profile_id.clone(),
                    display_name: "Local HTTP".into(),
                    port: 7890,
                    protocol: DesktopProxyProtocol::Http,
                    credential_action: crate::profile_store::CredentialAction::Remove,
                },
            )
            .unwrap();
        assert!(!updated.public_view().profiles[0].has_credential);
        let deleted = coordinator
            .delete(
                &vault,
                DeleteProfileInput {
                    expected_store_revision: updated.store_revision,
                    profile_id,
                },
            )
            .unwrap();
        assert!(deleted.profiles.is_empty());
        assert!(vault.entries.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
