use crate::{
    profile_store_files_windows::{
        random_hex_16, ProfileCoordinatorError as LegacyCoordinatorError, ProtectedProfileFiles,
        ProtectedStoreError,
    },
    profile_store_v2::{
        canonical_store_bytes, create_profile, delete_profile, parse_store, parse_transaction,
        reconcile_transaction, update_profile, CreateProfileInput, DeleteProfileInput,
        MutationPlan, ProfileList, ProfileStore, ProfileStoreError, ReconcileDisposition,
        SecretVaultV2, SecretVaultV2Error, UpdateProfileInput,
    },
    profile_store_windows::{CredentialVault, CredentialVaultError},
};
use tunbridge_core::{
    profile_v2::{migrate_v1, StoredProfileV2},
    upstream::SecretMaterialV2,
};

const MAX_RANDOM_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCoordinatorV2Error {
    Storage(ProtectedStoreError),
    Legacy(LegacyCoordinatorError),
    Vault(SecretVaultV2Error),
    LegacyVault(CredentialVaultError),
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

impl From<CredentialVaultError> for ProfileCoordinatorV2Error {
    fn from(error: CredentialVaultError) -> Self {
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

pub struct ProfileCoordinatorV2Windows {
    files: ProtectedProfileFiles,
}

impl ProfileCoordinatorV2Windows {
    pub fn prepare_production() -> Result<Self, ProfileCoordinatorV2Error> {
        Ok(Self {
            files: ProtectedProfileFiles::prepare_production()?,
        })
    }

    pub fn list(&self, vault: &CredentialVault) -> Result<ProfileList, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_before_lock(vault)?;
        let _lock = self.files.acquire_lock()?;
        let store = self.ensure_ready_locked(vault)?;
        Ok(store.public_view())
    }

    pub fn create_generated(
        &self,
        vault: &CredentialVault,
        input: CreateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_before_lock(vault)?;
        let _lock = self.files.acquire_lock()?;
        let current = self.ensure_ready_locked(vault)?;
        let profile_id = self.unused_profile_id(&current)?;
        let generation = input
            .credential
            .as_ref()
            .map(|_| self.unused_generation(vault, &profile_id))
            .transpose()?;
        let plan = create_profile(Some(&current), input, profile_id, generation)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn update_generated(
        &self,
        vault: &CredentialVault,
        input: UpdateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_before_lock(vault)?;
        let _lock = self.files.acquire_lock()?;
        let current = self.ensure_ready_locked(vault)?;
        let needs_generation = matches!(
            input.credential_action,
            crate::profile_store_v2::CredentialAction::Replace { .. }
        );
        let generation = needs_generation
            .then(|| self.unused_generation(vault, &input.profile_id))
            .transpose()?;
        let plan = update_profile(&current, input, generation)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn delete(
        &self,
        vault: &CredentialVault,
        input: DeleteProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_legacy_before_lock(vault)?;
        let _lock = self.files.acquire_lock()?;
        let current = self.ensure_ready_locked(vault)?;
        let plan = delete_profile(&current, input)?;
        let committed = plan.new_store.clone();
        self.execute_plan(vault, plan)?;
        Ok(committed)
    }

    pub fn load_saved(
        &self,
        vault: &CredentialVault,
        profile_id: &str,
        expected_store_revision: u64,
    ) -> Result<SavedProfileMaterial, ProfileCoordinatorV2Error> {
        crate::profile_store_v2::credential_target(profile_id, "00000000000000000000000000000000")?;
        self.reconcile_legacy_before_lock(vault)?;
        let _lock = self.files.acquire_lock()?;
        let current = self.ensure_ready_locked(vault)?;
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
            .map(|generation| SecretVaultV2::read(vault, profile_id, generation))
            .transpose()?;
        Ok(SavedProfileMaterial {
            profile,
            secret_material,
        })
    }

    fn reconcile_legacy_before_lock(
        &self,
        vault: &CredentialVault,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        if self.files.read_v2_store_bytes()?.is_none()
            && self.files.read_legacy_store_bytes()?.is_some()
        {
            self.files.list(vault)?;
        }
        Ok(())
    }

    fn ensure_ready_locked(
        &self,
        vault: &CredentialVault,
    ) -> Result<ProfileStore, ProfileCoordinatorV2Error> {
        self.reconcile_transaction_locked(vault)?;
        if let Some(bytes) = self.files.read_v2_store_bytes()? {
            let store = parse_store(&bytes)?;
            self.finish_legacy_cleanup_locked(vault, &store)?;
            return Ok(store);
        }
        let Some(legacy_bytes) = self.files.read_legacy_store_bytes()? else {
            return Ok(ProfileStore::default());
        };
        let migration = migrate_v1(&legacy_bytes).map_err(|_| ProfileStoreError::InvalidStore)?;
        for reference in &migration.credential_references {
            let legacy = vault.read(&reference.profile_id, &reference.generation)?;
            let (username, password) = legacy.into_parts();
            let material = SecretMaterialV2::basic_auth(username, password);
            match SecretVaultV2::write_new(
                vault,
                &reference.profile_id,
                &reference.generation,
                &material,
            ) {
                Ok(()) => {}
                Err(SecretVaultV2Error::AlreadyExists) => {
                    if SecretVaultV2::read(vault, &reference.profile_id, &reference.generation)?
                        != material
                    {
                        return Err(ProfileStoreError::TransactionUnknown.into());
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.files
            .publish_v2_store(&canonical_store_bytes(&migration.store)?)?;
        self.finish_legacy_cleanup_locked(vault, &migration.store)?;
        Ok(migration.store)
    }

    fn finish_legacy_cleanup_locked(
        &self,
        vault: &CredentialVault,
        current: &ProfileStore,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        let Some(bytes) = self.files.read_legacy_store_bytes()? else {
            return Ok(());
        };
        let migration = migrate_v1(&bytes).map_err(|_| ProfileStoreError::TransactionUnknown)?;
        if migration.store != *current {
            return Err(ProfileStoreError::TransactionUnknown.into());
        }
        for reference in migration.credential_references {
            vault.delete_exact(&reference.profile_id, &reference.generation)?;
        }
        self.files.clear_legacy_store()?;
        Ok(())
    }

    fn reconcile_transaction_locked(
        &self,
        vault: &CredentialVault,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        let Some(bytes) = self.files.read_v2_transaction_bytes()? else {
            return Ok(());
        };
        let transaction = parse_transaction(&bytes)?;
        let current = self
            .files
            .read_v2_store_bytes()?
            .map(|bytes| parse_store(&bytes))
            .transpose()?
            .unwrap_or_default();
        let plan = reconcile_transaction(&transaction, Some(&current))?;
        if let Some(expected_target) = plan.delete_target {
            let generation = match plan.disposition {
                ReconcileDisposition::RollBack => transaction.new_credential_generation.as_deref(),
                ReconcileDisposition::Commit => transaction.old_credential_generation.as_deref(),
            }
            .ok_or(ProfileStoreError::TransactionUnknown)?;
            if crate::profile_store_v2::credential_target(&transaction.profile_id, generation)?
                != expected_target
            {
                return Err(ProfileStoreError::TransactionUnknown.into());
            }
            SecretVaultV2::delete_exact(vault, &transaction.profile_id, generation)?;
        }
        self.files.clear_v2_transaction()?;
        Ok(())
    }

    fn execute_plan(
        &self,
        vault: &CredentialVault,
        plan: MutationPlan,
    ) -> Result<(), ProfileCoordinatorV2Error> {
        if let Some(transaction) = plan.journal.as_ref() {
            let bytes = serde_json::to_vec(transaction)
                .map_err(|_| ProfileStoreError::InvalidTransaction)?;
            self.files.publish_v2_transaction(&bytes)?;
        }
        if let Some(pending) = plan.write_credential.as_ref() {
            let generation = plan
                .journal
                .as_ref()
                .and_then(|transaction| transaction.new_credential_generation.as_deref())
                .ok_or(ProfileStoreError::InvalidTransaction)?;
            SecretVaultV2::write_new(
                vault,
                &plan
                    .journal
                    .as_ref()
                    .ok_or(ProfileStoreError::InvalidTransaction)?
                    .profile_id,
                generation,
                &pending.material,
            )?;
        }
        self.files
            .publish_v2_store(&canonical_store_bytes(&plan.new_store)?)?;
        if let Some(target) = plan.post_publish_delete_target.as_deref() {
            let transaction = plan
                .journal
                .as_ref()
                .ok_or(ProfileStoreError::InvalidTransaction)?;
            let generation = transaction
                .old_credential_generation
                .as_deref()
                .ok_or(ProfileStoreError::InvalidTransaction)?;
            if crate::profile_store_v2::credential_target(&transaction.profile_id, generation)?
                != target
            {
                return Err(ProfileStoreError::InvalidTransaction.into());
            }
            SecretVaultV2::delete_exact(vault, &transaction.profile_id, generation)?;
        }
        if plan.journal.is_some() {
            self.files.clear_v2_transaction()?;
        }
        Ok(())
    }

    fn unused_profile_id(&self, store: &ProfileStore) -> Result<String, ProfileCoordinatorV2Error> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let candidate = random_hex_16().map_err(|_| ProtectedStoreError::SystemFailure)?;
            if store
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
        vault: &CredentialVault,
        profile_id: &str,
    ) -> Result<String, ProfileCoordinatorV2Error> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let candidate = random_hex_16().map_err(|_| ProtectedStoreError::SystemFailure)?;
            match SecretVaultV2::read(vault, profile_id, &candidate) {
                Err(SecretVaultV2Error::NotFound) => return Ok(candidate),
                Ok(_) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ProfileStoreError::IdCollision.into())
    }
}
