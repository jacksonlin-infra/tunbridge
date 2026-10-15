use crate::local_proxy::{SecretText, TestInput};
use crate::profile_store::{
    canonical_store_bytes, create_profile, credential_target, delete_profile, parse_store,
    parse_transaction, reconcile_transaction, update_profile, CreateProfileInput,
    DeleteProfileInput, MutationPlan, ProfileStore, ProfileStoreError, ProfileTransaction,
    ReconcileDisposition, UpdateProfileInput, MAX_PROFILE_STORE_BYTES, MAX_TRANSACTION_BYTES,
};
use crate::profile_store_windows::{CredentialVault, CredentialVaultError};
use std::{
    ffi::c_void,
    fs::{self, File},
    io::{self, Read, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{FromRawHandle as _, RawHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
        HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        GetAce, GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSid,
        TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FileAttributeTagInfo, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, MoveFileExW, ReplaceFileW, CREATE_NEW, DELETE, FILE_APPEND_DATA,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, FILE_WRITE_EA, MOVEFILE_WRITE_THROUGH, OPEN_ALWAYS, OPEN_EXISTING,
        VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Com::CoTaskMemFree,
        SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

const STORE_FILENAME: &str = "profiles-v1.json";
const JOURNAL_FILENAME: &str = "profile-txn-v1.json";
pub(crate) const STORE_FILENAME_V2: &str = "profiles-v2.json";
pub(crate) const JOURNAL_FILENAME_V2: &str = "profile-txn-v2.json";
const LOCK_FILENAME: &str = "profile-store-v1.lock";
#[cfg(all(test, feature = "acceptance-m3-profile"))]
const ACCEPTANCE_PREFIX: &str = "TunBridge-M3-Profile-Acceptance-";
const PRODUCT_DIRECTORY: &str = "TunBridge";
const DESKTOP_DIRECTORY: &str = "desktop";
const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const WRITE_LIKE_ACCESS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;
const MAX_RANDOM_ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedStoreError {
    Busy,
    NotFound,
    UntrustedStorage,
    InvalidData,
    SystemFailure,
}

impl From<ProfileStoreError> for ProtectedStoreError {
    fn from(_: ProfileStoreError) -> Self {
        Self::InvalidData
    }
}

pub struct ProtectedProfileFiles {
    root: PathBuf,
    current_sid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCoordinatorError {
    Storage(ProtectedStoreError),
    Vault(CredentialVaultError),
    Model(ProfileStoreError),
    Interrupted,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionStep {
    JournalPublished,
    CredentialWritten,
    StorePublished,
    OldCredentialDeleted,
}

impl ProtectedProfileFiles {
    /// Prepare the fixed production current-user store without accepting a
    /// caller path or consulting environment variables.
    pub fn prepare_production() -> Result<Self, ProtectedStoreError> {
        let local_app_data = local_app_data_directory()?;
        validate_directory_binding(&local_app_data, None)?;
        let current_sid = current_user_sid()?;

        let product = local_app_data.join(PRODUCT_DIRECTORY);
        if product.exists() {
            validate_trusted_parent_directory_binding(&product, &current_sid)?;
        } else {
            create_secure_directory(&product, &current_sid)?;
            validate_directory_binding(&product, Some(&current_sid))?;
        }

        let root = product.join(DESKTOP_DIRECTORY);
        create_secure_directory(&root, &current_sid)?;
        validate_directory_binding(&root, Some(&current_sid))?;
        Ok(Self { root, current_sid })
    }

    /// Prepare only the feature-gated random acceptance namespace.
    #[cfg(all(test, feature = "acceptance-m3-profile"))]
    pub fn prepare_acceptance(random_suffix: &str) -> Result<Self, ProtectedStoreError> {
        if random_suffix.len() != 32
            || !random_suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ProtectedStoreError::InvalidData);
        }
        let local_app_data = local_app_data_directory()?;
        validate_directory_binding(&local_app_data, None)?;
        let current_sid = current_user_sid()?;
        let root = local_app_data.join(format!("{ACCEPTANCE_PREFIX}{random_suffix}"));
        create_secure_directory(&root, &current_sid)?;
        validate_directory_binding(&root, Some(&current_sid))?;
        Ok(Self { root, current_sid })
    }

    pub fn acquire_lock(&self) -> Result<ProfileStoreLock, ProtectedStoreError> {
        self.revalidate_root()?;
        let path = self.root.join(LOCK_FILENAME);
        let wide = wide_path(&path);
        let descriptor = current_user_descriptor(&self.current_sid)?;
        let attributes = security_attributes(&descriptor);
        // SAFETY: the fixed path is NUL-terminated. Share mode zero makes the
        // kernel handle the cross-process/session exclusion and crash release.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: immediately follows the failing Win32 call.
            return if unsafe { GetLastError() } == ERROR_SHARING_VIOLATION {
                Err(ProtectedStoreError::Busy)
            } else {
                Err(ProtectedStoreError::SystemFailure)
            };
        }
        if validate_handle_binding(handle, &path, Some(&self.current_sid)).is_err() {
            // SAFETY: handle was returned by CreateFileW and is closed once.
            unsafe { CloseHandle(handle) };
            return Err(ProtectedStoreError::UntrustedStorage);
        }
        Ok(ProfileStoreLock { handle })
    }

    pub fn read_store(&self) -> Result<Option<ProfileStore>, ProtectedStoreError> {
        self.read_fixed(STORE_FILENAME, MAX_PROFILE_STORE_BYTES)?
            .map(|bytes| parse_store(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn publish_store(&self, bytes: &[u8]) -> Result<(), ProtectedStoreError> {
        parse_store(bytes)?;
        self.publish_fixed(STORE_FILENAME, "store-candidate-", bytes)
    }

    pub fn read_transaction(&self) -> Result<Option<ProfileTransaction>, ProtectedStoreError> {
        self.read_fixed(JOURNAL_FILENAME, MAX_TRANSACTION_BYTES)?
            .map(|bytes| parse_transaction(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn publish_transaction(&self, bytes: &[u8]) -> Result<(), ProtectedStoreError> {
        parse_transaction(bytes)?;
        self.publish_fixed(JOURNAL_FILENAME, "txn-candidate-", bytes)
    }

    pub fn clear_transaction(&self) -> Result<(), ProtectedStoreError> {
        self.remove_fixed(JOURNAL_FILENAME)
    }

    pub(crate) fn read_v2_store_bytes(&self) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
        self.read_fixed(
            STORE_FILENAME_V2,
            tunbridge_core::profile_v2::MAX_PROFILE_STORE_BYTES,
        )
    }

    pub(crate) fn publish_v2_store(&self, bytes: &[u8]) -> Result<(), ProtectedStoreError> {
        tunbridge_core::profile_v2::parse_v2(bytes)
            .map_err(|_| ProtectedStoreError::InvalidData)?;
        self.publish_fixed(STORE_FILENAME_V2, "store-v2-candidate-", bytes)
    }

    pub(crate) fn read_v2_transaction_bytes(&self) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
        self.read_fixed(
            JOURNAL_FILENAME_V2,
            crate::profile_store_v2::MAX_TRANSACTION_BYTES_V2,
        )
    }

    pub(crate) fn publish_v2_transaction(&self, bytes: &[u8]) -> Result<(), ProtectedStoreError> {
        crate::profile_store_v2::parse_transaction(bytes)
            .map_err(|_| ProtectedStoreError::InvalidData)?;
        self.publish_fixed(JOURNAL_FILENAME_V2, "txn-v2-candidate-", bytes)
    }

    pub(crate) fn clear_v2_transaction(&self) -> Result<(), ProtectedStoreError> {
        self.remove_fixed(JOURNAL_FILENAME_V2)
    }

    pub(crate) fn read_legacy_store_bytes(&self) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
        self.read_fixed(STORE_FILENAME, MAX_PROFILE_STORE_BYTES)
    }

    pub(crate) fn clear_legacy_store(&self) -> Result<(), ProtectedStoreError> {
        self.remove_fixed(STORE_FILENAME)
    }

    #[cfg(all(test, feature = "acceptance-m3-profile"))]
    pub fn reconcile(&self, vault: &CredentialVault) -> Result<(), ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)
    }

    pub fn list(
        &self,
        vault: &CredentialVault,
    ) -> Result<crate::profile_store::ProfileList, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        Ok(self.read_store()?.unwrap_or_default().public_view())
    }

    pub fn create_generated(
        &self,
        vault: &CredentialVault,
        input: CreateProfileInput,
    ) -> Result<ProfileStore, ProfileCoordinatorError> {
        let _lock = self.acquire_lock()?;
        self.reconcile_locked(vault)?;
        let current = self.read_store()?;
        let needs_credential = input.credential.is_some();
        let mut profile_id = None;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let candidate = random_hex_16().map_err(|_| ProtectedStoreError::SystemFailure)?;
            if current.as_ref().is_none_or(|store| {
                store
                    .profiles
                    .binary_search_by(|profile| profile.profile_id.as_str().cmp(&candidate))
                    .is_err()
            }) {
                profile_id = Some(candidate);
                break;
            }
        }
        let profile_id = profile_id.ok_or(ProfileCoordinatorError::Model(
            ProfileStoreError::IdCollision,
        ))?;
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
        vault: &CredentialVault,
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

    pub fn load_saved_test(
        &self,
        vault: &CredentialVault,
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

    fn unused_generation(
        &self,
        vault: &CredentialVault,
        profile_id: &str,
    ) -> Result<String, ProfileCoordinatorError> {
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let generation = random_hex_16().map_err(|_| ProtectedStoreError::SystemFailure)?;
            match vault.read(profile_id, &generation) {
                Err(CredentialVaultError::NotFound) => return Ok(generation),
                Ok(_) | Err(CredentialVaultError::AlreadyExists) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ProfileCoordinatorError::Model(
            ProfileStoreError::IdCollision,
        ))
    }

    pub fn delete(
        &self,
        vault: &CredentialVault,
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

    fn reconcile_locked(&self, vault: &CredentialVault) -> Result<(), ProfileCoordinatorError> {
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
            let derived = credential_target(&transaction.profile_id, generation)?;
            if derived != expected_target {
                return Err(ProfileCoordinatorError::Model(
                    ProfileStoreError::TransactionUnknown,
                ));
            }
            vault.delete_exact(&transaction.profile_id, generation)?;
        }
        self.clear_transaction()?;
        Ok(())
    }

    fn execute_plan(
        &self,
        vault: &CredentialVault,
        plan: MutationPlan,
    ) -> Result<(), ProfileCoordinatorError> {
        self.execute_plan_with_hook(vault, plan, |_| false)
    }

    fn execute_plan_with_hook<F>(
        &self,
        vault: &CredentialVault,
        plan: MutationPlan,
        mut stop_after: F,
    ) -> Result<(), ProfileCoordinatorError>
    where
        F: FnMut(ExecutionStep) -> bool,
    {
        if let Some(transaction) = plan.journal.as_ref() {
            let bytes = serde_json::to_vec(transaction).map_err(|_| {
                ProfileCoordinatorError::Model(ProfileStoreError::InvalidTransaction)
            })?;
            self.publish_transaction(&bytes)?;
            if stop_after(ExecutionStep::JournalPublished) {
                return Err(ProfileCoordinatorError::Interrupted);
            }
        }

        if let Some(pending) = plan.write_credential.as_ref() {
            let transaction = plan.journal.as_ref().ok_or(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown,
            ))?;
            let generation = transaction.new_credential_generation.as_ref().ok_or(
                ProfileCoordinatorError::Model(ProfileStoreError::TransactionUnknown),
            )?;
            let derived = credential_target(&transaction.profile_id, generation)?;
            if derived != pending.target {
                return Err(ProfileCoordinatorError::Model(
                    ProfileStoreError::TransactionUnknown,
                ));
            }
            vault.write_new(&transaction.profile_id, generation, &pending.credential)?;
            if stop_after(ExecutionStep::CredentialWritten) {
                return Err(ProfileCoordinatorError::Interrupted);
            }
        }

        self.publish_store(&canonical_store_bytes(&plan.new_store)?)?;
        if stop_after(ExecutionStep::StorePublished) {
            return Err(ProfileCoordinatorError::Interrupted);
        }

        if let Some(expected_target) = plan.post_publish_delete_target.as_ref() {
            let transaction = plan.journal.as_ref().ok_or(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown,
            ))?;
            let generation = transaction.old_credential_generation.as_ref().ok_or(
                ProfileCoordinatorError::Model(ProfileStoreError::TransactionUnknown),
            )?;
            let derived = credential_target(&transaction.profile_id, generation)?;
            if derived != *expected_target {
                return Err(ProfileCoordinatorError::Model(
                    ProfileStoreError::TransactionUnknown,
                ));
            }
            vault.delete_exact(&transaction.profile_id, generation)?;
            if stop_after(ExecutionStep::OldCredentialDeleted) {
                return Err(ProfileCoordinatorError::Interrupted);
            }
        }

        if plan.journal.is_some() {
            self.clear_transaction()?;
        }
        Ok(())
    }

    fn publish_fixed(
        &self,
        destination_name: &str,
        candidate_prefix: &str,
        bytes: &[u8],
    ) -> Result<(), ProtectedStoreError> {
        self.revalidate_root()?;
        let candidate = self.root.join(format!(
            "{candidate_prefix}{}.json",
            random_hex_16().map_err(|_| ProtectedStoreError::SystemFailure)?
        ));
        let destination = self.root.join(destination_name);
        write_new_synced(&candidate, bytes, &self.current_sid)?;
        let result = (|| {
            validate_file_binding(&candidate, &self.current_sid)?;
            if destination.exists() {
                validate_file_binding(&destination, &self.current_sid)?;
            }
            atomic_publish(&candidate, &destination)?;
            validate_file_binding(&destination, &self.current_sid)
        })();
        if result.is_err() {
            let _ = remove_exact_file(&candidate);
        }
        result
    }

    fn read_fixed(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ProtectedStoreError> {
        self.revalidate_root()?;
        let path = self.root.join(name);
        if !path.exists() {
            return Ok(None);
        }
        let file = open_read_bound(&path, &self.current_sid)?;
        let metadata = file.metadata().map_err(map_io)?;
        if !metadata.is_file() || metadata.len() > max_bytes as u64 {
            return Err(ProtectedStoreError::InvalidData);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((max_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(map_io)?;
        if bytes.len() > max_bytes {
            return Err(ProtectedStoreError::InvalidData);
        }
        Ok(Some(bytes))
    }

    fn remove_fixed(&self, name: &str) -> Result<(), ProtectedStoreError> {
        self.revalidate_root()?;
        let path = self.root.join(name);
        if !path.exists() {
            return Ok(());
        }
        validate_file_binding(&path, &self.current_sid)?;
        remove_exact_file(&path)
    }

    fn revalidate_root(&self) -> Result<(), ProtectedStoreError> {
        validate_directory_binding(&self.root, Some(&self.current_sid))
    }
}

pub struct ProfileStoreLock {
    handle: HANDLE,
}

impl Drop for ProfileStoreLock {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: this object uniquely owns the kernel handle.
            unsafe { CloseHandle(self.handle) };
        }
    }
}

fn create_secure_directory(path: &Path, current_sid: &str) -> Result<(), ProtectedStoreError> {
    if path.exists() {
        return Ok(());
    }
    let descriptor = current_user_descriptor(current_sid)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    // SAFETY: path and descriptor are valid for the duration of the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(map_io(error));
        }
    }
    Ok(())
}

fn current_user_sid() -> Result<String, ProtectedStoreError> {
    let mut token = ptr::null_mut();
    // SAFETY: token points to writable storage and the pseudo-process handle
    // is valid in the current process.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let token = OwnedHandle(token);
    let mut needed = 0_u32;
    // SAFETY: documented sizing call uses a null buffer.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let mut buffer = vec![0_u8; needed as usize];
    // SAFETY: buffer has exactly the requested capacity.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(ProtectedStoreError::SystemFailure);
    }
    // SAFETY: GetTokenInformation initialized a TOKEN_USER at buffer start.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn validate_current_user_acl_handle(
    handle: HANDLE,
    current_sid: &str,
) -> Result<(), ProtectedStoreError> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: handle is valid and all requested outputs are writable.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let _descriptor = LocalAllocation(descriptor.cast());
    validate_acl_parts(owner, dacl, descriptor, current_sid)
}

fn validate_trusted_parent_acl_handle(
    handle: HANDLE,
    current_sid: &str,
) -> Result<(), ProtectedStoreError> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: handle is valid and all requested outputs are writable.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let _descriptor = LocalAllocation(descriptor.cast());
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    let owner = sid_string(owner)?;
    if owner != current_sid && owner != SYSTEM_SID && owner != ADMINISTRATORS_SID {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    // The fixed parent can also contain the separately owned run directory.
    // Inheritance is accepted only while all write-capable ACEs remain trusted.
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(ProtectedStoreError::UntrustedStorage);
        }
        validate_ace(raw.cast_const(), current_sid)?;
    }
    Ok(())
}

fn validate_acl_parts(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
    current_sid: &str,
) -> Result<(), ProtectedStoreError> {
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || sid_string(owner)? != current_sid
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: descriptor came from a Windows security-info API.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    // SAFETY: dacl is valid after IsValidAcl.
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut raw = ptr::null_mut();
        // SAFETY: index is bounded by AceCount.
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(ProtectedStoreError::UntrustedStorage);
        }
        validate_ace(raw.cast_const(), current_sid)?;
    }
    Ok(())
}

fn validate_directory_binding(
    path: &Path,
    current_sid: Option<&str>,
) -> Result<(), ProtectedStoreError> {
    let wide = wide_path(path);
    // SAFETY: path is NUL-terminated. OPEN_REPARSE_POINT prevents following
    // the final component; BACKUP_SEMANTICS permits a directory handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let handle = OwnedHandle(handle);
    validate_handle_binding(handle.0, path, current_sid)
}

fn validate_trusted_parent_directory_binding(
    path: &Path,
    current_sid: &str,
) -> Result<(), ProtectedStoreError> {
    let wide = wide_path(path);
    // SAFETY: fixed path is NUL-terminated and final traversal is disabled.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let handle = OwnedHandle(handle);
    validate_handle_binding(handle.0, path, None)?;
    validate_trusted_parent_acl_handle(handle.0, current_sid)
}

fn validate_handle_binding(
    handle: HANDLE,
    expected_path: &Path,
    current_sid: Option<&str>,
) -> Result<(), ProtectedStoreError> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: handle is valid and tag is writable for its exact type size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
        || tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(ProtectedStoreError::UntrustedStorage);
    }

    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: sizing call uses a null output buffer.
    let needed = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, flags) };
    if needed == 0 || needed > 32_768 {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    let mut buffer = vec![0_u16; needed as usize + 1];
    // SAFETY: buffer is writable for the requested UTF-16 units.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    buffer.truncate(written as usize);
    let actual = String::from_utf16(&buffer).map_err(|_| ProtectedStoreError::UntrustedStorage)?;
    let expected = expected_path.to_string_lossy();
    if normalize_bound_path(&actual) != normalize_bound_path(&expected) {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    if let Some(current_sid) = current_sid {
        validate_current_user_acl_handle(handle, current_sid)?;
    }
    Ok(())
}

fn normalize_bound_path(path: &str) -> String {
    path.strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('/', "\\")
        .to_lowercase()
}

fn validate_ace(raw: *const c_void, current_sid: &str) -> Result<(), ProtectedStoreError> {
    // SAFETY: caller obtained raw from a validated ACL.
    let header = unsafe { ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
    if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
        return Ok(());
    }
    let ace_type = u32::from(header.AceType);
    if matches!(
        ace_type,
        ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    ) {
        return Ok(());
    }
    if ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE
        || !matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        )
    {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    // SAFETY: ACCESS_ALLOWED(_CALLBACK)_ACE has Mask at +4 and SidStart at +8.
    let mask = unsafe { ptr::read_unaligned(raw.cast::<u8>().add(4).cast::<u32>()) };
    if mask & WRITE_LIKE_ACCESS == 0 {
        return Ok(());
    }
    let sid = unsafe { raw.cast::<u8>().add(8).cast_mut().cast::<c_void>() };
    let sid = sid_string(sid)?;
    if sid == current_sid || sid == SYSTEM_SID || sid == ADMINISTRATORS_SID {
        Ok(())
    } else {
        Err(ProtectedStoreError::UntrustedStorage)
    }
}

fn write_new_synced(
    path: &Path,
    bytes: &[u8],
    current_sid: &str,
) -> Result<(), ProtectedStoreError> {
    let descriptor = current_user_descriptor(current_sid)?;
    let attributes = security_attributes(&descriptor);
    let wide = wide_path(path);
    // SAFETY: the exact NUL-terminated candidate path and protected security
    // descriptor live through CreateFileW. CREATE_NEW rejects replacement.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_io(io::Error::last_os_error()));
    }
    if let Err(error) = validate_handle_binding(handle, path, Some(current_sid)) {
        // SAFETY: handle was returned by CreateFileW and has not transferred.
        unsafe { CloseHandle(handle) };
        let _ = remove_exact_file(path);
        return Err(error);
    }
    // SAFETY: the successful handle is transferred exactly once to File.
    let mut file = unsafe { File::from_raw_handle(handle as RawHandle) };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = remove_exact_file(path);
        return Err(map_io(error));
    }
    Ok(())
}

fn open_read_bound(path: &Path, current_sid: &str) -> Result<File, ProtectedStoreError> {
    let wide = wide_path(path);
    // SAFETY: the exact path is NUL-terminated and final reparse traversal is
    // disabled. The handle is validated before ownership transfers to File.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_io(io::Error::last_os_error()));
    }
    if let Err(error) = validate_handle_binding(handle, path, Some(current_sid)) {
        // SAFETY: handle has not transferred to File.
        unsafe { CloseHandle(handle) };
        return Err(error);
    }
    // SAFETY: validated handle ownership transfers exactly once.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

fn validate_file_binding(path: &Path, current_sid: &str) -> Result<(), ProtectedStoreError> {
    drop(open_read_bound(path, current_sid)?);
    Ok(())
}

fn current_user_descriptor(current_sid: &str) -> Result<SecurityDescriptor, ProtectedStoreError> {
    SecurityDescriptor::from_sddl(&format!(
        "O:{current_sid}G:{current_sid}D:P(A;OICI;FA;;;{current_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    ))
}

fn security_attributes(descriptor: &SecurityDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

fn atomic_publish(source: &Path, destination: &Path) -> Result<(), ProtectedStoreError> {
    let destination_exists = destination.exists();
    let source = wide_path(source);
    let destination = wide_path(destination);
    // SAFETY: both exact same-directory paths are NUL-terminated. Existing
    // targets use ReplaceFileW flags 0 so ACL merge failures are not ignored;
    // first publish is a same-volume write-through rename without replacement.
    let succeeded = unsafe {
        if destination_exists {
            ReplaceFileW(
                destination.as_ptr(),
                source.as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } else {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if succeeded == 0 {
        return Err(ProtectedStoreError::SystemFailure);
    }
    Ok(())
}

fn remove_exact_file(path: &Path) -> Result<(), ProtectedStoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(map_io(error)),
    }
}

fn local_app_data_directory() -> Result<PathBuf, ProtectedStoreError> {
    let mut raw = ptr::null_mut();
    // SAFETY: raw points to writable storage and Windows allocates the path.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut raw) };
    if result < 0 || raw.is_null() {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let mut length = 0;
    // SAFETY: successful API result is NUL-terminated.
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let path = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map(PathBuf::from)
        .map_err(|_| ProtectedStoreError::SystemFailure);
    // SAFETY: SHGetKnownFolderPath used the COM task allocator.
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

fn sid_string(sid: PSID) -> Result<String, ProtectedStoreError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(ProtectedStoreError::UntrustedStorage);
    }
    let mut raw = ptr::null_mut();
    // SAFETY: sid is valid and raw is writable.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(ProtectedStoreError::SystemFailure);
    }
    let allocation = LocalWideString(raw);
    let mut length = 0;
    // SAFETY: conversion returns a NUL-terminated string.
    unsafe {
        while *allocation.0.add(length) != 0 {
            length += 1;
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(allocation.0, length) })
        .map_err(|_| ProtectedStoreError::SystemFailure)
}

pub(crate) fn random_hex_16() -> Result<String, ()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut bytes = [0_u8; 16];
    // SAFETY: system-preferred RNG requires a null algorithm handle.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err(());
    }
    let mut value = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(value)
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn map_io(error: io::Error) -> ProtectedStoreError {
    if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
        ProtectedStoreError::Busy
    } else if matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
    ) {
        ProtectedStoreError::NotFound
    } else {
        ProtectedStoreError::SystemFailure
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, ProtectedStoreError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        // SAFETY: SDDL is NUL-terminated and raw is writable.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(ProtectedStoreError::SystemFailure);
        }
        Ok(Self(raw))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: descriptor was allocated by LocalAlloc.
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            // SAFETY: this object uniquely owns the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocation came from GetNamedSecurityInfoW.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocation came from ConvertSidToStringSidW.
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }
}

#[cfg(all(test, feature = "acceptance-m3-profile"))]
mod tests {
    use super::*;
    use crate::local_proxy_platform;
    use crate::profile_store::{
        canonical_store_bytes, create_profile, delete_profile, update_profile, CreateProfileInput,
        CredentialInput, DeleteProfileInput, ProfileOperation, ProfileStore, ProfileTransaction,
        UpdateProfileInput, TRANSACTION_SCHEMA_VERSION,
    };
    use std::cell::RefCell;
    use std::os::windows::fs::symlink_file;

    struct ExactCleanup(PathBuf);

    impl Drop for ExactCleanup {
        fn drop(&mut self) {
            for name in [STORE_FILENAME, JOURNAL_FILENAME, LOCK_FILENAME] {
                let path = self.0.join(name);
                if path.exists() {
                    let _ = remove_exact_file(&path);
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    struct ExactCredentialCleanup<'a> {
        vault: &'a CredentialVault,
        entries: Vec<(String, String)>,
    }

    struct ProductionExactCleanup {
        root: PathBuf,
        product: PathBuf,
        current_sid: String,
        vault: CredentialVault,
        credentials: RefCell<Vec<(String, String)>>,
        remove_product: bool,
    }

    impl ProductionExactCleanup {
        fn register_credential(&self, profile_id: &str, generation: &str) {
            self.credentials
                .borrow_mut()
                .push((profile_id.to_owned(), generation.to_owned()));
        }
    }

    impl Drop for ProductionExactCleanup {
        fn drop(&mut self) {
            for (profile_id, generation) in self.credentials.get_mut().iter() {
                let _ = self.vault.delete_exact(profile_id, generation);
            }
            for name in [STORE_FILENAME, JOURNAL_FILENAME, LOCK_FILENAME] {
                let path = self.root.join(name);
                if path.exists() && validate_file_binding(&path, &self.current_sid).is_ok() {
                    let _ = remove_exact_file(&path);
                }
            }
            let _ = fs::remove_dir(&self.root);
            if self.remove_product {
                let _ = fs::remove_dir(&self.product);
            }
        }
    }

    impl Drop for ExactCredentialCleanup<'_> {
        fn drop(&mut self) {
            for (profile_id, generation) in &self.entries {
                let _ = self.vault.delete_exact(profile_id, generation);
            }
        }
    }

    fn credential(username: &str, password: &str) -> CredentialInput {
        serde_json::from_value(serde_json::json!({
            "username": username,
            "password": password
        }))
        .unwrap()
    }

    fn create_input(revision: u64, username: &str, password: &str) -> CreateProfileInput {
        serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": revision,
            "displayName": "Acceptance profile",
            "port": 7078,
            "protocol": "socks5",
            "credential": {"username": username, "password": password}
        }))
        .unwrap()
    }

    fn replace_input(
        revision: u64,
        profile_id: &str,
        username: &str,
        password: &str,
    ) -> UpdateProfileInput {
        serde_json::from_value(serde_json::json!({
            "expectedStoreRevision": revision,
            "profileId": profile_id,
            "displayName": "Acceptance profile",
            "port": 7078,
            "protocol": "socks5",
            "credentialAction": {
                "action": "replace",
                "username": username,
                "password": password
            }
        }))
        .unwrap()
    }

    #[test]
    #[ignore = "removes only the exact no-credential profile created by manual Gate B UI acceptance"]
    fn cleanup_manual_gate_b_profile_is_exact() {
        let files = ProtectedProfileFiles::prepare_production().unwrap();
        let vault = CredentialVault;
        let current = files.list(&vault).unwrap();
        assert_eq!(current.profiles.len(), 1);
        let profile = &current.profiles[0];
        assert_eq!(profile.display_name, "Gate B 7078 acceptance");
        assert_eq!(profile.port, 7078);
        assert_eq!(
            profile.protocol,
            crate::local_proxy::DesktopProxyProtocol::Socks5
        );
        assert!(!profile.has_credential);
        let profile_id = profile.profile_id.clone();
        let deleted = files
            .delete(
                &vault,
                DeleteProfileInput {
                    expected_store_revision: current.store_revision,
                    profile_id,
                },
            )
            .unwrap();
        assert!(deleted.profiles.is_empty());
        drop(files);

        let local_app_data = local_app_data_directory().unwrap();
        let root = local_app_data
            .join(PRODUCT_DIRECTORY)
            .join(DESKTOP_DIRECTORY);
        let current_sid = current_user_sid().unwrap();
        for name in [STORE_FILENAME, JOURNAL_FILENAME, LOCK_FILENAME] {
            let path = root.join(name);
            if path.exists() {
                validate_file_binding(&path, &current_sid).unwrap();
                remove_exact_file(&path).unwrap();
            }
        }
        fs::remove_dir(&root).unwrap();
        assert!(!root.exists());
        println!(
            "M3_PROFILE_UI_CLEANUP_REPORT={}",
            serde_json::json!({
                "schemaVersion": 1,
                "ok": true,
                "checks": {
                    "singleExactProfileMatched": true,
                    "noCredentialTargetExisted": true,
                    "strictCoordinatorDelete": true,
                    "fixedFilesRemovedExactly": true,
                    "desktopDirectoryRemoved": true,
                    "noLifecycleOperation": true
                }
            })
        );
    }

    #[test]
    #[ignore = "explicitly exercises the absent fixed production profile path and local proxy"]
    fn real_production_profile_lifecycle_is_exact() {
        let local_app_data = local_app_data_directory().unwrap();
        let product = local_app_data.join(PRODUCT_DIRECTORY);
        let root = product.join(DESKTOP_DIRECTORY);
        let legacy = product.join("run").join("profile.json");
        let product_existed = product.exists();
        assert!(
            !root.exists(),
            "production desktop directory must be absent"
        );
        assert!(!legacy.exists(), "legacy profile must be absent");

        let files = ProtectedProfileFiles::prepare_production().unwrap();
        let cleanup = ProductionExactCleanup {
            root: root.clone(),
            product: product.clone(),
            current_sid: files.current_sid.clone(),
            vault: CredentialVault,
            credentials: RefCell::new(Vec::new()),
            remove_product: !product_existed,
        };
        let vault = &cleanup.vault;

        let empty = files.list(vault).unwrap();
        assert_eq!(empty.store_revision, 0);
        assert!(empty.profiles.is_empty());

        let sentinel_profile = random_hex_16().unwrap();
        let sentinel_generation = random_hex_16().unwrap();
        vault
            .write_new(
                &sentinel_profile,
                &sentinel_generation,
                &credential("sentinel-user", "sentinel-password"),
            )
            .unwrap();
        cleanup.register_credential(&sentinel_profile, &sentinel_generation);

        let created = files
            .create_generated(vault, create_input(0, "saved-user", "saved-password"))
            .unwrap();
        assert_eq!(created.store_revision, 1);
        let credential_profile = created.profiles.first().unwrap().clone();
        let generation_a = credential_profile
            .credential_generation
            .as_deref()
            .unwrap()
            .to_owned();
        cleanup.register_credential(&credential_profile.profile_id, &generation_a);
        vault
            .read(&credential_profile.profile_id, &generation_a)
            .unwrap();
        assert!(created.public_view().profiles[0].has_credential);

        let held_lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.list(vault),
            Err(ProfileCoordinatorError::Storage(ProtectedStoreError::Busy))
        );
        drop(held_lock);

        drop(files);
        let files = ProtectedProfileFiles::prepare_production().unwrap();
        assert_eq!(files.list(vault).unwrap().store_revision, 1);
        assert!(matches!(
            files.update_generated(
                vault,
                replace_input(
                    0,
                    &credential_profile.profile_id,
                    "replacement-user",
                    "replacement-password"
                )
            ),
            Err(ProfileCoordinatorError::Model(
                ProfileStoreError::StaleRevision
            ))
        ));
        assert!(matches!(
            files.load_saved_test(vault, "forged", 1),
            Err(ProfileCoordinatorError::Model(
                ProfileStoreError::InvalidInput
            ))
        ));

        let replaced = files
            .update_generated(
                vault,
                replace_input(
                    1,
                    &credential_profile.profile_id,
                    "replacement-user",
                    "replacement-password",
                ),
            )
            .unwrap();
        let generation_b = replaced.profiles[0]
            .credential_generation
            .as_deref()
            .unwrap()
            .to_owned();
        cleanup.register_credential(&credential_profile.profile_id, &generation_b);
        assert_eq!(
            vault
                .read(&credential_profile.profile_id, &generation_a)
                .unwrap_err(),
            CredentialVaultError::NotFound
        );
        vault
            .read(&credential_profile.profile_id, &generation_b)
            .unwrap();

        let proxy_profile = files
            .create_generated(
                vault,
                serde_json::from_value(serde_json::json!({
                    "expectedStoreRevision": 2,
                    "displayName": "Confirmed local proxy",
                    "port": 7078,
                    "protocol": "socks5",
                    "credential": null
                }))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(proxy_profile.store_revision, 3);
        let proxy_id = proxy_profile
            .profiles
            .iter()
            .find(|profile| profile.credential_generation.is_none())
            .unwrap()
            .profile_id
            .clone();
        let test_input = files.load_saved_test(vault, &proxy_id, 3).unwrap();
        let proxy_result = local_proxy_platform::test_local_proxy(test_input).unwrap();
        assert!(proxy_result.ok);

        let after_proxy_delete = files
            .delete(
                vault,
                DeleteProfileInput {
                    expected_store_revision: 3,
                    profile_id: proxy_id,
                },
            )
            .unwrap();
        assert_eq!(after_proxy_delete.store_revision, 4);
        let final_store = files
            .delete(
                vault,
                DeleteProfileInput {
                    expected_store_revision: 4,
                    profile_id: credential_profile.profile_id.clone(),
                },
            )
            .unwrap();
        assert_eq!(final_store.store_revision, 5);
        assert!(final_store.profiles.is_empty());
        vault.read(&sentinel_profile, &sentinel_generation).unwrap();

        let crash_profile = random_hex_16().unwrap();
        let crash_generation_a = random_hex_16().unwrap();
        let crash_generation_b = random_hex_16().unwrap();
        cleanup.register_credential(&crash_profile, &crash_generation_a);
        cleanup.register_credential(&crash_profile, &crash_generation_b);
        for stop in [
            ExecutionStep::JournalPublished,
            ExecutionStep::CredentialWritten,
        ] {
            let plan = create_profile(
                Some(&final_store),
                create_input(5, "crash-user", "crash-password"),
                crash_profile.clone(),
                Some(crash_generation_a.clone()),
            )
            .unwrap();
            let lock = files.acquire_lock().unwrap();
            assert_eq!(
                files.execute_plan_with_hook(vault, plan, |step| step == stop),
                Err(ProfileCoordinatorError::Interrupted)
            );
            drop(lock);
            files.reconcile(vault).unwrap();
            assert_eq!(files.read_store().unwrap().unwrap(), final_store);
            assert_eq!(
                vault.read(&crash_profile, &crash_generation_a).unwrap_err(),
                CredentialVaultError::NotFound
            );
        }
        let create = create_profile(
            Some(&final_store),
            create_input(5, "crash-user", "crash-password"),
            crash_profile.clone(),
            Some(crash_generation_a.clone()),
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(vault, create, |step| {
                step == ExecutionStep::StorePublished
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(vault).unwrap();
        let crash_created = files.read_store().unwrap().unwrap();
        assert_eq!(crash_created.store_revision, 6);
        vault.read(&crash_profile, &crash_generation_a).unwrap();

        let replace = update_profile(
            &crash_created,
            replace_input(
                6,
                &crash_profile,
                "crash-replacement-user",
                "crash-replacement-password",
            ),
            Some(crash_generation_b.clone()),
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(vault, replace, |step| {
                step == ExecutionStep::OldCredentialDeleted
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(vault).unwrap();
        let crash_replaced = files.read_store().unwrap().unwrap();
        assert_eq!(crash_replaced.store_revision, 7);
        assert_eq!(
            vault.read(&crash_profile, &crash_generation_a).unwrap_err(),
            CredentialVaultError::NotFound
        );
        vault.read(&crash_profile, &crash_generation_b).unwrap();

        let delete = delete_profile(
            &crash_replaced,
            DeleteProfileInput {
                expected_store_revision: 7,
                profile_id: crash_profile.clone(),
            },
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(vault, delete, |step| {
                step == ExecutionStep::StorePublished
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(vault).unwrap();
        let crash_final = files.read_store().unwrap().unwrap();
        assert_eq!(crash_final.store_revision, 8);
        assert!(crash_final.profiles.is_empty());
        assert_eq!(
            vault.read(&crash_profile, &crash_generation_b).unwrap_err(),
            CredentialVaultError::NotFound
        );
        vault.read(&sentinel_profile, &sentinel_generation).unwrap();

        drop(files);
        let restarted = ProtectedProfileFiles::prepare_production().unwrap();
        let restarted_view = restarted.list(vault).unwrap();
        assert_eq!(restarted_view.store_revision, 8);
        assert!(restarted_view.profiles.is_empty());
        drop(restarted);

        let report = serde_json::json!({
            "schemaVersion": 1,
            "ok": true,
            "checks": {
                "productionPathWasInitiallyAbsent": true,
                "legacyProfileWasInitiallyAbsent": true,
                "fixedProductionPathPrepared": true,
                "csprngProfileAndGenerationCreated": true,
                "publicViewContainsNoCredential": true,
                "secondInstanceBusy": true,
                "restartPersistence": true,
                "staleRevisionRejected": true,
                "forgedIdentifierRejected": true,
                "credentialReplaceIsExact": true,
                "productionCrashMatrix": true,
                "savedProfileReachedFixedTarget": true,
                "deleteIsExact": true,
                "differentTargetSentinelPreserved": true,
                "restartAfterDeleteIsEmpty": true,
                "exactCleanupRegistered": true,
                "noLifecycleOperation": true
            }
        });
        println!("M3_PROFILE_PRODUCTION_REPORT={report}");
        drop(cleanup);
        let cleanup_vault = CredentialVault;
        for (profile_id, generation) in [
            (&credential_profile.profile_id, &generation_a),
            (&credential_profile.profile_id, &generation_b),
            (&sentinel_profile, &sentinel_generation),
            (&crash_profile, &crash_generation_a),
            (&crash_profile, &crash_generation_b),
        ] {
            assert_eq!(
                cleanup_vault.read(profile_id, generation).unwrap_err(),
                CredentialVaultError::NotFound
            );
        }
        assert!(!root.exists());
        assert_eq!(product.exists(), product_existed);
        assert!(!legacy.exists());
    }

    #[test]
    #[ignore = "explicitly exercises protected current-user LocalAppData primitives"]
    fn real_protected_store_lock_and_atomic_publish_are_exact() {
        let suffix = random_hex_16().unwrap();
        let files = ProtectedProfileFiles::prepare_acceptance(&suffix).unwrap();
        let cleanup = ExactCleanup(files.root.clone());
        assert!(files.read_store().unwrap().is_none());
        let lock = files.acquire_lock().unwrap();
        assert!(matches!(
            files.acquire_lock(),
            Err(ProtectedStoreError::Busy)
        ));

        let first = ProfileStore::default();
        let first_bytes = canonical_store_bytes(&first).unwrap();
        files.publish_store(&first_bytes).unwrap();
        assert_eq!(files.read_store().unwrap().unwrap(), first);

        let replacement = ProfileStore {
            store_revision: 1,
            ..ProfileStore::default()
        };
        files
            .publish_store(&canonical_store_bytes(&replacement).unwrap())
            .unwrap();
        assert_eq!(files.read_store().unwrap().unwrap(), replacement);

        let malformed = br#"{"schemaVersion":1,"storeRevision":0,"profiles":[],"unknown":true}"#;
        assert!(matches!(
            files.publish_store(malformed),
            Err(ProtectedStoreError::InvalidData)
        ));

        let journal_path = files.root.join(JOURNAL_FILENAME);
        symlink_file(files.root.join(STORE_FILENAME), &journal_path).unwrap();
        assert!(matches!(
            files.read_transaction(),
            Err(ProtectedStoreError::UntrustedStorage)
        ));
        remove_exact_file(&journal_path).unwrap();

        let generation = random_hex_16().unwrap();
        let transaction = ProfileTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            operation: ProfileOperation::Create,
            profile_id: suffix.clone(),
            base_revision: 0,
            next_revision: 1,
            old_credential_generation: None,
            new_credential_generation: Some(generation),
            old_store_sha256: "1".repeat(64),
            new_store_sha256: "2".repeat(64),
        };
        files
            .publish_transaction(&serde_json::to_vec(&transaction).unwrap())
            .unwrap();
        assert_eq!(files.read_transaction().unwrap().unwrap(), transaction);
        files.clear_transaction().unwrap();
        assert!(files.read_transaction().unwrap().is_none());

        drop(lock);
        let restarted_lock = files.acquire_lock().unwrap();
        assert_eq!(files.read_store().unwrap().unwrap(), replacement);
        assert!(files.read_transaction().unwrap().is_none());
        files.clear_transaction().unwrap();
        drop(restarted_lock);

        let report = serde_json::json!({
            "schemaVersion": 1,
            "ok": true,
            "checks": {
                "knownFolderResolved": true,
                "csprngAcceptanceNamespace": suffix.len() == 32,
                "protectedCurrentUserAcl": true,
                "realReparseFileRejected": true,
                "exclusiveLockBusy": true,
                "kernelLockReleasedOnDrop": true,
                "atomicStorePublish": true,
                "replaceFileFlagsZero": true,
                "sameUserRestartRead": true,
                "journalPublishReadClear": true,
                "strictUnknownFieldRejected": true,
                "absentJournalIsIdempotent": true,
                "exactCleanupRegistered": true
            }
        });
        println!("M3_PROFILE_FILE_REPORT={report}");
        drop(cleanup);
    }

    #[test]
    #[ignore = "explicitly exercises isolated LocalAppData and current-user credentials"]
    fn real_coordinator_reconciles_every_credential_crash_side_exactly() {
        let suffix = random_hex_16().unwrap();
        let profile_id = random_hex_16().unwrap();
        let generation_a = random_hex_16().unwrap();
        let generation_b = random_hex_16().unwrap();
        let sentinel_profile = random_hex_16().unwrap();
        let sentinel_generation = random_hex_16().unwrap();
        let files = ProtectedProfileFiles::prepare_acceptance(&suffix).unwrap();
        let file_cleanup = ExactCleanup(files.root.clone());
        let vault = CredentialVault;
        let credential_cleanup = ExactCredentialCleanup {
            vault: &vault,
            entries: vec![
                (profile_id.clone(), generation_a.clone()),
                (profile_id.clone(), generation_b.clone()),
                (sentinel_profile.clone(), sentinel_generation.clone()),
            ],
        };
        vault
            .write_new(
                &sentinel_profile,
                &sentinel_generation,
                &credential("sentinel-user", "sentinel-password"),
            )
            .unwrap();

        for stop in [
            ExecutionStep::JournalPublished,
            ExecutionStep::CredentialWritten,
        ] {
            let plan = create_profile(
                None,
                create_input(0, "create-user", "create-password"),
                profile_id.clone(),
                Some(generation_a.clone()),
            )
            .unwrap();
            let lock = files.acquire_lock().unwrap();
            assert_eq!(
                files.execute_plan_with_hook(&vault, plan, |step| step == stop),
                Err(ProfileCoordinatorError::Interrupted)
            );
            drop(lock);
            files.reconcile(&vault).unwrap();
            assert!(files.read_store().unwrap().is_none());
            assert_eq!(
                vault.read(&profile_id, &generation_a).unwrap_err(),
                CredentialVaultError::NotFound
            );
            assert!(files.read_transaction().unwrap().is_none());
        }

        let create = create_profile(
            None,
            create_input(0, "create-user", "create-password"),
            profile_id.clone(),
            Some(generation_a.clone()),
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(&vault, create, |step| {
                step == ExecutionStep::StorePublished
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(&vault).unwrap();
        let initial = files.read_store().unwrap().unwrap();
        assert_eq!(initial.store_revision, 1);
        assert_eq!(
            initial.profiles[0].credential_generation.as_deref(),
            Some(generation_a.as_str())
        );
        vault.read(&profile_id, &generation_a).unwrap();

        for stop in [
            ExecutionStep::JournalPublished,
            ExecutionStep::CredentialWritten,
        ] {
            let plan = update_profile(
                &initial,
                replace_input(1, &profile_id, "replacement-user", "replacement-password"),
                Some(generation_b.clone()),
            )
            .unwrap();
            let lock = files.acquire_lock().unwrap();
            assert_eq!(
                files.execute_plan_with_hook(&vault, plan, |step| step == stop),
                Err(ProfileCoordinatorError::Interrupted)
            );
            drop(lock);
            files.reconcile(&vault).unwrap();
            assert_eq!(files.read_store().unwrap().unwrap(), initial);
            vault.read(&profile_id, &generation_a).unwrap();
            assert_eq!(
                vault.read(&profile_id, &generation_b).unwrap_err(),
                CredentialVaultError::NotFound
            );
        }

        let replace = update_profile(
            &initial,
            replace_input(1, &profile_id, "replacement-user", "replacement-password"),
            Some(generation_b.clone()),
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(&vault, replace, |step| {
                step == ExecutionStep::OldCredentialDeleted
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(&vault).unwrap();
        let replaced = files.read_store().unwrap().unwrap();
        assert_eq!(replaced.store_revision, 2);
        assert_eq!(
            vault.read(&profile_id, &generation_a).unwrap_err(),
            CredentialVaultError::NotFound
        );
        vault.read(&profile_id, &generation_b).unwrap();

        let delete = delete_profile(
            &replaced,
            DeleteProfileInput {
                expected_store_revision: 2,
                profile_id: profile_id.clone(),
            },
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(&vault, delete, |step| {
                step == ExecutionStep::JournalPublished
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(&vault).unwrap();
        assert_eq!(files.read_store().unwrap().unwrap(), replaced);
        vault.read(&profile_id, &generation_b).unwrap();

        let delete = delete_profile(
            &replaced,
            DeleteProfileInput {
                expected_store_revision: 2,
                profile_id: profile_id.clone(),
            },
        )
        .unwrap();
        let lock = files.acquire_lock().unwrap();
        assert_eq!(
            files.execute_plan_with_hook(&vault, delete, |step| {
                step == ExecutionStep::StorePublished
            }),
            Err(ProfileCoordinatorError::Interrupted)
        );
        drop(lock);
        files.reconcile(&vault).unwrap();
        assert!(files.read_store().unwrap().unwrap().profiles.is_empty());
        assert_eq!(
            vault.read(&profile_id, &generation_b).unwrap_err(),
            CredentialVaultError::NotFound
        );
        vault.read(&sentinel_profile, &sentinel_generation).unwrap();

        let forged = ProfileTransaction {
            schema_version: TRANSACTION_SCHEMA_VERSION,
            operation: ProfileOperation::Delete,
            profile_id: profile_id.clone(),
            base_revision: 99,
            next_revision: 100,
            old_credential_generation: Some(generation_b.clone()),
            new_credential_generation: None,
            old_store_sha256: "3".repeat(64),
            new_store_sha256: "4".repeat(64),
        };
        files
            .publish_transaction(&serde_json::to_vec(&forged).unwrap())
            .unwrap();
        assert_eq!(
            files.reconcile(&vault),
            Err(ProfileCoordinatorError::Model(
                ProfileStoreError::TransactionUnknown
            ))
        );
        assert_eq!(files.read_transaction().unwrap().unwrap(), forged);
        files.clear_transaction().unwrap();
        vault.read(&sentinel_profile, &sentinel_generation).unwrap();

        let report = serde_json::json!({
            "schemaVersion": 1,
            "ok": true,
            "checks": {
                "createBeforeCredentialRollsBack": true,
                "createAfterCredentialRollsBack": true,
                "createAfterStoreCommits": true,
                "replaceBeforeCredentialPreservesOld": true,
                "replaceAfterCredentialPreservesOld": true,
                "replaceAfterOldDeleteIsIdempotent": true,
                "deleteBeforeStorePreservesOld": true,
                "deleteAfterStoreDeletesOnlyOld": true,
                "missingExactDeleteIsIdempotent": true,
                "differentTargetSentinelPreserved": true,
                "unknownJournalRetained": true,
                "journalContainsNoCredential": true,
                "noLifecycleOperation": true,
                "exactCleanupRegistered": true
            }
        });
        println!("M3_PROFILE_COORDINATOR_REPORT={report}");
        drop(credential_cleanup);
        drop(file_cleanup);
    }
}
