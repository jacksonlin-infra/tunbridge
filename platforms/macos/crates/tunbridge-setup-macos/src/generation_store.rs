//! Crash-recoverable mutation of one fixed root-owned policy/engine generation.
//!
//! Signed-bundle resolution and XPC authentication happen before this boundary;
//! this module accepts only already validated bytes and never caller paths.

use crate::{
    bootstrap_assets::ValidatedGenerationAssets,
    engine_asset::{SYSTEM_ENGINE_MANIFEST_PATH, SYSTEM_ENGINE_PATH},
    install_transaction::SYSTEM_POLICY_PATH,
};
use libc::{O_CLOEXEC, O_NOFOLLOW};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const SYSTEM_STATE_ROOT: &str = "/Library/Application Support/TunBridge/Install";
const JOURNAL_NAME: &str = "generation-v1.json";
const LOCK_NAME: &str = "generation-v1.lock";
const POLICY_BACKUP: &str = "policy.previous";
const MANIFEST_BACKUP: &str = "manifest.previous";
const ENGINE_BACKUP: &str = "engine.previous";
const JOURNAL_MODE: u32 = 0o600;
const POLICY_MODE: u32 = 0o600;
const MANIFEST_MODE: u32 = 0o644;
const ENGINE_MODE: u32 = 0o755;
const STATE_DIRECTORY_MODE: u32 = 0o700;
const ENGINE_DIRECTORY_MODE: u32 = 0o755;
const MAX_POLICY_BYTES: u64 = 4096;
const MAX_MANIFEST_BYTES: u64 = 4096;
const MAX_ENGINE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationStoreError {
    InvalidLayout,
    InvalidTransaction,
    Busy,
    InvalidAsset,
    JournalUnavailable,
    RecoveryRequired,
    InjectedFailure,
}

#[derive(Debug, Clone)]
pub struct GenerationPaths {
    state_root: PathBuf,
    policy_path: PathBuf,
    engine_root: PathBuf,
    manifest_path: PathBuf,
    engine_path: PathBuf,
}

impl GenerationPaths {
    pub fn system() -> Self {
        Self {
            state_root: SYSTEM_STATE_ROOT.into(),
            policy_path: SYSTEM_POLICY_PATH.into(),
            engine_root: Path::new(SYSTEM_ENGINE_PATH)
                .parent()
                .expect("fixed engine path has a parent")
                .into(),
            manifest_path: SYSTEM_ENGINE_MANIFEST_PATH.into(),
            engine_path: SYSTEM_ENGINE_PATH.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(root: &Path) -> Self {
        let engine_root = root.join("Application Support/TunBridge/Engine");
        Self {
            state_root: root.join("Application Support/TunBridge/Install"),
            policy_path: root
                .join("PrivilegedHelperTools")
                .join("com.tunbridge.desktop.helper.policy.json"),
            manifest_path: engine_root.join("manifest.json"),
            engine_path: engine_root.join("mihomo"),
            engine_root,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    Committing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationJournal {
    schema_version: u16,
    transaction_id: String,
    phase: JournalPhase,
    previous_policy: Option<AssetIdentity>,
    previous_manifest: Option<AssetIdentity>,
    previous_engine: Option<AssetIdentity>,
    policy_sha256: String,
    manifest_sha256: String,
    engine_sha256: String,
    policy_size: u64,
    manifest_size: u64,
    engine_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AssetIdentity {
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    None,
    AfterPolicy,
    AfterManifest,
    AfterEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetRole {
    Policy,
    Manifest,
    Engine,
}

pub struct GenerationStore {
    paths: GenerationPaths,
    expected_uid: u32,
    expected_gid: u32,
    _lock: File,
}

impl GenerationStore {
    pub fn open_system() -> Result<Self, GenerationStoreError> {
        Self::open(GenerationPaths::system(), 0, 0)
    }

    pub fn open(
        paths: GenerationPaths,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, GenerationStoreError> {
        validate_paths(&paths)?;
        validate_directory(
            &paths.state_root,
            expected_uid,
            expected_gid,
            STATE_DIRECTORY_MODE,
        )?;
        validate_directory(
            &paths.engine_root,
            expected_uid,
            expected_gid,
            ENGINE_DIRECTORY_MODE,
        )?;
        validate_safe_parent(
            paths
                .policy_path
                .parent()
                .ok_or(GenerationStoreError::InvalidLayout)?,
            expected_uid,
        )?;
        let lock = open_checked(
            &paths.state_root.join(LOCK_NAME),
            expected_uid,
            expected_gid,
            JOURNAL_MODE,
            true,
        )?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(GenerationStoreError::Busy);
        }
        Ok(Self {
            paths,
            expected_uid,
            expected_gid,
            _lock: lock,
        })
    }

    pub fn prepare_generation(
        &mut self,
        transaction_id: &str,
        assets: &ValidatedGenerationAssets,
    ) -> Result<(), GenerationStoreError> {
        let result = self.prepare_inner(transaction_id, assets, FaultPoint::None);
        if result.is_err() {
            match self.read_journal() {
                Ok(Some(_)) => {
                    if self.rollback_generation(transaction_id).is_err() {
                        return Err(GenerationStoreError::RecoveryRequired);
                    }
                }
                Ok(None) if valid_transaction_id(transaction_id) => {
                    if self.pending_path(transaction_id).exists()
                        && self.remove_pending(transaction_id).is_err()
                    {
                        return Err(GenerationStoreError::RecoveryRequired);
                    }
                }
                Ok(None) => {}
                Err(_) => return Err(GenerationStoreError::RecoveryRequired),
            }
        }
        result
    }

    pub fn commit_generation(&mut self, transaction_id: &str) -> Result<(), GenerationStoreError> {
        let mut journal = self.require_journal(transaction_id)?;
        if journal.phase != JournalPhase::Prepared {
            return Err(GenerationStoreError::RecoveryRequired);
        }
        self.verify_active(&journal)?;
        journal.phase = JournalPhase::Committing;
        self.write_journal(&journal)?;
        self.finish_commit(&journal)
    }

    pub fn rollback_generation(
        &mut self,
        transaction_id: &str,
    ) -> Result<(), GenerationStoreError> {
        let journal = self.require_journal(transaction_id)?;
        if journal.phase != JournalPhase::Prepared {
            return Err(GenerationStoreError::RecoveryRequired);
        }
        self.restore_one(AssetRole::Policy, &journal)?;
        self.restore_one(AssetRole::Manifest, &journal)?;
        self.restore_one(AssetRole::Engine, &journal)?;
        self.remove_pending(&journal.transaction_id)?;
        self.remove_journal()
    }

    pub fn recover_pending(&mut self) -> Result<(), GenerationStoreError> {
        let Some(journal) = self.read_journal()? else {
            return Ok(());
        };
        match journal.phase {
            JournalPhase::Prepared => self.rollback_generation(&journal.transaction_id),
            JournalPhase::Committing => {
                self.verify_active(&journal)?;
                self.finish_commit(&journal)
            }
        }
    }

    fn prepare_inner(
        &mut self,
        transaction_id: &str,
        assets: &ValidatedGenerationAssets,
        fault: FaultPoint,
    ) -> Result<(), GenerationStoreError> {
        if !valid_transaction_id(transaction_id) {
            return Err(GenerationStoreError::InvalidTransaction);
        }
        if self.read_journal()?.is_some() {
            return Err(GenerationStoreError::Busy);
        }
        let policy = assets.policy_json();
        let manifest = assets.engine_manifest();
        let engine = assets.engine_binary();
        if policy.is_empty()
            || policy.len() as u64 > MAX_POLICY_BYTES
            || manifest.is_empty()
            || manifest.len() as u64 > MAX_MANIFEST_BYTES
            || engine.is_empty()
            || engine.len() as u64 > MAX_ENGINE_BYTES
        {
            return Err(GenerationStoreError::InvalidAsset);
        }
        let pending = self.pending_path(transaction_id);
        fs::create_dir(&pending).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        fs::set_permissions(&pending, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))
            .map_err(|_| GenerationStoreError::JournalUnavailable)?;
        validate_directory(
            &pending,
            self.expected_uid,
            self.expected_gid,
            STATE_DIRECTORY_MODE,
        )?;

        let previous_policy = self.capture_previous(
            &self.paths.policy_path,
            &pending.join(POLICY_BACKUP),
            POLICY_MODE,
            MAX_POLICY_BYTES,
        )?;
        let previous_manifest = self.capture_previous(
            &self.paths.manifest_path,
            &pending.join(MANIFEST_BACKUP),
            MANIFEST_MODE,
            MAX_MANIFEST_BYTES,
        )?;
        let previous_engine = self.capture_previous(
            &self.paths.engine_path,
            &pending.join(ENGINE_BACKUP),
            ENGINE_MODE,
            MAX_ENGINE_BYTES,
        )?;
        let journal = GenerationJournal {
            schema_version: 1,
            transaction_id: transaction_id.into(),
            phase: JournalPhase::Prepared,
            previous_policy,
            previous_manifest,
            previous_engine,
            policy_sha256: digest(policy),
            manifest_sha256: digest(manifest),
            engine_sha256: digest(engine),
            policy_size: policy.len() as u64,
            manifest_size: manifest.len() as u64,
            engine_size: engine.len() as u64,
        };
        self.write_journal(&journal)?;
        write_atomic(
            &self.paths.policy_path,
            policy,
            POLICY_MODE,
            self.expected_uid,
            self.expected_gid,
            transaction_id,
        )?;
        inject(fault, FaultPoint::AfterPolicy)?;
        write_atomic(
            &self.paths.manifest_path,
            manifest,
            MANIFEST_MODE,
            self.expected_uid,
            self.expected_gid,
            transaction_id,
        )?;
        inject(fault, FaultPoint::AfterManifest)?;
        write_atomic(
            &self.paths.engine_path,
            engine,
            ENGINE_MODE,
            self.expected_uid,
            self.expected_gid,
            transaction_id,
        )?;
        inject(fault, FaultPoint::AfterEngine)?;
        self.verify_active(&journal)
    }

    fn capture_previous(
        &self,
        source: &Path,
        backup: &Path,
        mode: u32,
        maximum: u64,
    ) -> Result<Option<AssetIdentity>, GenerationStoreError> {
        let Some(bytes) =
            read_optional_checked(source, self.expected_uid, self.expected_gid, mode, maximum)?
        else {
            return Ok(None);
        };
        write_new(backup, &bytes, mode, self.expected_uid, self.expected_gid)?;
        sync_directory(backup.parent().ok_or(GenerationStoreError::InvalidLayout)?)?;
        Ok(Some(AssetIdentity {
            size: bytes.len() as u64,
            sha256: digest(&bytes),
        }))
    }

    fn restore_one(
        &self,
        role: AssetRole,
        journal: &GenerationJournal,
    ) -> Result<(), GenerationStoreError> {
        let (destination, backup_name, previous, mode, maximum, active_size, active_sha256) =
            match role {
                AssetRole::Policy => (
                    self.paths.policy_path.as_path(),
                    POLICY_BACKUP,
                    journal.previous_policy.as_ref(),
                    POLICY_MODE,
                    MAX_POLICY_BYTES,
                    journal.policy_size,
                    journal.policy_sha256.as_str(),
                ),
                AssetRole::Manifest => (
                    self.paths.manifest_path.as_path(),
                    MANIFEST_BACKUP,
                    journal.previous_manifest.as_ref(),
                    MANIFEST_MODE,
                    MAX_MANIFEST_BYTES,
                    journal.manifest_size,
                    journal.manifest_sha256.as_str(),
                ),
                AssetRole::Engine => (
                    self.paths.engine_path.as_path(),
                    ENGINE_BACKUP,
                    journal.previous_engine.as_ref(),
                    ENGINE_MODE,
                    MAX_ENGINE_BYTES,
                    journal.engine_size,
                    journal.engine_sha256.as_str(),
                ),
            };
        if let Some(previous) = previous {
            let backup = self.pending_path(&journal.transaction_id).join(backup_name);
            let bytes = read_required_checked(
                &backup,
                self.expected_uid,
                self.expected_gid,
                mode,
                maximum,
            )?;
            if bytes.len() as u64 != previous.size || digest(&bytes) != previous.sha256 {
                return Err(GenerationStoreError::RecoveryRequired);
            }
            let current = read_required_checked(
                destination,
                self.expected_uid,
                self.expected_gid,
                mode,
                maximum,
            )?;
            if current == bytes {
                return Ok(());
            }
            if current.len() as u64 != active_size || digest(&current) != active_sha256 {
                return Err(GenerationStoreError::RecoveryRequired);
            }
            write_atomic(
                destination,
                &bytes,
                mode,
                self.expected_uid,
                self.expected_gid,
                &journal.transaction_id,
            )
        } else {
            let Some(current) = read_optional_checked(
                destination,
                self.expected_uid,
                self.expected_gid,
                mode,
                maximum,
            )?
            else {
                return Ok(());
            };
            if current.len() as u64 != active_size || digest(&current) != active_sha256 {
                return Err(GenerationStoreError::RecoveryRequired);
            }
            fs::remove_file(destination).map_err(|_| GenerationStoreError::RecoveryRequired)?;
            sync_directory(
                destination
                    .parent()
                    .ok_or(GenerationStoreError::InvalidLayout)?,
            )
        }
    }

    fn verify_active(&self, journal: &GenerationJournal) -> Result<(), GenerationStoreError> {
        verify_exact_file(
            &self.paths.policy_path,
            self.expected_uid,
            self.expected_gid,
            POLICY_MODE,
            journal.policy_size,
            &journal.policy_sha256,
        )?;
        verify_exact_file(
            &self.paths.manifest_path,
            self.expected_uid,
            self.expected_gid,
            MANIFEST_MODE,
            journal.manifest_size,
            &journal.manifest_sha256,
        )?;
        verify_exact_file(
            &self.paths.engine_path,
            self.expected_uid,
            self.expected_gid,
            ENGINE_MODE,
            journal.engine_size,
            &journal.engine_sha256,
        )
    }

    fn finish_commit(&self, journal: &GenerationJournal) -> Result<(), GenerationStoreError> {
        match fs::symlink_metadata(self.pending_path(&journal.transaction_id)) {
            Ok(_) => self.remove_pending(&journal.transaction_id)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(GenerationStoreError::JournalUnavailable),
        }
        self.remove_journal()
    }

    fn pending_path(&self, transaction_id: &str) -> PathBuf {
        self.paths
            .state_root
            .join(format!("pending-{transaction_id}"))
    }

    fn journal_path(&self) -> PathBuf {
        self.paths.state_root.join(JOURNAL_NAME)
    }

    fn require_journal(
        &self,
        transaction_id: &str,
    ) -> Result<GenerationJournal, GenerationStoreError> {
        if !valid_transaction_id(transaction_id) {
            return Err(GenerationStoreError::InvalidTransaction);
        }
        let journal = self
            .read_journal()?
            .ok_or(GenerationStoreError::RecoveryRequired)?;
        if journal.transaction_id != transaction_id {
            return Err(GenerationStoreError::InvalidTransaction);
        }
        Ok(journal)
    }

    fn read_journal(&self) -> Result<Option<GenerationJournal>, GenerationStoreError> {
        let Some(bytes) = read_optional_checked(
            &self.journal_path(),
            self.expected_uid,
            self.expected_gid,
            JOURNAL_MODE,
            4096,
        )?
        else {
            return Ok(None);
        };
        let journal: GenerationJournal =
            serde_json::from_slice(&bytes).map_err(|_| GenerationStoreError::RecoveryRequired)?;
        if journal.schema_version != 1
            || !valid_transaction_id(&journal.transaction_id)
            || !valid_sha256(&journal.policy_sha256)
            || !valid_sha256(&journal.manifest_sha256)
            || !valid_sha256(&journal.engine_sha256)
            || !valid_optional_identity(&journal.previous_policy, MAX_POLICY_BYTES)
            || !valid_optional_identity(&journal.previous_manifest, MAX_MANIFEST_BYTES)
            || !valid_optional_identity(&journal.previous_engine, MAX_ENGINE_BYTES)
            || journal.policy_size == 0
            || journal.policy_size > MAX_POLICY_BYTES
            || journal.manifest_size == 0
            || journal.manifest_size > MAX_MANIFEST_BYTES
            || journal.engine_size == 0
            || journal.engine_size > MAX_ENGINE_BYTES
        {
            return Err(GenerationStoreError::RecoveryRequired);
        }
        Ok(Some(journal))
    }

    fn write_journal(&self, journal: &GenerationJournal) -> Result<(), GenerationStoreError> {
        let bytes =
            serde_json::to_vec(journal).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        write_atomic(
            &self.journal_path(),
            &bytes,
            JOURNAL_MODE,
            self.expected_uid,
            self.expected_gid,
            &journal.transaction_id,
        )
    }

    fn remove_pending(&self, transaction_id: &str) -> Result<(), GenerationStoreError> {
        let pending = self.pending_path(transaction_id);
        validate_directory(
            &pending,
            self.expected_uid,
            self.expected_gid,
            STATE_DIRECTORY_MODE,
        )?;
        for name in [POLICY_BACKUP, MANIFEST_BACKUP, ENGINE_BACKUP] {
            let path = pending.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !valid_file_metadata(
                        &metadata,
                        self.expected_uid,
                        self.expected_gid,
                        match name {
                            POLICY_BACKUP => POLICY_MODE,
                            MANIFEST_BACKUP => MANIFEST_MODE,
                            _ => ENGINE_MODE,
                        },
                    ) {
                        return Err(GenerationStoreError::RecoveryRequired);
                    }
                    fs::remove_file(path).map_err(|_| GenerationStoreError::JournalUnavailable)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(GenerationStoreError::JournalUnavailable),
            }
        }
        let mut entries =
            fs::read_dir(&pending).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        if entries.next().is_some() {
            return Err(GenerationStoreError::RecoveryRequired);
        }
        fs::remove_dir(&pending).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        sync_directory(&self.paths.state_root)
    }

    fn remove_journal(&self) -> Result<(), GenerationStoreError> {
        let path = self.journal_path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        if !valid_file_metadata(
            &metadata,
            self.expected_uid,
            self.expected_gid,
            JOURNAL_MODE,
        ) {
            return Err(GenerationStoreError::RecoveryRequired);
        }
        fs::remove_file(path).map_err(|_| GenerationStoreError::JournalUnavailable)?;
        sync_directory(&self.paths.state_root)
    }

    #[cfg(test)]
    fn prepare_crash_fixture(
        &mut self,
        transaction_id: &str,
        assets: &ValidatedGenerationAssets,
        fault: FaultPoint,
    ) -> Result<(), GenerationStoreError> {
        self.prepare_inner(transaction_id, assets, fault)
    }
}

fn validate_paths(paths: &GenerationPaths) -> Result<(), GenerationStoreError> {
    if !paths.state_root.is_absolute()
        || !paths.policy_path.is_absolute()
        || !paths.engine_root.is_absolute()
        || !paths.manifest_path.is_absolute()
        || !paths.engine_path.is_absolute()
        || paths
            .policy_path
            .file_name()
            .and_then(|value| value.to_str())
            != Some("com.tunbridge.desktop.helper.policy.json")
        || paths.manifest_path.parent() != Some(paths.engine_root.as_path())
        || paths
            .manifest_path
            .file_name()
            .and_then(|value| value.to_str())
            != Some("manifest.json")
        || paths.engine_path.parent() != Some(paths.engine_root.as_path())
        || paths
            .engine_path
            .file_name()
            .and_then(|value| value.to_str())
            != Some("mihomo")
    {
        return Err(GenerationStoreError::InvalidLayout);
    }
    Ok(())
}

fn validate_directory(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), GenerationStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GenerationStoreError::InvalidLayout)?;
    if metadata.file_type().is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == mode
    {
        Ok(())
    } else {
        Err(GenerationStoreError::InvalidLayout)
    }
}

fn validate_safe_parent(path: &Path, uid: u32) -> Result<(), GenerationStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GenerationStoreError::InvalidLayout)?;
    if metadata.file_type().is_dir() && metadata.uid() == uid && metadata.mode() & 0o022 == 0 {
        Ok(())
    } else {
        Err(GenerationStoreError::InvalidLayout)
    }
}

fn open_checked(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    create: bool,
) -> Result<File, GenerationStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(mode)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    if valid_file_metadata(&metadata, uid, gid, mode) {
        Ok(file)
    } else {
        Err(GenerationStoreError::RecoveryRequired)
    }
}

fn valid_file_metadata(metadata: &fs::Metadata, uid: u32, gid: u32, mode: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == mode
        && metadata.nlink() == 1
}

fn read_optional_checked(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    maximum: u64,
) -> Result<Option<Vec<u8>>, GenerationStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if valid_file_metadata(&metadata, uid, gid, mode) => {
            if metadata.len() == 0 || metadata.len() > maximum {
                return Err(GenerationStoreError::RecoveryRequired);
            }
        }
        Ok(_) => return Err(GenerationStoreError::RecoveryRequired),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(GenerationStoreError::JournalUnavailable),
    }
    read_required_checked(path, uid, gid, mode, maximum).map(Some)
}

fn read_required_checked(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, GenerationStoreError> {
    let mut file = open_checked(path, uid, gid, mode, false)?;
    let before = file
        .metadata()
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    if before.len() == 0 || before.len() > maximum {
        return Err(GenerationStoreError::RecoveryRequired);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(GenerationStoreError::RecoveryRequired);
    }
    Ok(bytes)
}

fn write_new(
    path: &Path,
    contents: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), GenerationStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| GenerationStoreError::JournalUnavailable)?;
    if !valid_file_metadata(&metadata, uid, gid, mode) || metadata.len() != contents.len() as u64 {
        return Err(GenerationStoreError::RecoveryRequired);
    }
    Ok(())
}

fn write_atomic(
    destination: &Path,
    contents: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    transaction_id: &str,
) -> Result<(), GenerationStoreError> {
    let parent = destination
        .parent()
        .ok_or(GenerationStoreError::InvalidLayout)?;
    let temporary = parent.join(format!(".tunbridge-generation-{transaction_id}"));
    let result = (|| {
        write_new(&temporary, contents, mode, uid, gid)?;
        fs::rename(&temporary, destination)
            .map_err(|_| GenerationStoreError::JournalUnavailable)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn verify_exact_file(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: &str,
) -> Result<(), GenerationStoreError> {
    let bytes = read_required_checked(path, uid, gid, mode, size)?;
    if bytes.len() as u64 == size && digest(&bytes) == sha256 {
        Ok(())
    } else {
        Err(GenerationStoreError::RecoveryRequired)
    }
}

fn sync_directory(path: &Path) -> Result<(), GenerationStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| GenerationStoreError::JournalUnavailable)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_optional_identity(identity: &Option<AssetIdentity>, maximum: u64) -> bool {
    identity
        .as_ref()
        .is_none_or(|value| value.size > 0 && value.size <= maximum && valid_sha256(&value.sha256))
}

fn valid_transaction_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn inject(observed: FaultPoint, expected: FaultPoint) -> Result<(), GenerationStoreError> {
    if observed == expected {
        Err(GenerationStoreError::InjectedFailure)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap_assets::ValidatedGenerationAssets,
        bootstrap_protocol::{BootstrapCaller, GenerationMaterial},
        bundle_metadata::APP_BUNDLE_ID,
    };
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    const TX: &str = "0123456789abcdef0123456789abcdef";
    const CDHASH: &str = "1111111111111111111111111111111111111111";
    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    fn fixture_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-generation-store-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_TEST.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn setup(name: &str) -> (PathBuf, GenerationPaths, u32, u32) {
        let root = fixture_root(name);
        let paths = GenerationPaths::fixture(&root);
        fs::create_dir_all(&paths.state_root).unwrap();
        fs::create_dir_all(&paths.engine_root).unwrap();
        fs::create_dir_all(paths.policy_path.parent().unwrap()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&paths.state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&paths.engine_root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            paths.policy_path.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let metadata = fs::metadata(&root).unwrap();
        (root, paths, metadata.uid(), metadata.gid())
    }

    fn validated(engine: &[u8]) -> ValidatedGenerationAssets {
        let caller = BootstrapCaller {
            pid: 501,
            uid: 502,
            audit_session_id: 42,
            team_id: "ABCDE12345".into(),
            cdhash: CDHASH.into(),
        };
        let policy = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "teamId": "ABCDE12345",
            "appSigningIdentifier": APP_BUNDLE_ID,
            "allowedCdhashes": [CDHASH]
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "version": "v1.19.28",
            "targetTriple": "aarch64-apple-darwin",
            "binarySize": engine.len(),
            "binarySha256": digest(engine)
        }))
        .unwrap();
        let material = GenerationMaterial {
            transaction_id: TX.into(),
            caller_cdhash: CDHASH.into(),
            policy_sha256: digest(&policy),
            engine_manifest_sha256: digest(&manifest),
            engine_sha256: digest(engine),
            engine_size: engine.len() as u64,
            target_triple: "aarch64-apple-darwin".into(),
        };
        ValidatedGenerationAssets::validate(&caller, &material, policy, manifest, engine.to_vec())
            .unwrap()
    }

    fn active(paths: &GenerationPaths) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            fs::read(&paths.policy_path).unwrap(),
            fs::read(&paths.manifest_path).unwrap(),
            fs::read(&paths.engine_path).unwrap(),
        )
    }

    fn seed_previous(paths: &GenerationPaths, uid: u32, gid: u32) {
        write_new(&paths.policy_path, b"old-policy", POLICY_MODE, uid, gid).unwrap();
        write_new(
            &paths.manifest_path,
            b"old-manifest",
            MANIFEST_MODE,
            uid,
            gid,
        )
        .unwrap();
        write_new(&paths.engine_path, b"old-engine", ENGINE_MODE, uid, gid).unwrap();
    }

    #[test]
    fn prepare_commit_and_rollback_preserve_exact_generations() {
        let (root, paths, uid, gid) = setup("commit-rollback");
        seed_previous(&paths, uid, gid);
        let previous = active(&paths);
        let assets = validated(b"new-engine");
        {
            let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
            store.prepare_generation(TX, &assets).unwrap();
            assert_eq!(active(&paths).2, b"new-engine");
            store.rollback_generation(TX).unwrap();
            assert_eq!(active(&paths), previous);
            store.prepare_generation(TX, &assets).unwrap();
            store.commit_generation(TX).unwrap();
            assert_eq!(active(&paths).2, b"new-engine");
            assert!(!store.journal_path().exists());
            assert!(!store.pending_path(TX).exists());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_prepare_crash_recovers_the_previous_generation() {
        for fault in [
            FaultPoint::AfterPolicy,
            FaultPoint::AfterManifest,
            FaultPoint::AfterEngine,
        ] {
            let (root, paths, uid, gid) = setup("prepare-crash");
            seed_previous(&paths, uid, gid);
            let previous = active(&paths);
            let assets = validated(b"new-engine");
            {
                let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                assert_eq!(
                    store.prepare_crash_fixture(TX, &assets, fault),
                    Err(GenerationStoreError::InjectedFailure)
                );
            }
            {
                let mut recovered = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                recovered.recover_pending().unwrap();
                assert_eq!(active(&paths), previous);
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn first_install_crash_removes_every_partially_created_asset() {
        for fault in [
            FaultPoint::AfterPolicy,
            FaultPoint::AfterManifest,
            FaultPoint::AfterEngine,
        ] {
            let (root, paths, uid, gid) = setup("first-install-crash");
            let assets = validated(b"new-engine");
            {
                let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                assert_eq!(
                    store.prepare_crash_fixture(TX, &assets, fault),
                    Err(GenerationStoreError::InjectedFailure)
                );
            }
            {
                let mut recovered = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                recovered.recover_pending().unwrap();
                assert!(!paths.policy_path.exists());
                assert!(!paths.manifest_path.exists());
                assert!(!paths.engine_path.exists());
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn committing_journal_converges_to_the_verified_new_generation() {
        for pending_was_removed in [false, true] {
            let (root, paths, uid, gid) = setup("commit-crash");
            seed_previous(&paths, uid, gid);
            let assets = validated(b"new-engine");
            {
                let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                store.prepare_generation(TX, &assets).unwrap();
                let mut journal = store.require_journal(TX).unwrap();
                journal.phase = JournalPhase::Committing;
                store.write_journal(&journal).unwrap();
                if pending_was_removed {
                    store.remove_pending(TX).unwrap();
                }
            }
            {
                let mut recovered = GenerationStore::open(paths.clone(), uid, gid).unwrap();
                recovered.recover_pending().unwrap();
                assert_eq!(active(&paths).2, b"new-engine");
                assert!(!recovered.journal_path().exists());
                assert!(!recovered.pending_path(TX).exists());
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn corrupted_previous_asset_and_concurrent_writer_fail_closed() {
        let (root, paths, uid, gid) = setup("corrupt-backup");
        seed_previous(&paths, uid, gid);
        let assets = validated(b"new-engine");
        let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
        assert!(matches!(
            GenerationStore::open(paths.clone(), uid, gid),
            Err(GenerationStoreError::Busy)
        ));
        store.prepare_generation(TX, &assets).unwrap();
        fs::write(store.pending_path(TX).join(ENGINE_BACKUP), b"bad-engine").unwrap();
        assert_eq!(
            store.rollback_generation(TX),
            Err(GenerationStoreError::RecoveryRequired)
        );
        assert!(store.journal_path().exists());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn substituted_symlink_hardlink_and_transaction_fail_closed() {
        let (root, paths, uid, gid) = setup("unsafe-layout");
        let assets = validated(b"new-engine");
        let outside = root.join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, &paths.policy_path).unwrap();
        let mut store = GenerationStore::open(paths.clone(), uid, gid).unwrap();
        assert_eq!(
            store.prepare_generation(TX, &assets),
            Err(GenerationStoreError::RecoveryRequired)
        );
        fs::remove_file(&paths.policy_path).unwrap();
        assert_eq!(
            store.prepare_generation("../substitution", &assets),
            Err(GenerationStoreError::InvalidTransaction)
        );
        write_new(&paths.engine_path, b"linked", ENGINE_MODE, uid, gid).unwrap();
        fs::hard_link(&paths.engine_path, root.join("engine-link")).unwrap();
        assert_eq!(
            store.prepare_generation(TX, &assets),
            Err(GenerationStoreError::RecoveryRequired)
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
