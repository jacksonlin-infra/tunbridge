use std::{
    ffi::c_void,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::windows::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_ALREADY_EXISTS, HLOCAL},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateDirectoryW, MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

use super::{
    integrity::{reject_reparse_point, validate_asset_acl, IntegrityError},
    owned::OwnedEngineRecord,
    random::random_hex_32,
};

const DATA_DIRECTORY_SDDL: &str = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const ACTIVE_CONFIG_FILENAME: &str = "active-config.yaml";
const ENGINE_CACHE_FILENAME: &str = "cache.db";
const OWNED_STATE_FILENAME: &str = "owned-engine.json";
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024;

/// Remove only the fixed inactive runtime residue after an authenticated
/// Recover and SCM shutdown. Any unknown entry or remaining owned state keeps
/// the protected evidence in place and fails closed.
pub fn cleanup_product_data_for_uninstall() -> Result<(), StorageError> {
    let program_data = program_data_directory()?;
    reject_reparse_point(&program_data, "ProgramData").map_err(StorageError::Integrity)?;
    let product = program_data.join("TunBridge");
    if !product.exists() {
        return Ok(());
    }
    reject_reparse_point(&product, "product data directory").map_err(StorageError::Integrity)?;
    validate_asset_acl(&product, "product data directory").map_err(StorageError::Integrity)?;
    let run = product.join("run");
    if !run.exists() {
        return remove_empty_directory(&product);
    }
    reject_reparse_point(&run, "runtime data directory").map_err(StorageError::Integrity)?;
    validate_asset_acl(&run, "runtime data directory").map_err(StorageError::Integrity)?;

    let entries = fs::read_dir(&run)?.collect::<Result<Vec<_>, _>>()?;
    for entry in &entries {
        if !is_known_inactive_runtime_asset(&entry.file_name()) {
            return Err(StorageError::UnexpectedUninstallAsset);
        }
        let path = entry.path();
        reject_reparse_point(&path, "active config").map_err(StorageError::Integrity)?;
        validate_asset_acl(&path, "active config").map_err(StorageError::Integrity)?;
        if !entry.file_type()?.is_file() {
            return Err(StorageError::UnexpectedUninstallAsset);
        }
    }
    for entry in entries {
        fs::remove_file(entry.path())?;
    }
    remove_empty_directory(&run)?;
    remove_empty_directory(&product)
}

fn is_known_inactive_runtime_asset(filename: &std::ffi::OsStr) -> bool {
    filename == ACTIVE_CONFIG_FILENAME || filename == ENGINE_CACHE_FILENAME
}

fn remove_empty_directory(path: &Path) -> Result<(), StorageError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
            Err(StorageError::UnexpectedUninstallAsset)
        }
        Err(error) => Err(StorageError::Io(error)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedDataDirectory {
    root: PathBuf,
}

impl ProtectedDataDirectory {
    /// Resolve and create the fixed machine-wide runtime directory. No caller
    /// path or environment variable participates in this boundary.
    pub fn prepare() -> Result<Self, StorageError> {
        let program_data = program_data_directory()?;
        reject_reparse_point(&program_data, "ProgramData").map_err(StorageError::Integrity)?;

        // ProgramData intentionally permits standard users to create their own
        // top-level children. Create the fixed product child with an explicit
        // protected descriptor, then reject a pre-created/squatted child unless
        // its owner and DACL already match the privileged asset policy.
        let product = program_data.join("TunBridge");
        create_secure_directory(&product)?;
        reject_reparse_point(&product, "product data directory")
            .map_err(StorageError::Integrity)?;
        validate_asset_acl(&product, "product data directory").map_err(StorageError::Integrity)?;

        let root = product.join("run");
        create_secure_directory(&root)?;
        reject_reparse_point(&root, "runtime data directory").map_err(StorageError::Integrity)?;
        validate_asset_acl(&root, "runtime data directory").map_err(StorageError::Integrity)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    pub(super) fn for_test(root: PathBuf) -> Self {
        Self { root }
    }

    /// Write a unique candidate without changing the current active config.
    pub fn write_candidate(&self, yaml: &str) -> Result<PathBuf, StorageError> {
        if yaml.len() > MAX_CONFIG_BYTES {
            return Err(StorageError::ConfigTooLarge(yaml.len()));
        }
        self.revalidate()?;
        let candidate = self
            .root
            .join(format!("candidate-{}.yaml", random_hex_32()?));
        write_new_synced(&candidate, yaml.as_bytes())?;
        let validation = reject_reparse_point(&candidate, "candidate config")
            .and_then(|()| validate_asset_acl(&candidate, "candidate config"));
        if let Err(error) = validation {
            let _ = fs::remove_file(&candidate);
            return Err(StorageError::Integrity(error));
        }
        Ok(candidate)
    }

    /// Promote a validated candidate with a same-volume write-through rename.
    pub fn promote_candidate(&self, candidate: &Path) -> Result<PathBuf, StorageError> {
        self.revalidate()?;
        if !self.is_candidate(candidate) {
            return Err(StorageError::CandidateEscape);
        }
        reject_reparse_point(candidate, "candidate config").map_err(StorageError::Integrity)?;
        validate_asset_acl(candidate, "candidate config").map_err(StorageError::Integrity)?;
        let active = self.root.join(ACTIVE_CONFIG_FILENAME);
        if active.exists() {
            reject_reparse_point(&active, "active config").map_err(StorageError::Integrity)?;
            validate_asset_acl(&active, "active config").map_err(StorageError::Integrity)?;
        }
        move_replace_write_through(candidate, &active)?;
        reject_reparse_point(&active, "active config").map_err(StorageError::Integrity)?;
        validate_asset_acl(&active, "active config").map_err(StorageError::Integrity)?;
        Ok(active)
    }

    pub fn remove_candidate(&self, candidate: &Path) -> Result<(), StorageError> {
        if !self.is_candidate(candidate) {
            return Err(StorageError::CandidateEscape);
        }
        match fs::remove_file(candidate) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StorageError::Io(error)),
        }
    }

    pub fn write_owned_state(&self, record: &OwnedEngineRecord) -> Result<PathBuf, StorageError> {
        let json = encode_owned_state(record)?;
        self.revalidate()?;
        let candidate = self.root.join(format!("state-{}.json", random_hex_32()?));
        write_new_synced(&candidate, &json)?;
        let validation = reject_reparse_point(&candidate, "owned state candidate")
            .and_then(|()| validate_asset_acl(&candidate, "owned state candidate"));
        if let Err(error) = validation {
            let _ = fs::remove_file(&candidate);
            return Err(StorageError::Integrity(error));
        }

        let state = self.root.join(OWNED_STATE_FILENAME);
        if state.exists() {
            reject_reparse_point(&state, "owned state").map_err(StorageError::Integrity)?;
            validate_asset_acl(&state, "owned state").map_err(StorageError::Integrity)?;
        }
        if let Err(error) = move_replace_write_through(&candidate, &state) {
            let _ = fs::remove_file(&candidate);
            return Err(error);
        }
        reject_reparse_point(&state, "owned state").map_err(StorageError::Integrity)?;
        validate_asset_acl(&state, "owned state").map_err(StorageError::Integrity)?;
        Ok(state)
    }

    pub fn read_owned_state(&self) -> Result<Option<OwnedEngineRecord>, StorageError> {
        self.revalidate()?;
        let state = self.root.join(OWNED_STATE_FILENAME);
        if !state.exists() {
            return Ok(None);
        }
        reject_reparse_point(&state, "owned state").map_err(StorageError::Integrity)?;
        validate_asset_acl(&state, "owned state").map_err(StorageError::Integrity)?;
        let metadata = state.metadata()?;
        if metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(StorageError::StateTooLarge(metadata.len()));
        }
        let file = fs::File::open(&state)?;
        let mut json = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut json)?;
        decode_owned_state(&json).map(Some)
    }

    pub fn read_active_config(&self) -> Result<String, StorageError> {
        self.revalidate()?;
        let active = self.root.join(ACTIVE_CONFIG_FILENAME);
        reject_reparse_point(&active, "active config").map_err(StorageError::Integrity)?;
        validate_asset_acl(&active, "active config").map_err(StorageError::Integrity)?;
        let metadata = active.metadata()?;
        if metadata.len() > MAX_CONFIG_BYTES as u64 {
            return Err(StorageError::ConfigTooLarge(metadata.len() as usize));
        }
        let file = fs::File::open(active)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(StorageError::ConfigTooLarge(bytes.len()));
        }
        String::from_utf8(bytes).map_err(|_| StorageError::InvalidConfigEncoding)
    }

    pub fn clear_owned_state(&self) -> Result<(), StorageError> {
        self.revalidate()?;
        let state = self.root.join(OWNED_STATE_FILENAME);
        if !state.exists() {
            return Ok(());
        }
        reject_reparse_point(&state, "owned state").map_err(StorageError::Integrity)?;
        validate_asset_acl(&state, "owned state").map_err(StorageError::Integrity)?;
        fs::remove_file(state).map_err(StorageError::Io)
    }

    fn is_candidate(&self, candidate: &Path) -> bool {
        candidate.parent() == Some(self.root.as_path())
            && candidate.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with("candidate-") && name.ends_with(".yaml")
            })
    }

    fn revalidate(&self) -> Result<(), StorageError> {
        reject_reparse_point(&self.root, "runtime data directory")
            .map_err(StorageError::Integrity)?;
        validate_asset_acl(&self.root, "runtime data directory").map_err(StorageError::Integrity)
    }
}

fn encode_owned_state(record: &OwnedEngineRecord) -> Result<Vec<u8>, StorageError> {
    record
        .validate()
        .map_err(|error| StorageError::InvalidOwnedState(error.to_string()))?;
    let json = serde_json::to_vec(record).map_err(StorageError::StateJson)?;
    if json.len() > MAX_STATE_BYTES {
        return Err(StorageError::StateTooLarge(json.len() as u64));
    }
    Ok(json)
}

fn decode_owned_state(json: &[u8]) -> Result<OwnedEngineRecord, StorageError> {
    if json.len() > MAX_STATE_BYTES {
        return Err(StorageError::StateTooLarge(json.len() as u64));
    }
    let record: OwnedEngineRecord =
        serde_json::from_slice(json).map_err(StorageError::StateJson)?;
    record
        .validate()
        .map_err(|error| StorageError::InvalidOwnedState(error.to_string()))?;
    Ok(record)
}

fn create_secure_directory(path: &Path) -> Result<(), StorageError> {
    if path.exists() {
        return Ok(());
    }
    let descriptor = SecurityDescriptor::from_sddl(DATA_DIRECTORY_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    // SAFETY: wide is NUL-terminated and attributes references a valid
    // self-relative descriptor for the duration of the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(StorageError::Io(error));
        }
    }
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(StorageError::Io(error));
    }
    Ok(())
}

fn move_replace_write_through(source: &Path, destination: &Path) -> Result<(), StorageError> {
    let source = wide_path(source);
    let destination = wide_path(destination);
    // SAFETY: both paths are NUL-terminated. The files are on the same fixed
    // volume and flags request replacement only after candidate validation.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(StorageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn program_data_directory() -> Result<PathBuf, StorageError> {
    let mut raw = ptr::null_mut();
    // SAFETY: raw points to writable storage and Windows allocates the path.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut raw) };
    if result < 0 {
        return Err(StorageError::KnownFolder(result));
    }
    let mut length = 0_usize;
    // SAFETY: successful SHGetKnownFolderPath returns a NUL-terminated string.
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let path = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map(PathBuf::from)
        .map_err(|_| StorageError::InvalidKnownFolder);
    // SAFETY: SHGetKnownFolderPath allocates with the COM task allocator.
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    path
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, StorageError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        // SAFETY: wide is NUL-terminated and raw points to writable storage.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(StorageError::Io(io::Error::last_os_error()));
        }
        Ok(Self(raw))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the descriptor was allocated by LocalAlloc.
            unsafe {
                LocalFree(self.0.cast::<c_void>() as HLOCAL);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("protected data I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("ProgramData known-folder lookup failed with HRESULT {0:#x}")]
    KnownFolder(i32),
    #[error("ProgramData path is invalid UTF-16")]
    InvalidKnownFolder,
    #[error("candidate config escaped the protected runtime directory")]
    CandidateEscape,
    #[error("rendered config exceeds {MAX_CONFIG_BYTES} bytes: {0}")]
    ConfigTooLarge(usize),
    #[error("active config is not valid UTF-8")]
    InvalidConfigEncoding,
    #[error("owned-engine state exceeds {MAX_STATE_BYTES} bytes: {0}")]
    StateTooLarge(u64),
    #[error("owned-engine state JSON is invalid: {0}")]
    StateJson(#[source] serde_json::Error),
    #[error("owned-engine state failed validation: {0}")]
    InvalidOwnedState(String),
    #[error("protected product data contains an unexpected uninstall asset")]
    UnexpectedUninstallAsset,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("tunbridge-storage-{}-{unique}", std::process::id()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn write_then_promote_replaces_only_after_complete_candidate() {
        let fixture = Fixture::new();
        let active = fixture.0.join(ACTIVE_CONFIG_FILENAME);
        fs::write(&active, "old").unwrap();
        let candidate = fixture.0.join("candidate-test.yaml");
        write_new_synced(&candidate, b"new").unwrap();
        assert_eq!(fs::read_to_string(&active).unwrap(), "old");
        move_replace_write_through(&candidate, &active).unwrap();
        assert_eq!(fs::read_to_string(&active).unwrap(), "new");
        assert!(!candidate.exists());
    }

    #[test]
    fn secure_directory_sddl_is_valid() {
        SecurityDescriptor::from_sddl(DATA_DIRECTORY_SDDL).unwrap();
    }

    #[test]
    fn uninstall_runtime_asset_allowlist_is_exact() {
        assert!(is_known_inactive_runtime_asset(std::ffi::OsStr::new(
            ACTIVE_CONFIG_FILENAME
        )));
        assert!(is_known_inactive_runtime_asset(std::ffi::OsStr::new(
            ENGINE_CACHE_FILENAME
        )));
        for rejected in [
            OWNED_STATE_FILENAME,
            "cache.db-wal",
            "cache.db-shm",
            "candidate-forged.yaml",
            "..\\cache.db",
        ] {
            assert!(!is_known_inactive_runtime_asset(std::ffi::OsStr::new(
                rejected
            )));
        }
    }

    #[test]
    fn program_data_known_folder_is_not_a_reparse_point() {
        let root = program_data_directory().unwrap();
        reject_reparse_point(&root, "ProgramData").unwrap();
    }

    #[test]
    fn candidate_scope_and_size_are_bounded_before_writes() {
        let fixture = Fixture::new();
        let storage = ProtectedDataDirectory {
            root: fixture.0.clone(),
        };
        assert!(storage.is_candidate(&fixture.0.join("candidate-a.yaml")));
        assert!(!storage.is_candidate(&fixture.0.join("active-config.yaml")));
        assert!(!storage.is_candidate(&fixture.0.join("..\\candidate-a.yaml")));
        assert!(matches!(
            storage.write_candidate(&"x".repeat(MAX_CONFIG_BYTES + 1)),
            Err(StorageError::ConfigTooLarge(_))
        ));
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
    }

    #[test]
    fn owned_state_codec_is_strict_and_size_bounded() {
        let record = OwnedEngineRecord {
            schema_version: 3,
            product_version: env!("CARGO_PKG_VERSION").into(),
            stage: super::super::OwnedEngineStage::Running,
            pid: 42,
            creation_time: 123,
            image_path: PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe"),
            engine_version: "1.19.18".into(),
            engine_sha256: "a".repeat(64),
            owner_principal_id: "S-1-5-21-test".into(),
            owner_session_id: 7,
            upstream_host: "127.0.0.1".into(),
            upstream_port: 7078,
            upstream_protocol: crate::protocol::UpstreamProtocol::Socks5,
            remote_upstream: false,
            upstream_pid: 99,
            upstream_creation_time: 456,
            upstream_image_path: PathBuf::from(r"C:\Program Files\ExampleProxy\exampleproxy.exe"),
            controller_host: "127.0.0.1".into(),
            controller_port: 25412,
            adapter_alias: "tunbridge".into(),
            preexisting_wintun_instances: Vec::new(),
            adapter_instance_id: Some("SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}".into()),
        };

        let encoded = encode_owned_state(&record).unwrap();
        assert_eq!(decode_owned_state(&encoded).unwrap(), record);

        let mut unknown = encoded;
        unknown.splice(1..1, br#""command":"taskkill","#.iter().copied());
        assert!(matches!(
            decode_owned_state(&unknown),
            Err(StorageError::StateJson(_))
        ));
        assert!(matches!(
            decode_owned_state(&vec![b'x'; MAX_STATE_BYTES + 1]),
            Err(StorageError::StateTooLarge(_))
        ));
    }
}
