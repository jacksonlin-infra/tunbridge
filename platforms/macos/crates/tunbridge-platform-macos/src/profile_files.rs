use libc::{O_CLOEXEC, O_NOFOLLOW};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ProfileStoreFiles};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(1);

pub struct MacosProfileStoreFiles {
    root: PathBuf,
    effective_user_id: u32,
}

impl MacosProfileStoreFiles {
    pub fn open(root: PathBuf) -> Result<Self, AdapterError> {
        if !root.is_absolute() {
            return Err(invalid_data());
        }
        ensure_directory(&root)?;
        Ok(Self {
            root,
            effective_user_id: unsafe { libc::geteuid() },
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn acquire_lock(&self, filename: &str) -> Result<MacosProfileStoreLock, AdapterError> {
        if filename.is_empty()
            || filename.len() > 64
            || !filename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid_data());
        }
        ensure_directory(&self.root)?;
        let path = self.root.join(filename);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(&path)
            .map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != self.effective_user_id
            || metadata.mode() & 0o777 != FILE_MODE
            || metadata.nlink() != 1
        {
            return Err(identity_rejected());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                Err(busy())
            } else {
                Err(unavailable())
            };
        }
        Ok(MacosProfileStoreLock(file))
    }

    fn checked_path(&self, path: &Path) -> Result<PathBuf, AdapterError> {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return Err(identity_rejected());
        };
        let mut components = relative.components();
        let Some(Component::Normal(filename)) = components.next() else {
            return Err(identity_rejected());
        };
        if components.next().is_some() || filename.is_empty() {
            return Err(identity_rejected());
        }
        Ok(self.root.join(filename))
    }

    fn validate_existing_file(&self, path: &Path) -> Result<Option<fs::Metadata>, AdapterError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unavailable()),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != self.effective_user_id
            || metadata.mode() & 0o777 != FILE_MODE
            || metadata.nlink() != 1
        {
            return Err(identity_rejected());
        }
        Ok(Some(metadata))
    }
}

pub struct MacosProfileStoreLock(File);

impl Drop for MacosProfileStoreLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl ProfileStoreFiles for MacosProfileStoreFiles {
    fn read_bounded(
        &self,
        path: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, AdapterError> {
        let path = self.checked_path(path)?;
        let Some(before) = self.validate_existing_file(&path)? else {
            return Ok(None);
        };
        if before.len() > maximum_bytes as u64 {
            return Err(invalid_data());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(&path)
            .map_err(|_| identity_rejected())?;
        let opened = file.metadata().map_err(|_| unavailable())?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(identity_rejected());
        }
        let mut contents = Vec::with_capacity(opened.len() as usize);
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1) as u64)
            .read_to_end(&mut contents)
            .map_err(|_| unavailable())?;
        if contents.len() > maximum_bytes {
            return Err(invalid_data());
        }
        Ok(Some(contents))
    }

    fn replace_atomically(&self, path: &Path, contents: &[u8]) -> Result<(), AdapterError> {
        let path = self.checked_path(path)?;
        let _ = self.validate_existing_file(&path)?;
        let temporary = self.root.join(format!(
            ".tunbridge-write-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .custom_flags(O_NOFOLLOW | O_CLOEXEC)
                .open(&temporary)
                .map_err(|_| unavailable())?;
            file.write_all(contents).map_err(|_| unavailable())?;
            file.sync_all().map_err(|_| unavailable())?;
            fs::rename(&temporary, &path).map_err(|_| unavailable())?;
            File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| unavailable())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove_exact(&self, path: &Path) -> Result<(), AdapterError> {
        let path = self.checked_path(path)?;
        if self.validate_existing_file(&path)?.is_none() {
            return Ok(());
        }
        fs::remove_file(path).map_err(|_| unavailable())?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable())
    }
}

fn ensure_directory(root: &Path) -> Result<(), AdapterError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_directory_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|_| permission_denied())?;
            fs::set_permissions(root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| permission_denied())?;
            validate_directory_metadata(&fs::symlink_metadata(root).map_err(|_| unavailable())?)
        }
        Err(_) => Err(unavailable()),
    }
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), AdapterError> {
    if metadata.file_type().is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o777 == DIRECTORY_MODE
    {
        Ok(())
    } else {
        Err(identity_rejected())
    }
}

const fn invalid_data() -> AdapterError {
    adapter_error(
        AdapterErrorCode::InvalidData,
        "The macOS profile store contains invalid data.",
        false,
    )
}
const fn identity_rejected() -> AdapterError {
    adapter_error(
        AdapterErrorCode::IdentityRejected,
        "The macOS profile store identity could not be verified.",
        false,
    )
}
const fn permission_denied() -> AdapterError {
    adapter_error(
        AdapterErrorCode::PermissionDenied,
        "The macOS profile store could not be created securely.",
        false,
    )
}
const fn busy() -> AdapterError {
    adapter_error(
        AdapterErrorCode::Unavailable,
        "Another macOS profile operation is already active.",
        true,
    )
}
const fn unavailable() -> AdapterError {
    adapter_error(
        AdapterErrorCode::Unavailable,
        "The macOS profile store is unavailable.",
        true,
    )
}
const fn adapter_error(
    code: AdapterErrorCode,
    safe_message: &'static str,
    retryable: bool,
) -> AdapterError {
    AdapterError {
        code,
        safe_message,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-macos-profile-files-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn private_file_round_trip_and_locking() {
        let root = test_root("round-trip");
        let files = MacosProfileStoreFiles::open(root.clone()).unwrap();
        let path = root.join("profiles.json");
        files.replace_atomically(&path, b"first").unwrap();
        assert_eq!(
            files.read_bounded(&path, 64).unwrap(),
            Some(b"first".to_vec())
        );
        let lock = files.acquire_lock("profile-store-v1.lock").unwrap();
        assert!(
            matches!(files.acquire_lock("profile-store-v1.lock"), Err(error) if error.retryable)
        );
        drop(lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_escape_symlink_oversize_and_insecure_root() {
        let root = test_root("reject");
        let outside = test_root("outside");
        fs::create_dir_all(&outside).unwrap();
        let files = MacosProfileStoreFiles::open(root.clone()).unwrap();
        assert_eq!(
            files.read_bounded(&outside.join("profiles.json"), 64),
            Err(identity_rejected())
        );
        let path = root.join("profiles.json");
        symlink(outside.join("target"), &path).unwrap();
        assert_eq!(files.read_bounded(&path, 64), Err(identity_rejected()));
        fs::remove_file(&path).unwrap();
        files.replace_atomically(&path, &[7; 65]).unwrap();
        assert_eq!(files.read_bounded(&path, 64), Err(invalid_data()));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();

        let insecure = test_root("insecure");
        fs::create_dir_all(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(MacosProfileStoreFiles::open(insecure.clone()).is_err());
        fs::remove_dir_all(insecure).unwrap();
    }
}
