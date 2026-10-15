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

pub struct LinuxProfileStoreFiles {
    root: PathBuf,
    effective_user_id: u32,
}

impl LinuxProfileStoreFiles {
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

    pub fn acquire_lock(&self, filename: &str) -> Result<LinuxProfileStoreLock, AdapterError> {
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
        Ok(LinuxProfileStoreLock(file))
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

pub struct LinuxProfileStoreLock(File);

impl Drop for LinuxProfileStoreLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl ProfileStoreFiles for LinuxProfileStoreFiles {
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
            let metadata = fs::symlink_metadata(root).map_err(|_| unavailable())?;
            validate_directory_metadata(&metadata)
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
        "The Linux profile store contains invalid data.",
        false,
    )
}

const fn identity_rejected() -> AdapterError {
    adapter_error(
        AdapterErrorCode::IdentityRejected,
        "The Linux profile store identity could not be verified.",
        false,
    )
}

const fn permission_denied() -> AdapterError {
    adapter_error(
        AdapterErrorCode::PermissionDenied,
        "The Linux profile store could not be created securely.",
        false,
    )
}

const fn busy() -> AdapterError {
    adapter_error(
        AdapterErrorCode::Unavailable,
        "Another Linux profile operation is already active.",
        true,
    )
}

const fn unavailable() -> AdapterError {
    adapter_error(
        AdapterErrorCode::Unavailable,
        "The Linux profile store is unavailable.",
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
            "tunbridge-linux-profile-files-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn creates_private_directory_and_atomically_replaces_private_file() {
        let root = test_root("replace");
        let files = LinuxProfileStoreFiles::open(root.clone()).unwrap();
        let path = root.join("profiles.json");

        files.replace_atomically(&path, b"first").unwrap();
        assert_eq!(
            files.read_bounded(&path, 64).unwrap(),
            Some(b"first".to_vec())
        );
        files.replace_atomically(&path, b"second").unwrap();
        assert_eq!(
            files.read_bounded(&path, 64).unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            DIRECTORY_MODE
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            FILE_MODE
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_lock_is_non_blocking_and_reusable() {
        let root = test_root("lock");
        let files = LinuxProfileStoreFiles::open(root.clone()).unwrap();
        let lock = files.acquire_lock("profile-store-v1.lock").unwrap();
        assert!(matches!(
            files.acquire_lock("profile-store-v1.lock"),
            Err(error) if error.retryable
        ));
        drop(lock);
        files.acquire_lock("profile-store-v1.lock").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_escape_nested_symlink_and_oversize_targets() {
        let root = test_root("reject");
        let outside = test_root("outside");
        fs::create_dir_all(&outside).unwrap();
        let files = LinuxProfileStoreFiles::open(root.clone()).unwrap();

        assert_eq!(
            files.read_bounded(&outside.join("profiles.json"), 64),
            Err(identity_rejected())
        );
        assert_eq!(
            files.read_bounded(&root.join("nested/profiles.json"), 64),
            Err(identity_rejected())
        );

        let symlink_path = root.join("profiles.json");
        symlink(outside.join("target"), &symlink_path).unwrap();
        assert_eq!(
            files.read_bounded(&symlink_path, 64),
            Err(identity_rejected())
        );
        fs::remove_file(&symlink_path).unwrap();

        let oversize_path = root.join("oversize.json");
        files.replace_atomically(&oversize_path, &[7; 65]).unwrap();
        assert_eq!(files.read_bounded(&oversize_path, 64), Err(invalid_data()));

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn refuses_insecure_root_and_non_private_existing_file() {
        let root = test_root("mode");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            LinuxProfileStoreFiles::open(root.clone()),
            Err(error) if error.code == AdapterErrorCode::IdentityRejected
        ));

        fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let files = LinuxProfileStoreFiles::open(root.clone()).unwrap();
        let path = root.join("profiles.json");
        fs::write(&path, b"public").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(files.read_bounded(&path, 64), Err(identity_rejected()));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_is_exact_and_idempotent() {
        let root = test_root("remove");
        let files = LinuxProfileStoreFiles::open(root.clone()).unwrap();
        let path = root.join("profiles.json");
        files.replace_atomically(&path, b"data").unwrap();
        files.remove_exact(&path).unwrap();
        files.remove_exact(&path).unwrap();
        assert_eq!(files.read_bounded(&path, 64).unwrap(), None);

        fs::remove_dir_all(root).unwrap();
    }
}
