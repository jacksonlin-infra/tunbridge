use crate::{
    lifecycle_host::{HostError, OwnedJournal},
    lifecycle_plan::OwnedRunRecord,
};
use libc::{O_CLOEXEC, O_NOFOLLOW};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const SYSTEM_ROOT: &str = "/Library/Application Support/com.tunbridge.desktop/helper";
const RECORD_NAME: &str = "owned-run-v1.json";
const LOCK_NAME: &str = "owned-run-v1.lock";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_RECORD_BYTES: usize = 65_536;
static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(1);

pub struct MacosOwnedJournal {
    root: PathBuf,
    expected_uid: u32,
    _lock: File,
}

impl MacosOwnedJournal {
    pub fn open_system() -> Result<Self, HostError> {
        Self::open_inner(PathBuf::from(SYSTEM_ROOT), 0, false)
    }

    pub fn open(root: PathBuf, expected_uid: u32) -> Result<Self, HostError> {
        Self::open_inner(root, expected_uid, true)
    }

    fn open_inner(
        root: PathBuf,
        expected_uid: u32,
        create_directory: bool,
    ) -> Result<Self, HostError> {
        if !root.is_absolute() {
            return Err(HostError::InvalidInput);
        }
        ensure_directory(&root, expected_uid, create_directory)?;
        let lock_path = root.join(LOCK_NAME);
        let lock = open_checked_file(&lock_path, expected_uid, true)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(HostError::JournalUnavailable);
        }
        Ok(Self {
            root,
            expected_uid,
            _lock: lock,
        })
    }

    fn record_path(&self) -> PathBuf {
        self.root.join(RECORD_NAME)
    }

    fn read_record(&self) -> Result<Option<OwnedRunRecord>, HostError> {
        let path = self.record_path();
        let before = match checked_metadata(&path, self.expected_uid)? {
            Some(metadata) => metadata,
            None => return Ok(None),
        };
        if before.len() > MAX_RECORD_BYTES as u64 {
            return Err(HostError::RecoveryRequired);
        }
        let mut file = open_checked_file(&path, self.expected_uid, false)?;
        let opened = file.metadata().map_err(|_| HostError::JournalUnavailable)?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(HostError::RecoveryRequired);
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        Read::by_ref(&mut file)
            .take((MAX_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| HostError::JournalUnavailable)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(HostError::RecoveryRequired);
        }
        let record: OwnedRunRecord =
            serde_json::from_slice(&bytes).map_err(|_| HostError::RecoveryRequired)?;
        record.validate().map_err(|_| HostError::RecoveryRequired)?;
        Ok(Some(record))
    }

    fn sync_root(&self) -> Result<(), HostError> {
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| HostError::JournalUnavailable)
    }
}

impl OwnedJournal for MacosOwnedJournal {
    fn load(&self) -> Result<Option<OwnedRunRecord>, HostError> {
        self.read_record()
    }

    fn persist(&mut self, record: &OwnedRunRecord) -> Result<(), HostError> {
        record.validate().map_err(|_| HostError::InvalidInput)?;
        ensure_directory(&self.root, self.expected_uid, false)?;
        let path = self.record_path();
        let _ = checked_metadata(&path, self.expected_uid)?;
        let bytes = serde_json::to_vec(record).map_err(|_| HostError::InvalidInput)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(HostError::InvalidInput);
        }
        let temporary = self.root.join(format!(
            ".owned-run-write-{}-{}",
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
                .map_err(|_| HostError::JournalUnavailable)?;
            file.write_all(&bytes)
                .map_err(|_| HostError::JournalUnavailable)?;
            file.sync_all().map_err(|_| HostError::JournalUnavailable)?;
            fs::rename(&temporary, &path).map_err(|_| HostError::JournalUnavailable)?;
            self.sync_root()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn clear_exact(&mut self, run_id: &str) -> Result<(), HostError> {
        let Some(record) = self.read_record()? else {
            return Ok(());
        };
        if record.run_id != run_id {
            return Err(HostError::RecoveryRequired);
        }
        fs::remove_file(self.record_path()).map_err(|_| HostError::JournalUnavailable)?;
        self.sync_root()
    }
}

fn ensure_directory(root: &Path, expected_uid: u32, create: bool) -> Result<(), HostError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_directory(&metadata, expected_uid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            fs::create_dir_all(root).map_err(|_| HostError::JournalUnavailable)?;
            fs::set_permissions(root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| HostError::JournalUnavailable)?;
            let metadata = fs::symlink_metadata(root).map_err(|_| HostError::JournalUnavailable)?;
            validate_directory(&metadata, expected_uid)
        }
        Err(_) => Err(HostError::JournalUnavailable),
    }
}

fn validate_directory(metadata: &fs::Metadata, expected_uid: u32) -> Result<(), HostError> {
    if metadata.file_type().is_dir()
        && metadata.uid() == expected_uid
        && metadata.mode() & 0o777 == DIRECTORY_MODE
    {
        Ok(())
    } else {
        Err(HostError::RecoveryRequired)
    }
}

fn checked_metadata(path: &Path, expected_uid: u32) -> Result<Option<fs::Metadata>, HostError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(HostError::JournalUnavailable),
    };
    if metadata.file_type().is_file()
        && metadata.uid() == expected_uid
        && metadata.mode() & 0o777 == FILE_MODE
        && metadata.nlink() == 1
    {
        Ok(Some(metadata))
    } else {
        Err(HostError::RecoveryRequired)
    }
}

fn open_checked_file(path: &Path, expected_uid: u32, create: bool) -> Result<File, HostError> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(FILE_MODE)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .map_err(|_| HostError::JournalUnavailable)?;
    let metadata = file.metadata().map_err(|_| HostError::JournalUnavailable)?;
    if metadata.file_type().is_file()
        && metadata.uid() == expected_uid
        && metadata.mode() & 0o777 == FILE_MODE
        && metadata.nlink() == 1
    {
        Ok(file)
    } else {
        Err(HostError::RecoveryRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle_plan::{
        DnsBaseline, DnsConfigurationMode, NetworkBaseline, OwnedStage, ProcessIdentity,
    };
    use std::{net::Ipv4Addr, os::unix::fs::symlink};

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-macos-owned-journal-{}-{}-{}",
            std::process::id(),
            name,
            NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn record() -> OwnedRunRecord {
        OwnedRunRecord {
            schema_version: 2,
            run_id: "a".repeat(32),
            stage: OwnedStage::Prepared,
            owner_principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            owner_session_id: 42,
            upstream: ProcessIdentity {
                pid: 600,
                start_time_ns: 100,
                executable_file_id: 200,
                executable_sha256: "b".repeat(64),
            },
            engine: None,
            tun: None,
            baseline: NetworkBaseline {
                default_interface_index: 9,
                default_gateway: Ipv4Addr::new(192, 0, 2, 1).into(),
                routes_sha256: "c".repeat(64),
                preexisting_utuns: Vec::new(),
                dns: DnsBaseline {
                    network_service_id: "fixture-service".into(),
                    mode: DnsConfigurationMode::Manual,
                    servers: vec![Ipv4Addr::new(192, 0, 2, 53).into()],
                    search_domains: vec!["example.test".into()],
                },
            },
            route_deltas: Vec::new(),
            planned_dns_sha256: None,
            controller_secret: "d".repeat(64),
        }
    }

    #[test]
    fn private_atomic_round_trip_and_exact_clear() {
        let root = test_root("round-trip");
        let uid = unsafe { libc::geteuid() };
        let mut journal = MacosOwnedJournal::open(root.clone(), uid).unwrap();
        journal.persist(&record()).unwrap();
        assert_eq!(journal.load().unwrap(), Some(record()));
        assert_eq!(
            journal.clear_exact(&"f".repeat(32)),
            Err(HostError::RecoveryRequired)
        );
        journal.clear_exact(&"a".repeat(32)).unwrap();
        assert!(journal.load().unwrap().is_none());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lock_symlink_permissions_and_corrupt_data_fail_closed() {
        let root = test_root("reject");
        let uid = unsafe { libc::geteuid() };
        let journal = MacosOwnedJournal::open(root.clone(), uid).unwrap();
        assert!(MacosOwnedJournal::open(root.clone(), uid).is_err());
        drop(journal);

        let record_path = root.join(RECORD_NAME);
        symlink("/tmp/not-a-tunbridge-record", &record_path).unwrap();
        let journal = MacosOwnedJournal::open(root.clone(), uid).unwrap();
        assert_eq!(journal.load(), Err(HostError::RecoveryRequired));
        drop(journal);
        fs::remove_file(&record_path).unwrap();

        fs::write(&record_path, b"{not-json").unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        let journal = MacosOwnedJournal::open(root.clone(), uid).unwrap();
        assert_eq!(journal.load(), Err(HostError::RecoveryRequired));
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }
}
