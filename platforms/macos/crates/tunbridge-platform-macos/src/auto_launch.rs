use libc::{O_CLOEXEC, O_NOFOLLOW};
use plist::{Dictionary, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, AutoLaunch};

const LABEL: &str = "com.tunbridge.desktop";
const MAX_PLIST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosAutoLaunch;

impl AutoLaunch for MacosAutoLaunch {
    fn enabled(&self) -> Result<bool, AdapterError> {
        let home = production_home()?;
        let executable = std::env::current_exe().map_err(|_| unavailable())?;
        enabled_at(&home, &executable)
    }

    fn set_enabled(&self, enabled: bool) -> Result<bool, AdapterError> {
        let home = production_home()?;
        let executable = std::env::current_exe().map_err(|_| unavailable())?;
        set_enabled_at(&home, &executable, enabled)
    }
}

fn production_home() -> Result<PathBuf, AdapterError> {
    let home = std::env::var_os("HOME").ok_or_else(unavailable)?;
    let home = PathBuf::from(home);
    if home.is_absolute() {
        Ok(home)
    } else {
        Err(identity_rejected())
    }
}

fn launch_agents(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
}

fn launch_agent_path(home: &Path) -> PathBuf {
    launch_agents(home).join(format!("{LABEL}.plist"))
}

fn enabled_at(home: &Path, executable: &Path) -> Result<bool, AdapterError> {
    if !home.is_absolute() || !executable.is_absolute() {
        return Err(identity_rejected());
    }
    let path = launch_agent_path(home);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(unavailable()),
    };
    validate_user_file(&metadata)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(&path)
        .map_err(|_| identity_rejected())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((MAX_PLIST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > MAX_PLIST_BYTES {
        return Err(invalid_data());
    }
    let value = Value::from_reader(Cursor::new(bytes)).map_err(|_| invalid_data())?;
    Ok(matches_expected(&value, executable))
}

fn set_enabled_at(home: &Path, executable: &Path, enabled: bool) -> Result<bool, AdapterError> {
    if !home.is_absolute() || !executable.is_absolute() {
        return Err(identity_rejected());
    }
    let directory = launch_agents(home);
    let path = launch_agent_path(home);
    if !enabled {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(unavailable()),
        };
        validate_user_file(&metadata)?;
        fs::remove_file(&path).map_err(|_| unavailable())?;
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())?;
        return Ok(false);
    }

    ensure_user_directory(&directory)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        validate_user_file(&metadata)?;
    }
    let bytes = launch_agent_bytes(executable)?;
    let temporary = directory.join(format!(".{LABEL}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW | O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| unavailable())?;
        file.write_all(&bytes).map_err(|_| unavailable())?;
        file.sync_all().map_err(|_| unavailable())?;
        fs::rename(&temporary, &path).map_err(|_| unavailable())?;
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    enabled_at(home, executable)
}

fn launch_agent_bytes(executable: &Path) -> Result<Vec<u8>, AdapterError> {
    let executable = executable.to_str().ok_or_else(invalid_data)?;
    if executable.is_empty() || executable.chars().any(char::is_control) {
        return Err(invalid_data());
    }
    let mut dictionary = Dictionary::new();
    dictionary.insert("Label".into(), Value::String(LABEL.into()));
    dictionary.insert(
        "ProgramArguments".into(),
        Value::Array(vec![
            Value::String(executable.into()),
            Value::String("--background".into()),
        ]),
    );
    dictionary.insert("RunAtLoad".into(), Value::Boolean(true));
    let mut bytes = Vec::new();
    Value::Dictionary(dictionary)
        .to_writer_xml(&mut bytes)
        .map_err(|_| invalid_data())?;
    if bytes.len() > MAX_PLIST_BYTES {
        return Err(invalid_data());
    }
    Ok(bytes)
}

fn matches_expected(value: &Value, executable: &Path) -> bool {
    let Some(dictionary) = value.as_dictionary() else {
        return false;
    };
    let expected = executable.to_string_lossy();
    dictionary.get("Label").and_then(Value::as_string) == Some(LABEL)
        && dictionary.get("RunAtLoad").and_then(Value::as_boolean) == Some(true)
        && dictionary
            .get("ProgramArguments")
            .and_then(Value::as_array)
            .is_some_and(|arguments| {
                arguments.len() == 2
                    && arguments[0].as_string() == Some(expected.as_ref())
                    && arguments[1].as_string() == Some("--background")
            })
}

fn ensure_user_directory(path: &Path) -> Result<(), AdapterError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| permission_denied())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| permission_denied())?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if metadata.file_type().is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o022 == 0
    {
        Ok(())
    } else {
        Err(identity_rejected())
    }
}

fn validate_user_file(metadata: &fs::Metadata) -> Result<(), AdapterError> {
    if metadata.file_type().is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() <= MAX_PLIST_BYTES as u64
    {
        Ok(())
    } else {
        Err(identity_rejected())
    }
}

const fn invalid_data() -> AdapterError {
    error(
        AdapterErrorCode::InvalidData,
        "The macOS login item configuration is invalid.",
        false,
    )
}
const fn identity_rejected() -> AdapterError {
    error(
        AdapterErrorCode::IdentityRejected,
        "The macOS login item identity could not be verified.",
        false,
    )
}
const fn permission_denied() -> AdapterError {
    error(
        AdapterErrorCode::PermissionDenied,
        "The macOS login item could not be created securely.",
        false,
    )
}
const fn unavailable() -> AdapterError {
    error(
        AdapterErrorCode::Unavailable,
        "The macOS login item is unavailable.",
        true,
    )
}
const fn error(
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunbridge-macos-auto-launch-{}-{name}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn launch_agent_round_trip_is_exact_and_idempotent() {
        let home = root("round-trip");
        let executable = Path::new("/Applications/TunBridge.app/Contents/MacOS/tunbridge-desktop");
        assert!(!set_enabled_at(&home, executable, false).unwrap());
        assert!(set_enabled_at(&home, executable, true).unwrap());
        assert!(enabled_at(&home, executable).unwrap());
        assert!(!set_enabled_at(&home, executable, false).unwrap());
        assert!(!enabled_at(&home, executable).unwrap());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn rejects_foreign_or_insecure_configuration() {
        let home = root("reject");
        let executable = Path::new("/Applications/TunBridge.app/Contents/MacOS/tunbridge-desktop");
        assert!(set_enabled_at(&home, executable, true).unwrap());
        let path = launch_agent_path(&home);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(enabled_at(&home, executable), Err(identity_rejected()));
        fs::remove_dir_all(home).unwrap();
    }
}
