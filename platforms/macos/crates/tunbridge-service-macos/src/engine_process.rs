//! Protected Darwin engine asset/config staging and suspended spawn.

use crate::{
    engine_config::DarwinEngineConfig, lifecycle_plan::ProcessIdentity, native::process_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_char, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};

pub const ENGINE_PATH: &str = "/Library/Application Support/TunBridge/Engine/mihomo";
pub const ENGINE_MANIFEST_PATH: &str =
    "/Library/Application Support/TunBridge/Engine/manifest.json";
pub const RUNTIME_ROOT: &str = "/Library/Application Support/TunBridge/Runtime";

const PRODUCT_ROOT: &str = "/Library/Application Support/TunBridge";
const ENGINE_ROOT: &str = "/Library/Application Support/TunBridge/Engine";
const POSIX_SPAWN_START_SUSPENDED: i16 = 0x0080;
const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;
const POSIX_SPAWN_SETSID: i16 = 0x0400;
/// The engine runs as root with this group alone, so the traffic lock can let
/// exactly the engine's own sockets use the physical interface. No other
/// process on the system may hold it; the start fails if a group already has
/// this id.
pub const ENGINE_GID: u32 = 0x5442;

unsafe extern "C" {
    fn posix_spawnattr_set_gid_np(
        attributes: *const libc::posix_spawnattr_t,
        gid: libc::gid_t,
    ) -> libc::c_int;
    fn posix_spawnattr_set_groups_np(
        attributes: *const libc::posix_spawnattr_t,
        count: libc::c_int,
        groups: *mut libc::gid_t,
        group_member_uid: libc::uid_t,
    ) -> libc::c_int;
}

/// No account or group on this Mac may already use the engine group.
fn engine_group_is_free() -> bool {
    unsafe { libc::getgrgid(ENGINE_GID).is_null() }
}
const MAX_MANIFEST_BYTES: u64 = 4096;
const MAX_ENGINE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineProcessError {
    InvalidLayout,
    AssetIntegrity,
    ConfigUnavailable,
    SpawnUnavailable,
    IdentityMismatch,
    ProcessUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EngineManifest {
    schema_version: u16,
    version: String,
    target_triple: String,
    binary_size: u64,
    binary_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedAsset {
    file_id: u64,
    sha256: String,
}

#[derive(Debug, Clone)]
pub struct EngineLauncher {
    engine_path: PathBuf,
    manifest_path: PathBuf,
    runtime_root: PathBuf,
    required_owner: u32,
}

impl EngineLauncher {
    pub fn system() -> Self {
        Self {
            engine_path: ENGINE_PATH.into(),
            manifest_path: ENGINE_MANIFEST_PATH.into(),
            runtime_root: RUNTIME_ROOT.into(),
            required_owner: 0,
        }
    }

    pub fn stage_and_spawn_suspended(
        &self,
        config: &DarwinEngineConfig,
        run_id: &str,
    ) -> Result<SuspendedEngine, EngineProcessError> {
        validate_system_layout(self)?;
        let asset = validate_asset(&self.engine_path, &self.manifest_path, self.required_owner)?;
        let config_path = stage_config(
            &self.runtime_root,
            run_id,
            config.as_bytes(),
            self.required_owner,
        )?;
        let engine = self
            .spawn_with_config(&asset, &config_path)
            .inspect_err(|_| {
                let _ = remove_exact_config(&self.runtime_root, &config_path, self.required_owner);
            })?;
        Ok(SuspendedEngine {
            identity: engine,
            config_path: Some(config_path),
            runtime_root: self.runtime_root.clone(),
            config_owner: self.required_owner,
            armed: true,
        })
    }

    fn spawn_with_config(
        &self,
        asset: &ValidatedAsset,
        config_path: &Path,
    ) -> Result<ProcessIdentity, EngineProcessError> {
        let executable = path_cstring(&self.engine_path)?;
        let config = path_cstring(config_path)?;
        let data = path_cstring(&self.runtime_root)?;
        let arguments = [
            executable.clone(),
            CString::new("-f").expect("fixed argument"),
            config,
            CString::new("-d").expect("fixed argument"),
            data,
        ];
        let identity = spawn_suspended_raw(&executable, &arguments)?;
        if identity.executable_file_id != asset.file_id
            || identity.executable_sha256 != asset.sha256
        {
            if terminate_exact_process(&identity, libc::SIGKILL).is_err() {
                force_abort_owned_child(identity.pid);
            }
            return Err(EngineProcessError::IdentityMismatch);
        }
        Ok(identity)
    }
}

pub fn terminate_system_engine(expected: &ProcessIdentity) -> Result<(), EngineProcessError> {
    let launcher = EngineLauncher::system();
    validate_system_layout(&launcher)?;
    let asset = validate_asset(
        &launcher.engine_path,
        &launcher.manifest_path,
        launcher.required_owner,
    )?;
    if expected.executable_file_id != asset.file_id || expected.executable_sha256 != asset.sha256 {
        return Err(EngineProcessError::IdentityMismatch);
    }
    terminate_exact_process(expected, libc::SIGTERM)
}

pub fn remove_system_config(run_id: &str) -> Result<(), EngineProcessError> {
    let launcher = EngineLauncher::system();
    validate_system_layout(&launcher)?;
    let path = launcher.runtime_root.join(format!("config-{run_id}.yaml"));
    remove_exact_config_if_present(&launcher.runtime_root, &path, launcher.required_owner)
}

pub struct SuspendedEngine {
    identity: ProcessIdentity,
    config_path: Option<PathBuf>,
    runtime_root: PathBuf,
    config_owner: u32,
    armed: bool,
}

impl SuspendedEngine {
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn resume(mut self) -> Result<RunningEngine, EngineProcessError> {
        verify_exact_process(&self.identity)?;
        if unsafe { libc::kill(self.identity.pid as i32, libc::SIGCONT) } != 0 {
            return Err(EngineProcessError::ProcessUnavailable);
        }
        self.armed = false;
        Ok(RunningEngine {
            identity: self.identity.clone(),
            config_path: self.config_path.take(),
            runtime_root: self.runtime_root.clone(),
            config_owner: self.config_owner,
        })
    }

    pub fn terminate(mut self) -> Result<(), EngineProcessError> {
        let result = terminate_exact_process(&self.identity, libc::SIGKILL);
        if result.is_ok() {
            self.remove_config()?;
            self.armed = false;
        }
        result
    }

    fn remove_config(&mut self) -> Result<(), EngineProcessError> {
        if let Some(path) = self.config_path.take() {
            remove_exact_config(&self.runtime_root, &path, self.config_owner)
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for SuspendedEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SuspendedEngine")
            .field("identity", &self.identity)
            .field("config_path", &"[REDACTED]")
            .field("armed", &self.armed)
            .finish()
    }
}

impl Drop for SuspendedEngine {
    fn drop(&mut self) {
        if self.armed {
            abort_exact_process(&self.identity);
            let _ = self.remove_config();
        }
    }
}

pub struct RunningEngine {
    identity: ProcessIdentity,
    config_path: Option<PathBuf>,
    runtime_root: PathBuf,
    config_owner: u32,
}

impl RunningEngine {
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn terminate(mut self) -> Result<(), EngineProcessError> {
        terminate_exact_process(&self.identity, libc::SIGTERM)?;
        if let Some(path) = self.config_path.take() {
            remove_exact_config(&self.runtime_root, &path, self.config_owner)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for RunningEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningEngine")
            .field("identity", &self.identity)
            .field("config_path", &"[REDACTED]")
            .finish()
    }
}

fn validate_system_layout(launcher: &EngineLauncher) -> Result<(), EngineProcessError> {
    if launcher.engine_path != Path::new(ENGINE_PATH)
        || launcher.manifest_path != Path::new(ENGINE_MANIFEST_PATH)
        || launcher.runtime_root != Path::new(RUNTIME_ROOT)
        || launcher.required_owner != 0
    {
        return Err(EngineProcessError::InvalidLayout);
    }
    validate_ancestor(Path::new("/Library"), 0)?;
    validate_ancestor(Path::new("/Library/Application Support"), 0)?;
    validate_exact_directory(Path::new(PRODUCT_ROOT), 0, 0o755)?;
    validate_exact_directory(Path::new(ENGINE_ROOT), 0, 0o755)?;
    validate_exact_directory(Path::new(RUNTIME_ROOT), 0, 0o700)?;
    Ok(())
}

fn validate_asset(
    engine_path: &Path,
    manifest_path: &Path,
    owner: u32,
) -> Result<ValidatedAsset, EngineProcessError> {
    let manifest_bytes = read_trusted_file(
        manifest_path,
        owner,
        0o644,
        MAX_MANIFEST_BYTES,
        EngineProcessError::AssetIntegrity,
    )?;
    let manifest: EngineManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| EngineProcessError::AssetIntegrity)?;
    if manifest.schema_version != 1
        || !valid_version(&manifest.version)
        || !valid_target(&manifest.target_triple)
        || manifest.binary_size == 0
        || manifest.binary_size > MAX_ENGINE_BYTES
        || !valid_sha256(&manifest.binary_sha256)
    {
        return Err(EngineProcessError::AssetIntegrity);
    }

    let mut file = open_trusted_file(
        engine_path,
        owner,
        0o755,
        EngineProcessError::AssetIntegrity,
    )?;
    let before = file
        .metadata()
        .map_err(|_| EngineProcessError::AssetIntegrity)?;
    if before.len() != manifest.binary_size || before.len() > MAX_ENGINE_BYTES {
        return Err(EngineProcessError::AssetIntegrity);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| EngineProcessError::AssetIntegrity)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(EngineProcessError::AssetIntegrity)?;
        if total > MAX_ENGINE_BYTES {
            return Err(EngineProcessError::AssetIntegrity);
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|_| EngineProcessError::AssetIntegrity)?;
    let sha256 = format!("{:x}", hasher.finalize());
    if total != manifest.binary_size
        || sha256 != manifest.binary_sha256
        || !same_file_metadata(&before, &after)
    {
        return Err(EngineProcessError::AssetIntegrity);
    }
    Ok(ValidatedAsset {
        file_id: before.ino(),
        sha256,
    })
}

fn stage_config(
    runtime_root: &Path,
    run_id: &str,
    contents: &[u8],
    owner: u32,
) -> Result<PathBuf, EngineProcessError> {
    validate_private_directory(runtime_root, owner)?;
    if !valid_run_id(run_id) || contents.is_empty() || contents.len() > MAX_CONFIG_BYTES {
        return Err(EngineProcessError::ConfigUnavailable);
    }
    let path = runtime_root.join(format!("config-{run_id}.yaml"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| EngineProcessError::ConfigUnavailable)?;
    let metadata = match file
        .write_all(contents)
        .and_then(|_| file.sync_all())
        .and_then(|_| file.metadata())
    {
        Ok(metadata) => metadata,
        Err(_) => {
            drop(file);
            let _ = fs::remove_file(&path);
            let _ = sync_directory(runtime_root);
            return Err(EngineProcessError::ConfigUnavailable);
        }
    };
    if metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != contents.len() as u64
    {
        drop(file);
        let _ = fs::remove_file(&path);
        let _ = sync_directory(runtime_root);
        return Err(EngineProcessError::ConfigUnavailable);
    }
    if let Err(error) = sync_directory(runtime_root) {
        drop(file);
        let _ = fs::remove_file(&path);
        let _ = sync_directory(runtime_root);
        return Err(error);
    }
    Ok(path)
}

fn remove_exact_config(
    runtime_root: &Path,
    path: &Path,
    owner: u32,
) -> Result<(), EngineProcessError> {
    validate_private_directory(runtime_root, owner)?;
    validate_config_path(runtime_root, path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| EngineProcessError::ConfigUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(EngineProcessError::ConfigUnavailable);
    }
    fs::remove_file(path).map_err(|_| EngineProcessError::ConfigUnavailable)?;
    sync_directory(runtime_root)
}

fn remove_exact_config_if_present(
    runtime_root: &Path,
    path: &Path,
    owner: u32,
) -> Result<(), EngineProcessError> {
    validate_private_directory(runtime_root, owner)?;
    validate_config_path(runtime_root, path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => remove_exact_config(runtime_root, path, owner),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(EngineProcessError::ConfigUnavailable),
    }
}

fn validate_config_path(runtime_root: &Path, path: &Path) -> Result<(), EngineProcessError> {
    if path.parent() != Some(runtime_root)
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.strip_prefix("config-")
                    .and_then(|value| value.strip_suffix(".yaml"))
                    .is_some_and(valid_run_id)
            })
    {
        Err(EngineProcessError::ConfigUnavailable)
    } else {
        Ok(())
    }
}

fn validate_private_directory(path: &Path, owner: u32) -> Result<(), EngineProcessError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| EngineProcessError::ConfigUnavailable)?;
    if !path.is_absolute()
        || !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(EngineProcessError::ConfigUnavailable);
    }
    Ok(())
}

fn validate_ancestor(path: &Path, owner: u32) -> Result<(), EngineProcessError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| EngineProcessError::InvalidLayout)?;
    if !metadata.file_type().is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(EngineProcessError::InvalidLayout);
    }
    Ok(())
}

fn validate_exact_directory(path: &Path, owner: u32, mode: u32) -> Result<(), EngineProcessError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| EngineProcessError::InvalidLayout)?;
    if !metadata.file_type().is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != mode
    {
        return Err(EngineProcessError::InvalidLayout);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), EngineProcessError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| EngineProcessError::ConfigUnavailable)
}

fn read_trusted_file(
    path: &Path,
    owner: u32,
    mode: u32,
    max_bytes: u64,
    error: EngineProcessError,
) -> Result<Vec<u8>, EngineProcessError> {
    let mut file = open_trusted_file(path, owner, mode, error)?;
    let metadata = file.metadata().map_err(|_| error)?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(error);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    let after = file.metadata().map_err(|_| error)?;
    if bytes.len() as u64 != metadata.len() || !same_file_metadata(&metadata, &after) {
        return Err(error);
    }
    Ok(bytes)
}

fn open_trusted_file(
    path: &Path,
    owner: u32,
    mode: u32,
    error: EngineProcessError,
) -> Result<File, EngineProcessError> {
    if !path.is_absolute() {
        return Err(error);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| error)?;
    let metadata = file.metadata().map_err(|_| error)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
        || metadata.ino() == 0
    {
        return Err(error);
    }
    Ok(file)
}

fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

fn spawn_suspended_raw(
    executable: &CString,
    arguments: &[CString],
) -> Result<ProcessIdentity, EngineProcessError> {
    if arguments.is_empty() || arguments.len() > 16 {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    let mut attributes: libc::posix_spawnattr_t = ptr::null_mut();
    if unsafe { libc::posix_spawnattr_init(&mut attributes) } != 0 {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    struct AttributeGuard(libc::posix_spawnattr_t);
    impl Drop for AttributeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawnattr_destroy(&mut self.0);
            }
        }
    }
    let mut attributes = AttributeGuard(attributes);

    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut defaults = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigemptyset(&mut mask) } != 0
        || unsafe { libc::sigfillset(&mut defaults) } != 0
        || unsafe { libc::sigdelset(&mut defaults, libc::SIGKILL) } != 0
        || unsafe { libc::sigdelset(&mut defaults, libc::SIGSTOP) } != 0
    {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    // A new session keeps launchd from killing the engine with the helper's
    // process group: a helper crash must not take the tunnel down with it.
    let flags = POSIX_SPAWN_START_SUSPENDED
        | POSIX_SPAWN_SETSID
        | POSIX_SPAWN_CLOEXEC_DEFAULT
        | libc::POSIX_SPAWN_SETSIGMASK as i16
        | libc::POSIX_SPAWN_SETSIGDEF as i16;
    if unsafe { libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) } != 0
        || unsafe { libc::posix_spawnattr_setsigdefault(&mut attributes.0, &defaults) } != 0
        || unsafe { libc::posix_spawnattr_setflags(&mut attributes.0, flags) } != 0
    {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    // The privileged helper always runs as root and gives the engine its own
    // group; an unprivileged caller (the fixture tests) cannot change groups.
    let engine_group = (unsafe { libc::geteuid() } == 0).then_some(ENGINE_GID);
    if let Some(gid) = engine_group {
        let mut groups = [gid as libc::gid_t];
        if !engine_group_is_free()
            || unsafe { posix_spawnattr_set_gid_np(&attributes.0, gid as libc::gid_t) } != 0
            || unsafe {
                // KAUTH_UID_NONE: no group-membership resolution for this list.
                posix_spawnattr_set_groups_np(&attributes.0, 1, groups.as_mut_ptr(), u32::MAX - 100)
            } != 0
        {
            return Err(EngineProcessError::SpawnUnavailable);
        }
    }

    let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
    if unsafe { libc::posix_spawn_file_actions_init(&mut actions) } != 0 {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    struct ActionGuard(libc::posix_spawn_file_actions_t);
    impl Drop for ActionGuard {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawn_file_actions_destroy(&mut self.0);
            }
        }
    }
    let mut actions = ActionGuard(actions);
    let dev_null = CString::new("/dev/null").expect("fixed path");
    for (descriptor, open_flags) in [
        (libc::STDIN_FILENO, libc::O_RDONLY),
        (libc::STDOUT_FILENO, libc::O_WRONLY),
        (libc::STDERR_FILENO, libc::O_WRONLY),
    ] {
        if unsafe {
            libc::posix_spawn_file_actions_addopen(
                &mut actions.0,
                descriptor,
                dev_null.as_ptr(),
                open_flags,
                0,
            )
        } != 0
        {
            return Err(EngineProcessError::SpawnUnavailable);
        }
    }

    let mut argv: Vec<*mut c_char> = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect();
    argv.push(ptr::null_mut());
    // Mihomo otherwise suppresses the configured TUN IPv6 address whenever
    // the physical interfaces have no usable IPv6 address. TunBridge owns the
    // IPv6 split routes and must keep the TUN dual-stack even on IPv4-only
    // uplinks so those routes have a reachable interface endpoint.
    let force_tun_ipv6 = CString::new("SKIP_SYSTEM_IPV6_CHECK=1").expect("fixed environment");
    let mut environment = [
        force_tun_ipv6.as_ptr().cast_mut(),
        ptr::null_mut::<c_char>(),
    ];
    let mut pid = 0;
    let status = unsafe {
        libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_mut_ptr(),
            environment.as_mut_ptr(),
        )
    };
    if status != 0 || pid <= 1 {
        return Err(EngineProcessError::SpawnUnavailable);
    }
    // The lock trusts this group; an engine that did not get it must not run.
    if engine_group.is_some_and(|gid| {
        !crate::native::process_credentials(pid as u32).is_ok_and(|credentials| {
            credentials.effective_uid == 0
                && credentials.effective_gid == gid
                && credentials.real_gid == gid
        })
    }) {
        force_abort_owned_child(pid as u32);
        return Err(EngineProcessError::SpawnUnavailable);
    }
    match process_identity(pid as u32) {
        Ok(identity) => Ok(identity),
        Err(_) => {
            force_abort_owned_child(pid as u32);
            Err(EngineProcessError::IdentityMismatch)
        }
    }
}

fn verify_exact_process(expected: &ProcessIdentity) -> Result<(), EngineProcessError> {
    match process_identity(expected.pid) {
        Ok(observed) if observed == *expected => Ok(()),
        Ok(_) => Err(EngineProcessError::IdentityMismatch),
        Err(_) => Err(EngineProcessError::ProcessUnavailable),
    }
}

fn terminate_exact_process(
    expected: &ProcessIdentity,
    signal: i32,
) -> Result<(), EngineProcessError> {
    verify_exact_process(expected)?;
    if unsafe { libc::kill(expected.pid as i32, signal) } != 0 {
        return Err(EngineProcessError::ProcessUnavailable);
    }
    if signal != libc::SIGKILL {
        let continued = unsafe { libc::kill(expected.pid as i32, libc::SIGCONT) };
        if continued != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(EngineProcessError::ProcessUnavailable);
        }
    }
    let mut deadline = Instant::now() + TERMINATE_TIMEOUT;
    let mut sent_kill = signal == libc::SIGKILL;
    loop {
        let mut status = 0;
        let waited = unsafe {
            libc::waitpid(
                expected.pid as i32,
                &mut status,
                libc::WNOHANG | libc::WUNTRACED,
            )
        };
        if waited == expected.pid as i32 {
            if libc::WIFSTOPPED(status) {
                if !sent_kill && unsafe { libc::kill(expected.pid as i32, libc::SIGCONT) } != 0 {
                    return Err(EngineProcessError::ProcessUnavailable);
                }
            } else {
                return Ok(());
            }
        } else if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
        {
            return Err(EngineProcessError::ProcessUnavailable);
        }
        match process_identity(expected.pid) {
            Ok(observed) if observed == *expected => {}
            Ok(_) => return Err(EngineProcessError::IdentityMismatch),
            Err(_) => {
                let alive = unsafe { libc::kill(expected.pid as i32, 0) };
                if alive != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    return Ok(());
                }
                if alive != 0 {
                    return Err(EngineProcessError::ProcessUnavailable);
                }
            }
        }
        if Instant::now() >= deadline {
            if sent_kill {
                return Err(EngineProcessError::ProcessUnavailable);
            }
            verify_exact_process(expected)?;
            if unsafe { libc::kill(expected.pid as i32, libc::SIGKILL) } != 0 {
                return Err(EngineProcessError::ProcessUnavailable);
            }
            sent_kill = true;
            deadline = Instant::now() + TERMINATE_TIMEOUT;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn abort_exact_process(expected: &ProcessIdentity) {
    let _ = terminate_exact_process(expected, libc::SIGKILL);
}

fn force_abort_owned_child(pid: u32) {
    // This is only used synchronously immediately after posix_spawn, before
    // the direct child can be reaped or its PID reused.
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
        libc::waitpid(pid as i32, ptr::null_mut(), 0);
    }
}

fn path_cstring(path: &Path) -> Result<CString, EngineProcessError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| EngineProcessError::InvalidLayout)
}

fn valid_version(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= 64
        && value.starts_with('v')
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && value[1..].split('.').all(|component| !component.is_empty())
}

fn valid_target(value: &str) -> bool {
    let native = if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-apple-darwin"
    };
    value == native || value == "universal2-apple-darwin"
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_run_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = PathBuf::from(format!(
                "/private/tmp/tunbridge-m3x-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn copy_fixture(root: &Path) -> (PathBuf, PathBuf, EngineManifest) {
        let engine = root.join("mihomo");
        fs::copy("/usr/bin/touch", &engine).unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
        let bytes = fs::read(&engine).unwrap();
        let manifest = EngineManifest {
            schema_version: 1,
            version: "v1.19.28".into(),
            target_triple: if cfg!(target_arch = "aarch64") {
                "aarch64-apple-darwin".into()
            } else {
                "x86_64-apple-darwin".into()
            },
            binary_size: bytes.len() as u64,
            binary_sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        let manifest_path = root.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
        (engine, manifest_path, manifest)
    }

    #[test]
    fn trusted_asset_requires_exact_manifest_hash_size_owner_and_modes() {
        let root = TempRoot::new();
        let (engine, manifest_path, manifest) = copy_fixture(&root.0);
        let owner = unsafe { libc::geteuid() };
        let asset = validate_asset(&engine, &manifest_path, owner).unwrap();
        assert_eq!(asset.sha256, manifest.binary_sha256);

        let hardlink = root.0.join("engine-hardlink");
        fs::hard_link(&engine, &hardlink).unwrap();
        assert_eq!(
            validate_asset(&engine, &manifest_path, owner),
            Err(EngineProcessError::AssetIntegrity)
        );
        fs::remove_file(hardlink).unwrap();

        let symlink = root.0.join("engine-symlink");
        std::os::unix::fs::symlink(&engine, &symlink).unwrap();
        assert_eq!(
            validate_asset(&symlink, &manifest_path, owner),
            Err(EngineProcessError::AssetIntegrity)
        );

        fs::set_permissions(&engine, fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            validate_asset(&engine, &manifest_path, owner),
            Err(EngineProcessError::AssetIntegrity)
        );
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&manifest_path, b"{}").unwrap();
        assert_eq!(
            validate_asset(&engine, &manifest_path, owner),
            Err(EngineProcessError::AssetIntegrity)
        );
    }

    #[test]
    fn private_config_is_create_new_exact_and_removed_without_path_escape() {
        let root = TempRoot::new();
        let owner = unsafe { libc::geteuid() };
        let run_id = "a".repeat(32);
        let path = stage_config(&root.0, &run_id, b"secret: fixture\n", owner).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(
            stage_config(&root.0, &run_id, b"replacement\n", owner),
            Err(EngineProcessError::ConfigUnavailable)
        );
        assert_eq!(
            remove_exact_config(&root.0, &root.0.join("../escape"), owner),
            Err(EngineProcessError::ConfigUnavailable)
        );
        remove_exact_config(&root.0, &path, owner).unwrap();
        assert!(!path.exists());
        remove_exact_config_if_present(&root.0, &path, owner).unwrap();
    }

    #[test]
    fn exact_termination_rejects_identity_substitution_before_signaling() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let identity = process_identity(child.id()).unwrap();
        let mut substituted = identity.clone();
        substituted.executable_sha256 = "0".repeat(64);
        assert_eq!(
            terminate_exact_process(&substituted, libc::SIGTERM),
            Err(EngineProcessError::IdentityMismatch)
        );
        assert!(child.try_wait().unwrap().is_none());
        terminate_exact_process(&identity, libc::SIGTERM).unwrap();
    }

    #[test]
    fn exact_termination_supports_reparented_orphan_processes() {
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $!"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let pid = std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            if crate::native::process_executable_leaf(pid).as_deref() == Ok("sleep") {
                if let (Ok(first), Ok(second)) = (process_identity(pid), process_identity(pid)) {
                    if first == second {
                        break second;
                    }
                }
            }
            assert!(Instant::now() < deadline);
            thread::sleep(POLL_INTERVAL);
        };
        terminate_exact_process(&identity, libc::SIGTERM).unwrap();
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            -1,
            "orphan process must be absent"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn posix_spawn_stays_suspended_until_exact_resume_and_can_be_reaped() {
        let root = TempRoot::new();
        let marker = root.0.join("marker");
        let executable = CString::new("/usr/bin/touch").unwrap();
        let arguments = [executable.clone(), path_cstring(&marker).unwrap()];
        let identity = spawn_suspended_raw(&executable, &arguments).unwrap();
        let suspended = SuspendedEngine {
            identity,
            config_path: None,
            runtime_root: root.0.clone(),
            config_owner: unsafe { libc::geteuid() },
            armed: true,
        };
        thread::sleep(Duration::from_millis(50));
        assert!(!marker.exists());
        let running = suspended.resume().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            let waited =
                unsafe { libc::waitpid(running.identity.pid as i32, &mut status, libc::WNOHANG) };
            if waited == running.identity.pid as i32 {
                assert!(std::process::ExitStatus::from_raw(status).success());
                break;
            }
            assert!(waited >= 0 && Instant::now() < deadline);
            thread::sleep(POLL_INTERVAL);
        }
        assert!(marker.exists());
    }

    #[test]
    fn suspended_drop_aborts_before_fixture_can_execute() {
        let root = TempRoot::new();
        let marker = root.0.join("must-not-exist");
        let executable = CString::new("/usr/bin/touch").unwrap();
        let arguments = [executable.clone(), path_cstring(&marker).unwrap()];
        let identity = spawn_suspended_raw(&executable, &arguments).unwrap();
        let suspended = SuspendedEngine {
            identity,
            config_path: None,
            runtime_root: root.0.clone(),
            config_owner: unsafe { libc::geteuid() },
            armed: true,
        };
        drop(suspended);
        assert!(!marker.exists());
    }

    #[test]
    fn post_spawn_asset_identity_mismatch_is_aborted_while_suspended() {
        let root = TempRoot::new();
        let (engine_path, manifest_path, _) = copy_fixture(&root.0);
        let owner = unsafe { libc::geteuid() };
        let mut asset = validate_asset(&engine_path, &manifest_path, owner).unwrap();
        asset.sha256 = "0".repeat(64);
        let launcher = EngineLauncher {
            engine_path,
            manifest_path,
            runtime_root: root.0.clone(),
            required_owner: owner,
        };
        assert_eq!(
            launcher.spawn_with_config(&asset, &root.0.join("unused.yaml")),
            Err(EngineProcessError::IdentityMismatch)
        );
    }
}
