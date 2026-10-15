use std::{
    ffi::c_void,
    fs::{self, OpenOptions},
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    ptr, thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use tunbridge_service::{
    protocol::Capability,
    windows::{
        cleanup_product_data_for_uninstall, ensure_service_started, reject_reparse_point,
        service_registration, validate_asset_acl, ServiceClient, ServiceRegistration,
    },
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_LOCK_VIOLATION, ERROR_NO_MORE_FILES,
        ERROR_SHARING_VIOLATION, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        CreateDirectoryW, MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH,
    },
    System::{
        Com::CoTaskMemFree,
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenEventW, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, SetEvent, TerminateProcess, WaitForSingleObject,
            EVENT_MODIFY_STATE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            PROCESS_TERMINATE,
        },
    },
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

use crate::{
    read_package, read_package_for_upgrade, PackageError, ProductPackage, PACKAGE_MANIFEST,
    PAYLOAD_FILENAMES,
};

const PRODUCT_DIRECTORY: &str = "TunBridge";
const STAGING_DIRECTORY: &str = "TunBridge.stage";
const ROLLBACK_DIRECTORY: &str = "TunBridge.rollback";
const CORE_STAGING_DIRECTORY: &str = "TunBridge.core.stage";
const CORE_ROLLBACK_DIRECTORY: &str = "TunBridge.core.rollback";
const CORE_UPDATE_FILES: [&str; 3] = ["mihomo.exe", "engines.lock.json", PACKAGE_MANIFEST];
const SERVICE_EXE: &str = "tunbridge-service.exe";
const DESKTOP_EXE: &str = "tunbridge-desktop.exe";
const UPDATE_EXIT_EVENT: &str = "Local\\com.tunbridge.desktop.prepare-update";
const PROTECTED_DIRECTORY_SDDL: &str =
    "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
const SERVICE_READY_TIMEOUT: Duration = Duration::from_secs(20);
const FILE_UNLOCK_TIMEOUT: Duration = Duration::from_secs(10);
const DESKTOP_EXIT_TIMEOUT: Duration = Duration::from_secs(20);

fn required_service_capabilities() -> [Capability; 9] {
    [
        Capability::Status,
        Capability::Start,
        Capability::Stop,
        Capability::Recover,
        Capability::Lease,
        Capability::ObserveLocalTraffic,
        Capability::CloseOwnedConnections,
        Capability::RemoteUpstream,
        Capability::ObserveMihomoLogs,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupVerb {
    Install,
    UpdateCore,
    Uninstall,
}

impl SetupVerb {
    pub fn parse(arguments: &[String]) -> Result<Self, SetupError> {
        match arguments {
            [verb] if verb == "install" => Ok(Self::Install),
            [verb] if verb == "update-core" => Ok(Self::UpdateCore),
            [verb] if verb == "uninstall" => Ok(Self::Uninstall),
            _ => Err(SetupError::InvalidArguments),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupReport {
    pub schema_version: u16,
    pub ok: bool,
    pub operation: &'static str,
    pub upgraded: bool,
    pub rollback_performed: bool,
    pub error: Option<&'static str>,
}

impl SetupReport {
    pub fn success(verb: SetupVerb, upgraded: bool) -> Self {
        Self {
            schema_version: 1,
            ok: true,
            operation: verb.label(),
            upgraded,
            rollback_performed: false,
            error: None,
        }
    }

    pub fn failure(verb: SetupVerb, error: &SetupError) -> Self {
        Self {
            schema_version: 1,
            ok: false,
            operation: verb.label(),
            upgraded: false,
            rollback_performed: matches!(error, SetupError::UpgradeRolledBack),
            error: Some(error.code()),
        }
    }
}

impl SetupVerb {
    fn label(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::UpdateCore => "update_core",
            Self::Uninstall => "uninstall",
        }
    }
}

pub fn execute(verb: SetupVerb) -> Result<bool, SetupError> {
    require_elevated_interactive_session()?;
    let program_files = program_files_directory()?;
    reject_reparse_point(&program_files, "Program Files").map_err(|_| SetupError::UnsafePath)?;
    match verb {
        SetupVerb::Install => install(&program_files),
        SetupVerb::UpdateCore => update_core(&program_files),
        SetupVerb::Uninstall => {
            uninstall(&program_files)?;
            Ok(false)
        }
    }
}

fn update_core(program_files: &Path) -> Result<bool, SetupError> {
    let source_exe = std::env::current_exe().map_err(SetupError::Io)?;
    let source = source_exe.parent().ok_or(SetupError::UnsafePath)?;
    reject_reparse_point(source, "package directory").map_err(|_| SetupError::UnsafePath)?;
    let source = source.canonicalize().map_err(SetupError::Io)?;
    let package = read_package(&source)?;
    package.validate_directory(&source)?;

    let active = program_files.join(PRODUCT_DIRECTORY);
    let staging = program_files.join(STAGING_DIRECTORY);
    let rollback = program_files.join(ROLLBACK_DIRECTORY);
    reject_transaction_residue(&staging, &rollback)?;
    let core_staging = program_files.join(CORE_STAGING_DIRECTORY);
    let core_rollback = program_files.join(CORE_ROLLBACK_DIRECTORY);
    reject_transaction_residue(&core_staging, &core_rollback)?;

    let installed = validate_generation(&active)?;
    validate_core_update_package(&installed, &package)?;
    if service_registration().map_err(|_| SetupError::ServiceRegistrationUnsafe)?
        != ServiceRegistration::Exact
    {
        return Err(SetupError::ServiceRegistrationUnsafe);
    }

    // Stop only the owned engine/network state. The Desktop and Windows
    // service stay alive, so the invoking UI receives the final result.
    recover_service()?;
    stage_core_files(&source, &active, &core_staging, &core_rollback)?;
    if replace_core_files(&core_staging, &active).is_err()
        || validate_generation(&active).is_err()
        || probe_service().is_err()
    {
        restore_core_files(&core_rollback, &active)
            .map_err(|_| SetupError::InstallationRollbackFailed)?;
        validate_generation(&active).map_err(|_| SetupError::InstallationRollbackFailed)?;
        probe_service().map_err(|_| SetupError::InstallationRollbackFailed)?;
        remove_core_directory(&core_staging)?;
        remove_core_directory(&core_rollback)?;
        return Err(SetupError::UpgradeRolledBack);
    }
    remove_core_directory(&core_staging)?;
    remove_core_directory(&core_rollback)?;
    Ok(true)
}

fn validate_core_update_package(
    installed: &ProductPackage,
    source: &ProductPackage,
) -> Result<(), SetupError> {
    if installed.product_version != source.product_version
        || installed.schema_version != source.schema_version
        || installed.service_feature != source.service_feature
        || installed.service_protocol_version != source.service_protocol_version
        || installed.service_capabilities != source.service_capabilities
    {
        return Err(SetupError::CoreUpdatePackageMismatch);
    }
    for filename in PAYLOAD_FILENAMES {
        if matches!(filename, "mihomo.exe" | "engines.lock.json") {
            continue;
        }
        let old = installed
            .files
            .iter()
            .find(|file| file.filename == filename);
        let new = source.files.iter().find(|file| file.filename == filename);
        if old != new {
            return Err(SetupError::CoreUpdatePackageMismatch);
        }
    }
    Ok(())
}

fn stage_core_files(
    source: &Path,
    active: &Path,
    staging: &Path,
    rollback: &Path,
) -> Result<(), SetupError> {
    create_protected_directory(staging)?;
    if let Err(error) = create_protected_directory(rollback) {
        let _ = remove_core_directory(staging);
        return Err(error);
    }
    let result = (|| {
        for filename in CORE_UPDATE_FILES {
            copy_new_file(&source.join(filename), &staging.join(filename))?;
            copy_new_file(&active.join(filename), &rollback.join(filename))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_core_directory(staging);
        let _ = remove_core_directory(rollback);
    }
    result
}

fn copy_new_file(source: &Path, target: &Path) -> Result<(), SetupError> {
    reject_reparse_point(source, "core update asset").map_err(|_| SetupError::UnsafePath)?;
    let mut source_file = OpenOptions::new().read(true).open(source)?;
    let mut target_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    io::copy(&mut source_file, &mut target_file)?;
    target_file.sync_all()?;
    Ok(())
}

fn replace_core_files(source: &Path, active: &Path) -> Result<(), SetupError> {
    for filename in CORE_UPDATE_FILES {
        replace_file(&source.join(filename), &active.join(filename))?;
    }
    Ok(())
}

fn restore_core_files(rollback: &Path, active: &Path) -> Result<(), SetupError> {
    for filename in CORE_UPDATE_FILES {
        replace_file(&rollback.join(filename), &active.join(filename))?;
    }
    Ok(())
}

fn replace_file(source: &Path, target: &Path) -> Result<(), SetupError> {
    let source = wide_path(source);
    let target = wide_path(target);
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(SetupError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn remove_core_directory(root: &Path) -> Result<(), SetupError> {
    if !root.exists() {
        return Ok(());
    }
    reject_reparse_point(root, "core transaction directory").map_err(|_| SetupError::UnsafePath)?;
    validate_asset_acl(root, "core transaction directory").map_err(|_| SetupError::UnsafeAcl)?;
    for filename in CORE_UPDATE_FILES {
        let path = root.join(filename);
        if path.exists() {
            reject_reparse_point(&path, "core transaction asset")
                .map_err(|_| SetupError::UnsafePath)?;
            fs::remove_file(path)?;
        }
    }
    fs::remove_dir(root)?;
    Ok(())
}

fn install(program_files: &Path) -> Result<bool, SetupError> {
    let source_exe = std::env::current_exe().map_err(SetupError::Io)?;
    let source = source_exe.parent().ok_or(SetupError::UnsafePath)?;
    reject_reparse_point(source, "package directory").map_err(|_| SetupError::UnsafePath)?;
    let source = source.canonicalize().map_err(SetupError::Io)?;
    let package = read_package(&source)?;
    package.validate_directory(&source)?;

    let active = program_files.join(PRODUCT_DIRECTORY);
    let staging = program_files.join(STAGING_DIRECTORY);
    let rollback = program_files.join(ROLLBACK_DIRECTORY);
    reconcile_interrupted_install(&active, &staging, &rollback)?;

    if !active.exists() {
        if service_registration().map_err(|_| SetupError::ServiceRegistrationUnsafe)?
            != ServiceRegistration::Absent
        {
            return Err(SetupError::ServiceRegistrationUnsafe);
        }
        stage_package(&source, &package, &staging)?;
        fs::rename(&staging, &active).map_err(SetupError::Io)?;
        if let Err(error) = install_and_probe_service(&active) {
            rollback_new_generation(&active)?;
            return Err(error);
        }
        return Ok(false);
    }

    let installed_package = validate_generation(&active)?;
    let registration = service_registration().map_err(|_| SetupError::ServiceRegistrationUnsafe)?;
    let source_is_active = source == active.canonicalize().map_err(SetupError::Io)?;
    let replacement_required = generation_requires_replacement(&installed_package, &package);
    if repair_requires_desktop_exit(source_is_active, registration, replacement_required) {
        stop_running_desktop(
            &active.join(DESKTOP_EXE),
            registration == ServiceRegistration::Exact,
        )?;
    }
    match registration {
        ServiceRegistration::Absent => {
            // An installed Desktop invokes its adjacent setup for verification
            // and repair. In that case the validated source and active
            // generation are the same directory, so deleting active before
            // staging would destroy the only repair source. Register and
            // probe the already validated generation in place instead. A
            // downloaded outer Setup always extracts to a distinct temporary
            // package and continues through the replacement transaction below.
            if source_is_active {
                install_and_probe_service(&active)?;
                return Ok(false);
            }
            cleanup_product_data_for_uninstall().map_err(|_| SetupError::ProductDataUnsafe)?;
            remove_validated_generation(&active, false)?;
            stage_package(&source, &package, &staging)?;
            fs::rename(&staging, &active).map_err(SetupError::Io)?;
            if let Err(error) = install_and_probe_service(&active) {
                rollback_new_generation(&active)?;
                return Err(error);
            }
            return Ok(false);
        }
        ServiceRegistration::Exact if !replacement_required => {
            // "Verify / upgrade" is also used to verify an already installed
            // generation. Re-running Recover for the exact same package is
            // both unnecessary and harmful: a faulted runtime may legitimately
            // require a separate user-visible network recovery, but that must
            // not turn package verification into installer_failed.
            ensure_service_started().map_err(|_| SetupError::ServiceUnavailable)?;
            probe_service()?;
            return Ok(false);
        }
        ServiceRegistration::Exact => {}
    }
    // Prefer convergence through the installed generation. If that exact
    // recovery is the defect being upgraded, preserve the protected owned
    // record and hand it to the new same-schema service generation. The new
    // service still proves process and adapter identity before cleanup; no
    // unknown resource is inferred or removed by the installer.
    let _ = recover_service();
    uninstall_service(&active)?;
    wait_until_service_binary_unlocked(&active.join(SERVICE_EXE))?;
    stage_package(&source, &package, &staging)?;
    fs::rename(&active, &rollback).map_err(SetupError::Io)?;
    if let Err(error) = fs::rename(&staging, &active).map_err(SetupError::Io) {
        fs::rename(&rollback, &active).map_err(SetupError::Io)?;
        install_and_probe_service(&active)?;
        return Err(error);
    }

    if install_and_probe_service(&active).is_err() {
        rollback_new_generation(&active)?;
        fs::rename(&rollback, &active).map_err(SetupError::Io)?;
        install_and_probe_service(&active)?;
        return Err(SetupError::UpgradeRolledBack);
    }
    remove_validated_generation(&rollback, false)?;
    Ok(true)
}

fn repair_requires_desktop_exit(
    source_is_active: bool,
    registration: ServiceRegistration,
    replacement_required: bool,
) -> bool {
    // The in-product "Verify / repair" flow runs setup from the active
    // directory. Merely registering or probing its service must not stop the
    // invoking Desktop; only a transaction that replaces product files does.
    match registration {
        ServiceRegistration::Absent => !source_is_active,
        ServiceRegistration::Exact => replacement_required,
    }
}

fn generation_requires_replacement(installed: &ProductPackage, source: &ProductPackage) -> bool {
    // The validated manifest, not DisplayVersion alone, identifies the exact
    // installed generation. This keeps an identical in-product repair cheap,
    // while an outer Setup carrying rebuilt same-version binaries still takes
    // the full stop/stage/verify/rollback transaction.
    installed != source
}

fn stop_running_desktop(expected_path: &Path, can_recover: bool) -> Result<bool, SetupError> {
    let processes = running_desktop_processes(expected_path)?;
    if processes.is_empty() {
        return Ok(false);
    }

    if signal_desktop_update_exit() {
        let graceful_deadline = Instant::now() + DESKTOP_EXIT_TIMEOUT;
        if wait_for_processes(&processes, graceful_deadline)? {
            return Ok(true);
        }
    }

    // Older Desktop generations do not expose the bounded update-exit event.
    // Restore exact owned network state before terminating only the already
    // path- and session-bound installed processes.
    if can_recover {
        recover_service()?;
    }
    for process in &processes {
        if unsafe { WaitForSingleObject(process.0, 0) }
            == windows_sys::Win32::Foundation::WAIT_TIMEOUT
            && unsafe { TerminateProcess(process.0, 0) } == 0
        {
            return Err(SetupError::DesktopStopFailed);
        }
    }
    let forced_deadline = Instant::now() + FILE_UNLOCK_TIMEOUT;
    if !wait_for_processes(&processes, forced_deadline)? {
        return Err(SetupError::DesktopStopTimeout);
    }
    Ok(true)
}

fn running_desktop_processes(expected_path: &Path) -> Result<Vec<OwnedHandle>, SetupError> {
    let expected = expected_path.canonicalize().map_err(SetupError::Io)?;
    let mut current_session = 0_u32;
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) } == 0 {
        return Err(SetupError::DesktopInspectionFailed);
    }
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(SetupError::DesktopInspectionFailed);
    }
    let snapshot = OwnedHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = Vec::new();
    let mut has_entry = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
    if !has_entry && unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
        return Err(SetupError::DesktopInspectionFailed);
    }
    while has_entry {
        if process_entry_name(&entry).eq_ignore_ascii_case(DESKTOP_EXE) {
            let mut session = 0_u32;
            if unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut session) } != 0
                && session == current_session
            {
                let raw = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                        0,
                        entry.th32ProcessID,
                    )
                };
                if raw.is_null() {
                    return Err(SetupError::DesktopInspectionFailed);
                }
                let process = OwnedHandle(raw);
                let actual = process_image_path(process.0)?;
                if paths_equal(&actual, &expected) {
                    found.push(process);
                }
            }
        }
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        has_entry = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        if !has_entry && unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
            return Err(SetupError::DesktopInspectionFailed);
        }
    }
    Ok(found)
}

fn process_entry_name(entry: &PROCESSENTRY32W) -> String {
    let length = entry
        .szExeFile
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..length])
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, SetupError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0
        || length == 0
        || length as usize > buffer.len()
    {
        return Err(SetupError::DesktopInspectionFailed);
    }
    PathBuf::from(String::from_utf16_lossy(&buffer[..length as usize]))
        .canonicalize()
        .map_err(SetupError::Io)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn signal_desktop_update_exit() -> bool {
    let name: Vec<u16> = UPDATE_EXIT_EVENT
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if !event.is_null() {
        let event = OwnedHandle(event);
        return unsafe { SetEvent(event.0) } != 0;
    }
    false
}

fn wait_for_processes(processes: &[OwnedHandle], deadline: Instant) -> Result<bool, SetupError> {
    for process in processes {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let remaining = deadline.saturating_duration_since(now);
            let timeout = remaining.as_millis().min(u32::MAX as u128) as u32;
            match unsafe { WaitForSingleObject(process.0, timeout) } {
                windows_sys::Win32::Foundation::WAIT_OBJECT_0
                | windows_sys::Win32::Foundation::WAIT_ABANDONED => break,
                windows_sys::Win32::Foundation::WAIT_TIMEOUT => return Ok(false),
                _ => return Err(SetupError::DesktopInspectionFailed),
            }
        }
    }
    Ok(true)
}

fn rollback_new_generation(active: &Path) -> Result<(), SetupError> {
    match service_registration().map_err(|_| SetupError::InstallationRollbackFailed)? {
        ServiceRegistration::Absent => {}
        ServiceRegistration::Exact => {
            uninstall_service(active).map_err(|_| SetupError::InstallationRollbackFailed)?;
            wait_until_service_binary_unlocked(&active.join(SERVICE_EXE))
                .map_err(|_| SetupError::InstallationRollbackFailed)?;
        }
    }
    cleanup_product_data_for_uninstall().map_err(|_| SetupError::InstallationRollbackFailed)?;
    remove_validated_generation(active, false).map_err(|_| SetupError::InstallationRollbackFailed)
}

fn uninstall(program_files: &Path) -> Result<(), SetupError> {
    let active = program_files.join(PRODUCT_DIRECTORY);
    let staging = program_files.join(STAGING_DIRECTORY);
    let rollback = program_files.join(ROLLBACK_DIRECTORY);
    reject_transaction_residue(&staging, &rollback)?;
    validate_generation(&active)?;
    match service_registration().map_err(|_| SetupError::ServiceRegistrationUnsafe)? {
        ServiceRegistration::Absent => {
            // A prior exact uninstall may already have removed the SCM entry
            // before a locked product image prevented generation deletion.
            // Resume only after the remaining generation and protected data
            // independently satisfy their strict validators. No process,
            // adapter, route, or unproved resource is inferred from absence.
        }
        ServiceRegistration::Exact => {
            recover_service()?;
            uninstall_service(&active)?;
            wait_until_service_binary_unlocked(&active.join(SERVICE_EXE))?;
        }
    }
    cleanup_product_data_for_uninstall().map_err(|_| SetupError::ProductDataUnsafe)?;
    remove_validated_generation(&active, true)
}

fn stage_package(
    source: &Path,
    package: &ProductPackage,
    staging: &Path,
) -> Result<(), SetupError> {
    create_protected_directory(staging)?;
    let result = (|| {
        for filename in PAYLOAD_FILENAMES.into_iter().chain([PACKAGE_MANIFEST]) {
            let target = staging.join(filename);
            let mut source_file = OpenOptions::new()
                .read(true)
                .open(source.join(filename))
                .map_err(SetupError::Io)?;
            let mut target_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(SetupError::Io)?;
            io::copy(&mut source_file, &mut target_file).map_err(SetupError::Io)?;
            target_file.sync_all().map_err(SetupError::Io)?;
        }
        package.validate_directory(staging)?;
        validate_generation(staging).map(|_| ())
    })();
    if result.is_err() {
        let _ = remove_validated_generation(staging, false);
    }
    result
}

fn validate_generation(root: &Path) -> Result<ProductPackage, SetupError> {
    reject_reparse_point(root, "product generation").map_err(|_| SetupError::UnsafePath)?;
    validate_asset_acl(root, "product generation").map_err(|_| SetupError::UnsafeAcl)?;
    let package = read_package_for_upgrade(root)?;
    package.validate_upgrade_directory(root)?;
    for filename in PAYLOAD_FILENAMES.into_iter().chain([PACKAGE_MANIFEST]) {
        let path = root.join(filename);
        reject_reparse_point(&path, "product asset").map_err(|_| SetupError::UnsafePath)?;
        validate_asset_acl(&path, "product asset").map_err(|_| SetupError::UnsafeAcl)?;
        if path.canonicalize().map_err(SetupError::Io)?.parent()
            != Some(root.canonicalize().map_err(SetupError::Io)?.as_path())
        {
            return Err(SetupError::UnsafePath);
        }
    }
    Ok(package)
}

fn remove_validated_generation(root: &Path, defer_locked: bool) -> Result<(), SetupError> {
    validate_generation(root)?;
    for (index, filename) in PAYLOAD_FILENAMES
        .into_iter()
        .chain([PACKAGE_MANIFEST])
        .enumerate()
    {
        let path = root.join(filename);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if defer_locked && is_locked_image_error(&error) => {
                schedule_delete_after_reboot(&path)
                    .map_err(|_| SetupError::GenerationDeleteFailed(index))?;
            }
            Err(_) => return Err(SetupError::GenerationDeleteFailed(index)),
        }
    }
    match fs::remove_dir(root) {
        Ok(()) => Ok(()),
        Err(error) if defer_locked && is_deferable_directory_error(&error) => {
            schedule_delete_after_reboot(root)
                .map_err(|_| SetupError::GenerationDirectoryDeleteFailed)
        }
        Err(_) => Err(SetupError::GenerationDirectoryDeleteFailed),
    }
}

fn is_locked_image_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            error.raw_os_error().map(|value| value as u32),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        )
}

fn is_deferable_directory_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::DirectoryNotEmpty || is_locked_image_error(error)
}

fn schedule_delete_after_reboot(path: &Path) -> Result<(), SetupError> {
    let wide = wide_path(path);
    if unsafe { MoveFileExW(wide.as_ptr(), ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(SetupError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn reject_transaction_residue(staging: &Path, rollback: &Path) -> Result<(), SetupError> {
    if staging.exists() || rollback.exists() {
        return Err(SetupError::TransactionResidue);
    }
    Ok(())
}

fn reconcile_interrupted_install(
    active: &Path,
    staging: &Path,
    rollback: &Path,
) -> Result<(), SetupError> {
    if !staging.exists() && !rollback.exists() {
        return Ok(());
    }
    let registration = service_registration().map_err(|_| SetupError::ServiceRegistrationUnsafe)?;
    if !repairable_install_residue(
        active.exists(),
        staging.exists(),
        rollback.exists(),
        registration,
    ) {
        return Err(SetupError::TransactionResidue);
    }

    // This exact shape means active was committed and its service registered,
    // but cleanup of the inactive rollback generation was interrupted. Both
    // generations must independently pass strict manifest/hash/ACL validation
    // before any process or file is touched.
    validate_generation(active)?;
    validate_generation(rollback)?;
    stop_running_desktop(&active.join(DESKTOP_EXE), true)?;
    stop_running_desktop(&rollback.join(DESKTOP_EXE), true)?;
    remove_validated_generation(rollback, false)
}

fn repairable_install_residue(
    active_exists: bool,
    staging_exists: bool,
    rollback_exists: bool,
    registration: ServiceRegistration,
) -> bool {
    active_exists
        && !staging_exists
        && rollback_exists
        && registration == ServiceRegistration::Exact
}

fn recover_service() -> Result<(), SetupError> {
    ensure_service_started().map_err(|_| SetupError::ServiceUnavailable)?;
    let mut client = ServiceClient::connect().map_err(|_| SetupError::ServiceUnavailable)?;
    client
        .recover()
        .map_err(|_| SetupError::ServiceRecoveryFailed)?;
    Ok(())
}

fn install_and_probe_service(active: &Path) -> Result<(), SetupError> {
    run_service_verb(active, "install")?;
    probe_service()
}

fn probe_service() -> Result<(), SetupError> {
    let deadline = Instant::now() + SERVICE_READY_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(mut client) = ServiceClient::connect() {
            let expected = required_service_capabilities();
            if client.capabilities() == expected && client.status().is_ok() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(SetupError::ServiceProbeFailed)
}

fn uninstall_service(active: &Path) -> Result<(), SetupError> {
    run_service_verb(active, "uninstall")
}

fn run_service_verb(active: &Path, verb: &'static str) -> Result<(), SetupError> {
    let status = Command::new(active.join(SERVICE_EXE))
        .arg(verb)
        .status()
        .map_err(SetupError::Io)?;
    require_success(status)
}

fn require_success(status: ExitStatus) -> Result<(), SetupError> {
    if status.success() {
        Ok(())
    } else {
        Err(SetupError::ServiceCommandFailed)
    }
}

fn wait_until_service_binary_unlocked(path: &Path) -> Result<(), SetupError> {
    let deadline = Instant::now() + FILE_UNLOCK_TIMEOUT;
    while Instant::now() < deadline {
        match OpenOptions::new().write(true).open(path) {
            Ok(_) => return Ok(()),
            Err(error) if is_transient_image_lock(&error) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(SetupError::Io(error)),
        }
    }
    Err(SetupError::ServiceStopTimeout)
}

fn is_transient_image_lock(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_SHARING_VIOLATION as i32
                    || code == ERROR_LOCK_VIOLATION as i32
        )
}

fn create_protected_directory(path: &Path) -> Result<(), SetupError> {
    if path.exists() {
        return Err(SetupError::TransactionResidue);
    }
    let descriptor = SecurityDescriptor::from_sddl(PROTECTED_DIRECTORY_SDDL)?;
    let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_ALREADY_EXISTS {
            return Err(SetupError::TransactionResidue);
        }
        return Err(SetupError::Io(io::Error::from_raw_os_error(code as i32)));
    }
    validate_asset_acl(path, "staging directory").map_err(|_| SetupError::UnsafeAcl)
}

fn require_elevated_interactive_session() -> Result<(), SetupError> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(SetupError::Io(io::Error::last_os_error()));
    }
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0_u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(SetupError::Io(io::Error::last_os_error()));
    }
    if elevation.TokenIsElevated == 0 {
        return Err(SetupError::ElevationRequired);
    }
    let mut session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) } == 0 {
        return Err(SetupError::Io(io::Error::last_os_error()));
    }
    if session_id == 0 {
        return Err(SetupError::InteractiveSessionRequired);
    }
    Ok(())
}

fn program_files_directory() -> Result<PathBuf, SetupError> {
    let mut raw = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut raw) };
    if result < 0 {
        return Err(SetupError::KnownFolder);
    }
    let mut length = 0_usize;
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let path = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map(PathBuf::from)
        .map_err(|_| SetupError::KnownFolder);
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, SetupError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(SetupError::Io(io::Error::last_os_error()));
        }
        Ok(Self(raw))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0 as HLOCAL) };
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("setup accepts exactly install, update-core, or uninstall")]
    InvalidArguments,
    #[error("administrator elevation is required")]
    ElevationRequired,
    #[error("an interactive user session is required")]
    InteractiveSessionRequired,
    #[error("a fixed setup path failed validation")]
    UnsafePath,
    #[error("a product generation ACL failed validation")]
    UnsafeAcl,
    #[error("a previous setup transaction requires inspection")]
    TransactionResidue,
    #[error("the core update package changes non-core product assets")]
    CoreUpdatePackageMismatch,
    #[error("the existing service is unavailable")]
    ServiceUnavailable,
    #[error("the SCM registration is absent, conflicting, or untrusted")]
    ServiceRegistrationUnsafe,
    #[error("the existing service could not recover exact owned resources")]
    ServiceRecoveryFailed,
    #[error("a fixed service command failed")]
    ServiceCommandFailed,
    #[error("the service did not pass its authenticated readiness probe")]
    ServiceProbeFailed,
    #[error("the service did not release its fixed binary before the deadline")]
    ServiceStopTimeout,
    #[error("the installed Desktop process could not be inspected safely")]
    DesktopInspectionFailed,
    #[error("the installed Desktop process could not be stopped safely")]
    DesktopStopFailed,
    #[error("the installed Desktop process did not exit before the deadline")]
    DesktopStopTimeout,
    #[error("protected product data did not satisfy exact uninstall cleanup")]
    ProductDataUnsafe,
    #[error("the upgrade failed and the validated previous generation was restored")]
    UpgradeRolledBack,
    #[error("the failed installation could not be rolled back safely")]
    InstallationRollbackFailed,
    #[error("a fixed product generation file could not be deleted at index {0}")]
    GenerationDeleteFailed(usize),
    #[error("the fixed product generation directory could not be deleted")]
    GenerationDirectoryDeleteFailed,
    #[error("a Windows known folder lookup failed")]
    KnownFolder,
    #[error("setup I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Package(#[from] PackageError),
}

impl SetupError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::ElevationRequired => "elevation_required",
            Self::InteractiveSessionRequired => "interactive_session_required",
            Self::UnsafePath => "unsafe_path",
            Self::UnsafeAcl => "unsafe_acl",
            Self::TransactionResidue => "transaction_residue",
            Self::CoreUpdatePackageMismatch => "core_update_package_mismatch",
            Self::ServiceUnavailable => "service_unavailable",
            Self::ServiceRegistrationUnsafe => "service_registration_unsafe",
            Self::ServiceRecoveryFailed => "service_recovery_failed",
            Self::ServiceCommandFailed => "service_command_failed",
            Self::ServiceProbeFailed => "service_probe_failed",
            Self::ServiceStopTimeout => "service_stop_timeout",
            Self::DesktopInspectionFailed => "desktop_inspection_failed",
            Self::DesktopStopFailed => "desktop_stop_failed",
            Self::DesktopStopTimeout => "desktop_stop_timeout",
            Self::ProductDataUnsafe => "product_data_unsafe",
            Self::UpgradeRolledBack => "upgrade_rolled_back",
            Self::InstallationRollbackFailed => "installation_rollback_failed",
            Self::GenerationDeleteFailed(0) => "generation_delete_desktop_failed",
            Self::GenerationDeleteFailed(1) => "generation_delete_setup_failed",
            Self::GenerationDeleteFailed(2) => "generation_delete_service_failed",
            Self::GenerationDeleteFailed(3) => "generation_delete_cli_failed",
            Self::GenerationDeleteFailed(4) => "generation_delete_engine_failed",
            Self::GenerationDeleteFailed(5) => "generation_delete_engine_manifest_failed",
            Self::GenerationDeleteFailed(6) => "generation_delete_product_manifest_failed",
            Self::GenerationDeleteFailed(_) => "generation_delete_unknown_index",
            Self::GenerationDirectoryDeleteFailed => "generation_directory_delete_failed",
            Self::KnownFolder => "known_folder_failed",
            Self::Io(_) => "io_failed",
            Self::Package(_) => "package_invalid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PackageFile, PRODUCT_VERSION, REQUIRED_CAPABILITIES, SERVICE_FEATURE,
        SERVICE_PROTOCOL_VERSION,
    };

    fn package_fixture() -> ProductPackage {
        ProductPackage {
            schema_version: crate::PACKAGE_SCHEMA_VERSION,
            product_version: PRODUCT_VERSION.into(),
            service_feature: SERVICE_FEATURE.into(),
            service_protocol_version: SERVICE_PROTOCOL_VERSION,
            service_capabilities: REQUIRED_CAPABILITIES.map(str::to_owned).to_vec(),
            files: PAYLOAD_FILENAMES
                .map(|filename| PackageFile {
                    filename: filename.into(),
                    size: 1,
                    sha256: "a".repeat(64),
                })
                .to_vec(),
        }
    }

    #[test]
    fn setup_verbs_are_closed() {
        assert_eq!(
            SetupVerb::parse(&["install".into()]).unwrap(),
            SetupVerb::Install
        );
        assert_eq!(
            SetupVerb::parse(&["update-core".into()]).unwrap(),
            SetupVerb::UpdateCore
        );
        assert_eq!(
            SetupVerb::parse(&["uninstall".into()]).unwrap(),
            SetupVerb::Uninstall
        );
        for invalid in [
            Vec::new(),
            vec!["upgrade".into()],
            vec!["install".into(), "C:\\Other".into()],
        ] {
            assert!(matches!(
                SetupVerb::parse(&invalid),
                Err(SetupError::InvalidArguments)
            ));
        }
    }

    #[test]
    fn reports_are_fixed_and_redacted() {
        let report = serde_json::to_string(&SetupReport::failure(
            SetupVerb::Install,
            &SetupError::ServiceProbeFailed,
        ))
        .unwrap();
        assert!(report.contains("service_probe_failed"));
        assert!(!report.contains("Program Files"));
    }

    #[test]
    fn service_probe_requires_the_manifest_capabilities_in_exact_order() {
        let capabilities = serde_json::to_value(required_service_capabilities()).unwrap();
        assert_eq!(
            capabilities,
            serde_json::to_value(crate::REQUIRED_CAPABILITIES).unwrap()
        );
    }

    #[test]
    fn only_an_exact_manifest_match_skips_generation_replacement() {
        let installed = package_fixture();
        let source = installed.clone();
        assert!(!generation_requires_replacement(&installed, &source));

        let mut rebuilt_same_version = source.clone();
        rebuilt_same_version.files[2].sha256 = "b".repeat(64);
        assert!(generation_requires_replacement(
            &installed,
            &rebuilt_same_version
        ));

        let mut newer_core_same_product = installed.clone();
        newer_core_same_product.files[4].sha256 = "c".repeat(64);
        newer_core_same_product.files[5].sha256 = "d".repeat(64);
        assert!(generation_requires_replacement(
            &installed,
            &newer_core_same_product
        ));

        let mut next_version = source;
        next_version.product_version = "0.2.2".into();
        assert!(generation_requires_replacement(&installed, &next_version));
    }

    #[test]
    fn in_product_service_repair_keeps_the_desktop_running() {
        assert!(!repair_requires_desktop_exit(
            true,
            ServiceRegistration::Absent,
            false
        ));
        assert!(!repair_requires_desktop_exit(
            true,
            ServiceRegistration::Exact,
            false
        ));
        assert!(repair_requires_desktop_exit(
            false,
            ServiceRegistration::Absent,
            true
        ));
        assert!(repair_requires_desktop_exit(
            false,
            ServiceRegistration::Exact,
            true
        ));
    }

    #[test]
    fn core_update_rejects_product_or_non_core_payload_changes() {
        let installed = package_fixture();
        let mut core_only = installed.clone();
        core_only.files[4].sha256 = "b".repeat(64);
        core_only.files[5].sha256 = "c".repeat(64);
        assert!(validate_core_update_package(&installed, &core_only).is_ok());

        let mut changed_desktop = core_only.clone();
        changed_desktop.files[0].sha256 = "d".repeat(64);
        assert!(matches!(
            validate_core_update_package(&installed, &changed_desktop),
            Err(SetupError::CoreUpdatePackageMismatch)
        ));

        let mut changed_product = core_only;
        changed_product.product_version = "0.2.15".into();
        assert!(matches!(
            validate_core_update_package(&installed, &changed_product),
            Err(SetupError::CoreUpdatePackageMismatch)
        ));
    }

    #[test]
    fn installed_desktop_path_comparison_is_case_insensitive_but_exact() {
        assert!(paths_equal(
            Path::new(r"C:\Program Files\TunBridge\tunbridge-desktop.exe"),
            Path::new(r"c:\program files\tunbridge\TUNBRIDGE-DESKTOP.EXE")
        ));
        assert!(!paths_equal(
            Path::new(r"C:\Other\tunbridge-desktop.exe"),
            Path::new(r"C:\Program Files\TunBridge\tunbridge-desktop.exe")
        ));
    }

    #[test]
    fn desktop_process_entry_name_is_bounded_at_nul() {
        let mut entry = PROCESSENTRY32W::default();
        for (target, source) in entry
            .szExeFile
            .iter_mut()
            .zip("tunbridge-desktop.exe".encode_utf16())
        {
            *target = source;
        }
        assert_eq!(process_entry_name(&entry), DESKTOP_EXE);
    }

    #[test]
    fn only_committed_active_plus_inactive_rollback_is_auto_repairable() {
        assert!(repairable_install_residue(
            true,
            false,
            true,
            ServiceRegistration::Exact
        ));
        for facts in [
            (false, false, true, ServiceRegistration::Exact),
            (true, true, true, ServiceRegistration::Exact),
            (true, true, false, ServiceRegistration::Exact),
            (true, false, true, ServiceRegistration::Absent),
        ] {
            assert!(!repairable_install_residue(
                facts.0, facts.1, facts.2, facts.3
            ));
        }
    }

    #[test]
    fn only_native_image_lock_errors_are_retryable() {
        assert!(is_transient_image_lock(&io::Error::from_raw_os_error(
            ERROR_SHARING_VIOLATION as i32,
        )));
        assert!(is_transient_image_lock(&io::Error::from_raw_os_error(
            ERROR_LOCK_VIOLATION as i32,
        )));
        assert!(!is_transient_image_lock(&io::Error::from_raw_os_error(2)));
    }

    #[test]
    fn locked_image_errors_are_the_only_deferred_file_failures() {
        assert!(is_locked_image_error(&io::Error::from_raw_os_error(
            ERROR_SHARING_VIOLATION as i32
        )));
        assert!(is_locked_image_error(&io::Error::from_raw_os_error(
            ERROR_LOCK_VIOLATION as i32
        )));
        assert!(is_locked_image_error(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!is_locked_image_error(&io::Error::from_raw_os_error(2)));
        assert!(!is_locked_image_error(&io::Error::from(
            io::ErrorKind::InvalidData
        )));
        assert!(is_deferable_directory_error(&io::Error::from(
            io::ErrorKind::DirectoryNotEmpty
        )));
    }
}
