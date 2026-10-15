use std::{fmt, io, net::SocketAddr, path::Path, path::PathBuf};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    },
};

use crate::{
    protocol::UpstreamProtocol,
    startup::{
        decide_adapter, decide_startup, AdapterDecision, AdapterFact, ProcessFact, RuntimeFact,
        StartupDecision, StartupObservation,
    },
    state::Caller,
};

use super::{
    adapter::{
        native_adapter_instance_id, remove_owned_tun_adapter_instance, valid_wintun_instance_id,
        AdapterError, TUN_ALIAS,
    },
    integrity::{validate_engine_files, IntegrityError, ValidatedEngine},
    process::{
        normalized_path, query_process_identity, query_process_identity_from_handle,
        ProcessIdentity, ProcessIdentityError,
    },
    storage::{ProtectedDataDirectory, StorageError},
    upstream::{
        verify_loopback_listener_owner, verify_recorded_loopback_listener, UpstreamIdentityError,
        VerifiedUpstream,
    },
};

const OWNED_ENGINE_SCHEMA_VERSION: u16 = 4;
const MAX_PREEXISTING_WINTUN_INSTANCES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedEngineStage {
    Pending,
    Running,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedEngineRecord {
    pub schema_version: u16,
    pub product_version: String,
    pub stage: OwnedEngineStage,
    pub pid: u32,
    pub creation_time: u64,
    pub image_path: PathBuf,
    pub engine_version: String,
    pub engine_sha256: String,
    pub owner_principal_id: String,
    pub owner_session_id: u32,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_protocol: UpstreamProtocol,
    #[serde(default)]
    pub remote_upstream: bool,
    pub upstream_pid: u32,
    pub upstream_creation_time: u64,
    pub upstream_image_path: PathBuf,
    pub controller_host: String,
    pub controller_port: u16,
    pub adapter_alias: String,
    pub preexisting_wintun_instances: Vec<String>,
    pub adapter_instance_id: Option<String>,
}

impl fmt::Debug for OwnedEngineRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedEngineRecord")
            .field("schema_version", &self.schema_version)
            .field("product_version", &self.product_version)
            .field("stage", &self.stage)
            .field("pid", &self.pid)
            .field("remote_upstream", &self.remote_upstream)
            .field("upstream_endpoint", &"[REDACTED]")
            .field("controller_host", &self.controller_host)
            .field("controller_port", &self.controller_port)
            .field("adapter_alias", &self.adapter_alias)
            .finish_non_exhaustive()
    }
}

impl OwnedEngineRecord {
    pub fn validate(&self) -> Result<(), OwnedEngineError> {
        if !matches!(self.schema_version, 3 | OWNED_ENGINE_SCHEMA_VERSION) {
            return Err(OwnedEngineError::UnsupportedSchema(self.schema_version));
        }
        if self.schema_version == 3 && self.remote_upstream {
            return Err(OwnedEngineError::InvalidRecord);
        }
        if !valid_product_version(&self.product_version) {
            return Err(OwnedEngineError::InvalidRecord);
        }
        if self.pid == 0 || self.creation_time == 0 || !self.image_path.is_absolute() {
            return Err(OwnedEngineError::InvalidRecord);
        }
        if self.engine_version.is_empty()
            || self.engine_version.len() > 64
            || self.engine_version.chars().any(char::is_control)
            || self.engine_sha256.len() != 64
            || !self
                .engine_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.owner_principal_id.is_empty()
            || self.owner_principal_id.len() > 184
            || self.owner_principal_id.chars().any(char::is_control)
            || self.upstream_port == 0
            || !matches!(self.controller_host.as_str(), "127.0.0.1" | "::1")
            || self.controller_port == 0
            || self.adapter_alias != TUN_ALIAS
            || self.preexisting_wintun_instances.len() > MAX_PREEXISTING_WINTUN_INSTANCES
            || self.preexisting_wintun_instances.iter().any(|instance| {
                !valid_wintun_instance_id(instance) || *instance != instance.to_ascii_uppercase()
            })
            || self
                .preexisting_wintun_instances
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(OwnedEngineError::InvalidRecord);
        }
        if self.remote_upstream {
            let address = self
                .upstream_host
                .parse::<std::net::IpAddr>()
                .map_err(|_| OwnedEngineError::InvalidRecord)?;
            tunbridge_core::upstream::normalize_remote_host(&address.to_string())
                .map_err(|_| OwnedEngineError::InvalidRecord)?;
            if self.upstream_pid != 0
                || self.upstream_creation_time != 0
                || !self.upstream_image_path.as_os_str().is_empty()
            {
                return Err(OwnedEngineError::InvalidRecord);
            }
        } else if !matches!(self.upstream_host.as_str(), "127.0.0.1" | "::1")
            || self.upstream_pid == 0
            || self.upstream_creation_time == 0
            || !self.upstream_image_path.is_absolute()
        {
            return Err(OwnedEngineError::InvalidRecord);
        }
        match (self.stage, self.adapter_instance_id.as_deref()) {
            (OwnedEngineStage::Pending, None) => {}
            (OwnedEngineStage::Running, Some(instance))
                if valid_wintun_instance_id(instance)
                    && instance.as_bytes()[12..48]
                        .iter()
                        .all(|byte| !byte.is_ascii_lowercase()) => {}
            _ => return Err(OwnedEngineError::InvalidRecord),
        }
        Ok(())
    }

    fn preexisting_instance(&self, instance: &str) -> bool {
        let canonical = instance.to_ascii_uppercase();
        self.preexisting_wintun_instances
            .binary_search(&canonical)
            .is_ok()
    }
}

fn valid_product_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid_part = |part: &str| {
        !part.is_empty() && part.len() <= 5 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(major), Some(minor), Some(patch), None)
            if valid_part(major) && valid_part(minor) && valid_part(patch)
    )
}

pub(super) struct PendingRuntimeAssets<'a> {
    pub verified_upstream: Option<&'a VerifiedUpstream>,
    pub remote_upstream: bool,
    pub upstream_host: &'a str,
    pub upstream_port: u16,
    pub upstream_protocol: UpstreamProtocol,
    pub controller: &'a str,
    pub preexisting_wintun_instances: &'a [String],
}

pub(super) fn capture_pending_owned_engine(
    engine: &ValidatedEngine,
    pid: u32,
    owner: &Caller,
    assets: PendingRuntimeAssets<'_>,
) -> Result<OwnedEngineRecord, OwnedEngineError> {
    let identity = query_process_identity(pid).map_err(OwnedEngineError::ProcessQuery)?;
    if !paths_match(identity.image_path(), engine.path()) {
        return Err(OwnedEngineError::ImagePathMismatch);
    }
    let controller: SocketAddr = assets
        .controller
        .parse()
        .map_err(|_| OwnedEngineError::InvalidRecord)?;
    if !controller.ip().is_loopback() {
        return Err(OwnedEngineError::InvalidRecord);
    }
    let (upstream_pid, upstream_creation_time, upstream_image_path) =
        match (assets.remote_upstream, assets.verified_upstream) {
            (false, Some(upstream)) => (
                upstream.pid(),
                upstream.creation_time(),
                upstream.image_path().to_path_buf(),
            ),
            (true, None) => (0, 0, PathBuf::new()),
            _ => return Err(OwnedEngineError::InvalidRecord),
        };
    let record = OwnedEngineRecord {
        schema_version: OWNED_ENGINE_SCHEMA_VERSION,
        product_version: env!("CARGO_PKG_VERSION").into(),
        stage: OwnedEngineStage::Pending,
        pid,
        creation_time: identity.creation_time(),
        image_path: identity.image_path().to_path_buf(),
        engine_version: engine.version().into(),
        engine_sha256: engine.sha256().into(),
        owner_principal_id: owner.principal_id.clone(),
        owner_session_id: owner.session_id,
        upstream_host: match assets.upstream_host {
            "localhost" => "127.0.0.1".into(),
            host => host.into(),
        },
        upstream_port: assets.upstream_port,
        upstream_protocol: assets.upstream_protocol,
        remote_upstream: assets.remote_upstream,
        upstream_pid,
        upstream_creation_time,
        upstream_image_path,
        controller_host: controller.ip().to_string(),
        controller_port: controller.port(),
        adapter_alias: TUN_ALIAS.into(),
        preexisting_wintun_instances: assets.preexisting_wintun_instances.to_vec(),
        adapter_instance_id: None,
    };
    record.validate()?;
    Ok(record)
}

pub(super) fn promote_owned_engine_running(
    record: &OwnedEngineRecord,
) -> Result<OwnedEngineRecord, OwnedEngineError> {
    record.validate()?;
    if record.stage != OwnedEngineStage::Pending {
        return Err(OwnedEngineError::InvalidStage);
    }
    verify_owned_engine(record)?;
    verify_runtime_listeners(record)?;
    let adapter_instance_id = native_adapter_instance_id(&record.adapter_alias)
        .map_err(OwnedEngineError::AdapterIdentity)?
        .ok_or(OwnedEngineError::AdapterMissing)?;
    // Wintun intentionally keeps a disconnected devnode and reuses it on a
    // later launch. Pre-spawn health proved the alias was not operational;
    // the exact owned controller process and post-spawn health checks prove
    // this process reactivated the observed instance. Therefore a retained
    // pre-spawn instance is valid running provenance, even though pending
    // rollback still refuses to remove such a devnode after the process dies.
    let mut running = record.clone();
    running.stage = OwnedEngineStage::Running;
    running.adapter_instance_id = Some(adapter_instance_id);
    running.validate()?;
    Ok(running)
}

pub fn verify_owned_engine(
    record: &OwnedEngineRecord,
) -> Result<ProcessIdentity, OwnedEngineError> {
    record.validate()?;
    let identity = query_process_identity(record.pid).map_err(OwnedEngineError::ProcessQuery)?;
    verify_identity(record, &identity)?;
    Ok(identity)
}

/// Acceptance-only read proof using the production native handle identity
/// path. It returns no PID, path, creation time, or other process metadata.
#[cfg(feature = "acceptance-m2b5")]
pub fn exact_owned_process_running_for_acceptance() -> Result<bool, OwnedEngineError> {
    let Some(record) = load_owned_engine()? else {
        return Ok(false);
    };
    if record.stage != OwnedEngineStage::Running {
        return Ok(false);
    }
    inspect_owned_record(&record).map(|state| matches!(state, OwnedRecordState::Running))
}

fn verify_identity(
    record: &OwnedEngineRecord,
    identity: &ProcessIdentity,
) -> Result<(), OwnedEngineError> {
    if identity.creation_time() != record.creation_time {
        return Err(OwnedEngineError::CreationTimeMismatch);
    }
    if !paths_match(identity.image_path(), &record.image_path) {
        return Err(OwnedEngineError::ImagePathMismatch);
    }
    Ok(())
}

fn verify_runtime_listeners(record: &OwnedEngineRecord) -> Result<(), OwnedEngineError> {
    if !record.remote_upstream {
        verify_recorded_loopback_listener(
            &record.upstream_host,
            record.upstream_port,
            record.upstream_pid,
            record.upstream_creation_time,
            &record.upstream_image_path,
        )
        .map_err(OwnedEngineError::UpstreamIdentity)?;
    }
    verify_loopback_listener_owner(&record.controller_host, record.controller_port, record.pid)
        .map_err(OwnedEngineError::ControllerIdentity)
}

pub fn persist_owned_engine(record: &OwnedEngineRecord) -> Result<PathBuf, OwnedEngineError> {
    record.validate()?;
    ProtectedDataDirectory::prepare()
        .map_err(OwnedEngineError::Storage)?
        .write_owned_state(record)
        .map_err(OwnedEngineError::Storage)
}

pub fn load_owned_engine() -> Result<Option<OwnedEngineRecord>, OwnedEngineError> {
    ProtectedDataDirectory::prepare()
        .map_err(OwnedEngineError::Storage)?
        .read_owned_state()
        .map_err(OwnedEngineError::Storage)
}

pub fn clear_owned_engine() -> Result<(), OwnedEngineError> {
    ProtectedDataDirectory::prepare()
        .map_err(OwnedEngineError::Storage)?
        .clear_owned_state()
        .map_err(OwnedEngineError::Storage)
}

pub fn reconcile_owned_engine() -> Result<RecoveredOwnedEngine, OwnedEngineError> {
    reconcile_owned_engine_with_runtime_validation(true)
}

/// Reconcile for an explicit Recover request without requiring the upstream
/// proxy to retain the PID/creation identity captured when the tunnel began.
/// The owned Mihomo process and adapter remain exact-match boundaries; only
/// the no-longer-relevant upstream/controller health proof is skipped so a
/// restarted local proxy cannot permanently block uninstall or upgrade.
pub fn reconcile_owned_engine_for_recovery() -> Result<RecoveredOwnedEngine, OwnedEngineError> {
    reconcile_owned_engine_with_runtime_validation(false)
}

fn reconcile_owned_engine_with_runtime_validation(
    validate_runtime: bool,
) -> Result<RecoveredOwnedEngine, OwnedEngineError> {
    let storage = ProtectedDataDirectory::prepare().map_err(OwnedEngineError::Storage)?;
    let stored = match storage.read_owned_state() {
        Ok(stored) => stored,
        Err(error) => {
            return match decide_startup(StartupObservation::Invalid) {
                StartupDecision::FaultNoAction => Err(OwnedEngineError::Storage(error)),
                _ => Err(OwnedEngineError::InvalidRecord),
            };
        }
    };
    let Some(record) = stored else {
        return match decide_startup(StartupObservation::Absent) {
            StartupDecision::StoppedNoAction => Ok(RecoveredOwnedEngine::Absent),
            _ => Err(OwnedEngineError::InvalidRecord),
        };
    };

    let (process, process_error) = match inspect_owned_record(&record) {
        Ok(OwnedRecordState::Running) => (ProcessFact::ExactRunning, None),
        Ok(OwnedRecordState::Exited) => (ProcessFact::Exited, None),
        Err(error) => (ProcessFact::Unknown, Some(error)),
    };
    let (runtime, runtime_error) =
        if record.stage == OwnedEngineStage::Running && process == ProcessFact::ExactRunning {
            let verification = verify_recorded_engine_files(&record)
                .and_then(|()| {
                    if validate_runtime {
                        verify_runtime_listeners(&record)
                    } else {
                        Ok(())
                    }
                })
                .and_then(|()| verify_recorded_adapter(&record));
            match verification {
                Ok(()) => (RuntimeFact::Exact, None),
                Err(error) => (RuntimeFact::Unknown, Some(error)),
            }
        } else {
            (RuntimeFact::Unknown, None)
        };
    let observation = match record.stage {
        OwnedEngineStage::Pending => StartupObservation::Pending { process },
        OwnedEngineStage::Running => StartupObservation::Running { process, runtime },
    };

    match decide_startup(observation) {
        StartupDecision::StoppedNoAction => Err(OwnedEngineError::InvalidRecord),
        StartupDecision::FaultNoAction => Err(process_error
            .or(runtime_error)
            .unwrap_or(OwnedEngineError::InvalidRecord)),
        StartupDecision::ConvergePendingExactProcess => {
            terminate_owned_record(&record)?;
            reconcile_exited_assets(&storage, &record, RecoveredOwnedEngine::ClearedPending)
        }
        StartupDecision::ConvergeExitedRecord => reconcile_exited_assets(
            &storage,
            &record,
            match record.stage {
                OwnedEngineStage::Pending => RecoveredOwnedEngine::ClearedPending,
                OwnedEngineStage::Running => RecoveredOwnedEngine::ClearedExited,
            },
        ),
        StartupDecision::RestoreRunning => Ok(RecoveredOwnedEngine::Running(Box::new(record))),
    }
}

fn reconcile_exited_assets(
    storage: &ProtectedDataDirectory,
    record: &OwnedEngineRecord,
    outcome: RecoveredOwnedEngine,
) -> Result<RecoveredOwnedEngine, OwnedEngineError> {
    let (fact, live_instance, query_error) = match native_adapter_instance_id(&record.adapter_alias)
    {
        Ok(None) => (AdapterFact::Missing, None, None),
        Ok(Some(instance)) => (
            classify_adapter_fact(record, &instance),
            Some(instance),
            None,
        ),
        Err(error) => (
            AdapterFact::Unknown,
            None,
            Some(OwnedEngineError::AdapterIdentity(error)),
        ),
    };
    match decide_adapter(fact) {
        AdapterDecision::ClearState => {}
        AdapterDecision::RemoveExactThenClear => {
            let instance = live_instance.ok_or(OwnedEngineError::InvalidRecord)?;
            remove_owned_tun_adapter_instance(&record.adapter_alias, &instance)
                .map_err(OwnedEngineError::AdapterCleanup)?;
        }
        AdapterDecision::FaultRetainState => {
            return Err(query_error.unwrap_or(match fact {
                AdapterFact::Preexisting => OwnedEngineError::PreexistingAdapterInstance,
                AdapterFact::Other => OwnedEngineError::AdapterIdentityMismatch,
                _ => OwnedEngineError::InvalidRecord,
            }));
        }
    }
    storage
        .clear_owned_state()
        .map_err(OwnedEngineError::Storage)?;
    Ok(outcome)
}

fn classify_adapter_fact(record: &OwnedEngineRecord, live_instance: &str) -> AdapterFact {
    match record.stage {
        OwnedEngineStage::Pending if record.preexisting_instance(live_instance) => {
            AdapterFact::Preexisting
        }
        OwnedEngineStage::Pending => AdapterFact::ExactOwned,
        OwnedEngineStage::Running
            if record
                .adapter_instance_id
                .as_deref()
                .is_some_and(|recorded| recorded.eq_ignore_ascii_case(live_instance)) =>
        {
            AdapterFact::ExactOwned
        }
        OwnedEngineStage::Running if record.preexisting_instance(live_instance) => {
            AdapterFact::Preexisting
        }
        OwnedEngineStage::Running => AdapterFact::Other,
    }
}

/// Inspect reconcile liveness and identity through one query/synchronize
/// handle. A signaled process object is trusted only as evidence that no
/// termination is needed; a running object must match creation time and image
/// before it can restore Running ownership. Query failures stay fail-closed.
pub(super) fn inspect_owned_record(
    record: &OwnedEngineRecord,
) -> Result<OwnedRecordState, OwnedEngineError> {
    record.validate()?;
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    // SAFETY: access is read/synchronize-only and validation proved a nonzero
    // PID. No terminate right is requested on the reconcile observation path.
    let raw = unsafe { OpenProcess(access, 0, record.pid) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(OwnedRecordState::Exited);
        }
        return Err(OwnedEngineError::ProcessQuery(
            ProcessIdentityError::Windows(error),
        ));
    }
    let process = TerminationHandle(raw);
    if matches!(wait_process(process.0, 0)?, WaitState::Exited) {
        return Ok(OwnedRecordState::Exited);
    }
    let identity = query_process_identity_from_handle(record.pid, process.0)
        .map_err(OwnedEngineError::ProcessQuery)?;
    if identity.creation_time() != record.creation_time {
        // A PID can only be reused after the recorded process object exited.
        // Treat the record as stale while retaining the current unrelated
        // process untouched; adapter provenance is checked independently
        // before any cleanup or state deletion.
        return Ok(OwnedRecordState::Exited);
    }
    if !paths_match(identity.image_path(), &record.image_path) {
        return Err(OwnedEngineError::ImagePathMismatch);
    }
    if matches!(wait_process(process.0, 0)?, WaitState::Exited) {
        return Ok(OwnedRecordState::Exited);
    }
    Ok(OwnedRecordState::Running)
}

fn verify_recorded_engine_files(record: &OwnedEngineRecord) -> Result<(), OwnedEngineError> {
    let install_root = record
        .image_path
        .parent()
        .ok_or(OwnedEngineError::InvalidRecord)?;
    let engine = validate_engine_files(install_root).map_err(OwnedEngineError::EngineIntegrity)?;
    if !paths_match(engine.path(), &record.image_path)
        || engine.version() != record.engine_version
        || engine.sha256() != record.engine_sha256
    {
        return Err(OwnedEngineError::EngineRecordMismatch);
    }
    Ok(())
}

pub fn stop_persisted_owned_engine() -> Result<StopOwnedOutcome, OwnedEngineError> {
    let storage = ProtectedDataDirectory::prepare().map_err(OwnedEngineError::Storage)?;
    let Some(record) = storage
        .read_owned_state()
        .map_err(OwnedEngineError::Storage)?
    else {
        return Ok(StopOwnedOutcome::NoState);
    };
    let outcome = terminate_owned_record(&record)?;
    match record.stage {
        OwnedEngineStage::Pending => {
            remove_pending_adapter(&record)?;
        }
        OwnedEngineStage::Running => remove_recorded_adapter(&record)?,
    };
    storage
        .clear_owned_state()
        .map_err(OwnedEngineError::Storage)?;
    Ok(outcome)
}

pub(super) fn remove_pending_adapter(record: &OwnedEngineRecord) -> Result<(), OwnedEngineError> {
    record.validate()?;
    if record.stage != OwnedEngineStage::Pending {
        return Err(OwnedEngineError::InvalidStage);
    }
    let Some(instance) = native_adapter_instance_id(&record.adapter_alias)
        .map_err(OwnedEngineError::AdapterIdentity)?
    else {
        return Ok(());
    };
    verify_pending_adapter_provenance(record, &instance)?;
    remove_owned_tun_adapter_instance(&record.adapter_alias, &instance)
        .map(|_| ())
        .map_err(OwnedEngineError::AdapterCleanup)
}

fn verify_pending_adapter_provenance(
    record: &OwnedEngineRecord,
    instance: &str,
) -> Result<(), OwnedEngineError> {
    if record.preexisting_instance(instance) {
        Err(OwnedEngineError::PreexistingAdapterInstance)
    } else {
        Ok(())
    }
}

fn verify_recorded_adapter(record: &OwnedEngineRecord) -> Result<(), OwnedEngineError> {
    let recorded = record
        .adapter_instance_id
        .as_deref()
        .ok_or(OwnedEngineError::InvalidRecord)?;
    let live = native_adapter_instance_id(&record.adapter_alias)
        .map_err(OwnedEngineError::AdapterIdentity)?
        .ok_or(OwnedEngineError::AdapterMissing)?;
    if !live.eq_ignore_ascii_case(recorded) {
        return Err(OwnedEngineError::AdapterIdentityMismatch);
    }
    Ok(())
}

fn remove_recorded_adapter(record: &OwnedEngineRecord) -> Result<(), OwnedEngineError> {
    let recorded = record
        .adapter_instance_id
        .as_deref()
        .ok_or(OwnedEngineError::InvalidRecord)?;
    remove_owned_tun_adapter_instance(&record.adapter_alias, recorded)
        .map(|_| ())
        .map_err(OwnedEngineError::AdapterCleanup)
}

/// Acceptance-only helper for the SCM reconcile test. It has no PID/path
/// parameter and terminates only the exact process identity loaded from the
/// protected owned record, deliberately leaving adapter and state for the next
/// service instance to reconcile.
#[cfg(feature = "acceptance-fault-injection")]
pub fn terminate_owned_process_for_acceptance() -> Result<StopOwnedOutcome, OwnedEngineError> {
    let storage = ProtectedDataDirectory::prepare().map_err(OwnedEngineError::Storage)?;
    let Some(record) = storage
        .read_owned_state()
        .map_err(OwnedEngineError::Storage)?
    else {
        return Ok(StopOwnedOutcome::NoState);
    };
    terminate_owned_record(&record)
}

/// Acceptance-only helper that removes only the exact live adapter instance
/// committed in the protected running record. It accepts no alias, instance,
/// path, PID, route, or command parameter and deliberately leaves the engine
/// and state for the real watchdog sampler to observe and converge.
#[cfg(feature = "acceptance-fault-injection")]
pub fn remove_owned_adapter_for_acceptance() -> Result<(), OwnedEngineError> {
    let storage = ProtectedDataDirectory::prepare().map_err(OwnedEngineError::Storage)?;
    let record = storage
        .read_owned_state()
        .map_err(OwnedEngineError::Storage)?
        .ok_or(OwnedEngineError::InvalidRecord)?;
    if record.stage != OwnedEngineStage::Running {
        return Err(OwnedEngineError::InvalidStage);
    }
    remove_recorded_adapter(&record)
}

fn terminate_owned_record(
    record: &OwnedEngineRecord,
) -> Result<StopOwnedOutcome, OwnedEngineError> {
    record.validate()?;
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
    // SAFETY: access is limited to query, synchronization, and exact-handle
    // termination; record validation guarantees a nonzero PID.
    let raw = unsafe { OpenProcess(access, 0, record.pid) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(StopOwnedOutcome::AlreadyExited);
        }
        return Err(OwnedEngineError::TerminationOpen(error));
    }
    let process = TerminationHandle(raw);

    // An exited process can remain openable while another component retains a
    // handle to its process object. QueryFullProcessImageNameW is not reliable
    // for that signaled object. Check liveness first on this same handle: an
    // already-exited object needs no termination, while a reused/running PID
    // still proceeds through full creation-time and image verification before
    // TerminateProcess.
    if matches!(wait_process(process.0, 0)?, WaitState::Exited) {
        return Ok(StopOwnedOutcome::AlreadyExited);
    }
    let identity = query_process_identity_from_handle(record.pid, process.0)
        .map_err(OwnedEngineError::ProcessQuery)?;
    verify_identity(record, &identity)?;
    // SAFETY: identity was verified on this same process handle, eliminating
    // the PID-reuse gap between verification and termination.
    if unsafe { TerminateProcess(process.0, 1) } == 0 {
        return Err(OwnedEngineError::TerminationFailed(
            io::Error::last_os_error(),
        ));
    }
    match wait_process(process.0, 5_000)? {
        WaitState::Exited => Ok(StopOwnedOutcome::Terminated),
        WaitState::Running => Err(OwnedEngineError::TerminationTimeout),
    }
}

fn wait_process(process: HANDLE, timeout_ms: u32) -> Result<WaitState, OwnedEngineError> {
    // SAFETY: process is a live owned handle with synchronize access.
    match unsafe { WaitForSingleObject(process, timeout_ms) } {
        WAIT_OBJECT_0 => Ok(WaitState::Exited),
        WAIT_TIMEOUT => Ok(WaitState::Running),
        WAIT_FAILED => Err(OwnedEngineError::TerminationWait(io::Error::last_os_error())),
        result => Err(OwnedEngineError::UnexpectedWait(result)),
    }
}

enum WaitState {
    Running,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnedRecordState {
    Running,
    Exited,
}

struct TerminationHandle(HANDLE);

impl Drop for TerminationHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle ownership came from OpenProcess.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredOwnedEngine {
    Absent,
    Running(Box<OwnedEngineRecord>),
    ClearedPending,
    ClearedExited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOwnedOutcome {
    NoState,
    AlreadyExited,
    Terminated,
}

fn paths_match(left: &Path, right: &Path) -> bool {
    normalized_path(left) == normalized_path(right)
}

#[derive(Debug, thiserror::Error)]
pub enum OwnedEngineError {
    #[error("unsupported owned-engine state schema {0}")]
    UnsupportedSchema(u16),
    #[error("owned-engine state contains an invalid field")]
    InvalidRecord,
    #[error("owned-engine state cannot be promoted from its current stage")]
    InvalidStage,
    #[error("owned-engine process query failed: {0}")]
    ProcessQuery(#[source] ProcessIdentityError),
    #[error("owned-engine image path does not match the recorded path")]
    ImagePathMismatch,
    #[error("owned-engine creation time does not match; PID may have been reused")]
    CreationTimeMismatch,
    #[error("owned-engine protected storage failed: {0}")]
    Storage(#[source] StorageError),
    #[error("owned-engine process could not be opened for exact-handle termination: {0}")]
    TerminationOpen(#[source] io::Error),
    #[error("owned-engine exact-handle termination failed: {0}")]
    TerminationFailed(#[source] io::Error),
    #[error("owned-engine termination wait failed: {0}")]
    TerminationWait(#[source] io::Error),
    #[error("owned-engine did not exit within the fixed 5 second deadline")]
    TerminationTimeout,
    #[error("owned-engine termination wait returned unexpected status {0}")]
    UnexpectedWait(u32),
    #[error("owned-engine adapter cleanup failed: {0}")]
    AdapterCleanup(#[source] AdapterError),
    #[error("owned-engine adapter identity query failed: {0}")]
    AdapterIdentity(#[source] AdapterError),
    #[error("owned-engine running state has no live controlled adapter")]
    AdapterMissing,
    #[error("owned-engine live adapter does not match the persisted instance identity")]
    AdapterIdentityMismatch,
    #[error("owned-engine adapter instance existed before this lifecycle transaction")]
    PreexistingAdapterInstance,
    #[error("owned-engine upstream identity verification failed: {0}")]
    UpstreamIdentity(#[source] UpstreamIdentityError),
    #[error("owned-engine controller identity verification failed: {0}")]
    ControllerIdentity(#[source] UpstreamIdentityError),
    #[error("owned-engine installation integrity failed during recovery: {0}")]
    EngineIntegrity(#[source] IntegrityError),
    #[error("owned-engine installation no longer matches the persisted record")]
    EngineRecordMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Caller {
        Caller {
            principal_id: "S-1-5-21-test".into(),
            session_id: 7,
            is_admin: false,
        }
    }

    fn current_engine() -> ValidatedEngine {
        ValidatedEngine::for_test(std::env::current_exe().unwrap())
    }

    fn capture_current(engine: &ValidatedEngine, pid: u32) -> OwnedEngineRecord {
        capture_pending_owned_engine(
            engine,
            pid,
            &owner(),
            PendingRuntimeAssets {
                verified_upstream: Some(&VerifiedUpstream::for_test()),
                remote_upstream: false,
                upstream_host: "127.0.0.1",
                upstream_port: 7078,
                upstream_protocol: UpstreamProtocol::Socks5,
                controller: "127.0.0.1:25412",
                preexisting_wintun_instances: &[],
            },
        )
        .unwrap()
    }

    #[test]
    fn captures_and_reverifies_exact_current_process_identity() {
        let record = capture_current(&current_engine(), std::process::id());
        assert_eq!(record.pid, std::process::id());
        assert_eq!(record.owner_session_id, 7);
        assert_eq!(record.stage, OwnedEngineStage::Pending);
        assert!(verify_owned_engine(&record).is_ok());
    }

    #[test]
    fn schema_v3_requires_adapter_provenance_and_exact_runtime_assets() {
        let pending = capture_current(&current_engine(), std::process::id());
        assert!(pending.validate().is_ok());

        let mut legacy = pending.clone();
        legacy.schema_version = 2;
        assert!(matches!(
            legacy.validate(),
            Err(OwnedEngineError::UnsupportedSchema(2))
        ));

        let mut incomplete_running = pending.clone();
        incomplete_running.stage = OwnedEngineStage::Running;
        assert!(matches!(
            incomplete_running.validate(),
            Err(OwnedEngineError::InvalidRecord)
        ));

        let mut pending_with_adapter = pending.clone();
        pending_with_adapter.adapter_instance_id =
            Some("SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}".into());
        assert!(matches!(
            pending_with_adapter.validate(),
            Err(OwnedEngineError::InvalidRecord)
        ));

        let mut running = pending;
        running.stage = OwnedEngineStage::Running;
        running.adapter_instance_id =
            Some("SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}".into());
        assert!(running.validate().is_ok());

        running.preexisting_wintun_instances =
            vec!["SWD\\WINTUN\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}".into()];
        assert!(running.validate().is_ok());
    }

    #[test]
    fn schema_v3_accepts_bounded_cross_generation_recovery_records() {
        let mut record = capture_current(&current_engine(), std::process::id());
        record.product_version = "0.2.4".into();
        assert!(record.validate().is_ok());

        for invalid in ["", "0.2", "0.2.4.1", "0.2.x", "000000.2.4"] {
            record.product_version = invalid.into();
            assert!(matches!(
                record.validate(),
                Err(OwnedEngineError::InvalidRecord)
            ));
        }
    }

    #[test]
    fn malformed_or_non_ascii_adapter_identity_is_rejected_without_panicking() {
        let mut running = capture_current(&current_engine(), std::process::id());
        running.stage = OwnedEngineStage::Running;
        for instance in [
            "SWD\\Wintun\\{01f3d263-6584-8B43-A64C-C95FFF23DA26}",
            "SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA2é}",
            "SWD\\Other\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}",
        ] {
            running.adapter_instance_id = Some(instance.into());
            assert!(matches!(
                running.validate(),
                Err(OwnedEngineError::InvalidRecord)
            ));
        }
    }

    #[test]
    fn pending_cleanup_rejects_an_instance_from_the_pre_spawn_inventory() {
        let instance = "SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}";
        let mut pending = capture_current(&current_engine(), std::process::id());
        pending.preexisting_wintun_instances = vec![instance.to_ascii_uppercase()];
        assert!(pending.validate().is_ok());
        assert!(matches!(
            verify_pending_adapter_provenance(&pending, instance),
            Err(OwnedEngineError::PreexistingAdapterInstance)
        ));
    }

    #[test]
    fn startup_adapter_classification_requires_recorded_provenance() {
        let exact = "SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}";
        let other = "SWD\\Wintun\\{11F3D263-6584-8B43-A64C-C95FFF23DA26}";
        let mut pending = capture_current(&current_engine(), std::process::id());
        assert_eq!(
            classify_adapter_fact(&pending, exact),
            AdapterFact::ExactOwned
        );
        pending.preexisting_wintun_instances = vec![exact.to_ascii_uppercase()];
        assert_eq!(
            classify_adapter_fact(&pending, exact),
            AdapterFact::Preexisting
        );

        let mut running = capture_current(&current_engine(), std::process::id());
        running.stage = OwnedEngineStage::Running;
        running.adapter_instance_id = Some(exact.into());
        assert_eq!(
            classify_adapter_fact(&running, exact),
            AdapterFact::ExactOwned
        );
        running.preexisting_wintun_instances = vec![exact.to_ascii_uppercase()];
        assert_eq!(
            classify_adapter_fact(&running, exact),
            AdapterFact::ExactOwned
        );
        assert_eq!(classify_adapter_fact(&running, other), AdapterFact::Other);
    }

    #[test]
    fn rejects_pid_reuse_path_change_and_untrusted_serialized_fields() {
        let record = capture_current(&current_engine(), std::process::id());

        let mut reused = record.clone();
        reused.creation_time += 1;
        assert!(matches!(
            verify_owned_engine(&reused),
            Err(OwnedEngineError::CreationTimeMismatch)
        ));

        let mut replaced = record.clone();
        replaced.image_path = PathBuf::from(r"C:\evil\mihomo.exe");
        assert!(matches!(
            verify_owned_engine(&replaced),
            Err(OwnedEngineError::ImagePathMismatch)
        ));

        let mut invalid = record;
        invalid.engine_sha256 = "A".repeat(64);
        assert!(matches!(
            verify_owned_engine(&invalid),
            Err(OwnedEngineError::InvalidRecord)
        ));
    }

    #[test]
    fn strict_state_json_rejects_unknown_fields() {
        let record = capture_current(&current_engine(), std::process::id());
        let raw = serde_json::to_string(&record).unwrap();
        let raw = raw.replacen('{', r#"{"command":"taskkill","#, 1);
        assert!(serde_json::from_str::<OwnedEngineRecord>(&raw).is_err());
    }

    fn sleeping_child() -> (std::process::Child, OwnedEngineRecord) {
        use std::os::windows::process::CommandExt as _;

        let child = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .creation_flags(0x0800_0000)
            .spawn()
            .unwrap();
        let engine = ValidatedEngine::for_test(
            query_process_identity(child.id())
                .unwrap()
                .image_path()
                .to_path_buf(),
        );
        let record = capture_current(&engine, child.id());
        (child, record)
    }

    #[test]
    fn terminates_only_the_identity_verified_on_the_same_handle() {
        let (mut child, record) = sleeping_child();
        assert_eq!(
            terminate_owned_record(&record).unwrap(),
            StopOwnedOutcome::Terminated
        );
        assert!(child.try_wait().unwrap().is_some());

        let (mut unrelated, mut mismatched) = sleeping_child();
        mismatched.creation_time += 1;
        assert!(matches!(
            terminate_owned_record(&mismatched),
            Err(OwnedEngineError::CreationTimeMismatch)
        ));
        assert!(unrelated.try_wait().unwrap().is_none());
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[test]
    fn already_exited_but_retained_process_object_is_safe_to_recover() {
        let (mut child, record) = sleeping_child();
        child.kill().unwrap();
        child.wait().unwrap();

        assert_eq!(
            terminate_owned_record(&record).unwrap(),
            StopOwnedOutcome::AlreadyExited
        );
    }

    #[test]
    fn reconcile_observes_exited_retained_objects_before_identity_query() {
        let (mut child, record) = sleeping_child();
        assert_eq!(
            inspect_owned_record(&record).unwrap(),
            OwnedRecordState::Running
        );

        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            inspect_owned_record(&record).unwrap(),
            OwnedRecordState::Exited
        );
    }

    #[test]
    fn reconcile_pid_reuse_is_stale_and_does_not_terminate_the_live_process() {
        let (mut child, mut record) = sleeping_child();
        record.creation_time += 1;

        assert_eq!(
            inspect_owned_record(&record).unwrap(),
            OwnedRecordState::Exited
        );
        assert!(child.try_wait().unwrap().is_none());

        child.kill().unwrap();
        child.wait().unwrap();
    }
}
