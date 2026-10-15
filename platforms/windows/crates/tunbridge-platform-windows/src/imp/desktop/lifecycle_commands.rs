use crate::{
    profile_store_v2_windows::ProfileCoordinatorV2Windows, profile_store_windows::CredentialVault,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tunbridge_core::profile_v2::StoredUpstreamV2;
use tunbridge_service::{
    lease::{LEASE_RENEW_AFTER_TICKS, LEASE_TTL_TICKS},
    protocol::{ErrorCode, ResponseData, StartProfileV3, StartUpstreamV3},
    state::Phase,
    windows::{
        listener_owner_snapshot, resolve_unique_loopback_listener_pid, ClientError, ServiceClient,
        ShutdownToken, UpstreamIdentityError,
    },
};
use zeroize::Zeroize;

const LOOPBACK_HOST: &str = "127.0.0.1";
const LEASE_TICK: Duration = Duration::from_secs(1);
const LIFECYCLE_DIAGNOSTIC_BUILD: &str = "local-upstream-diag-2";
const LIFECYCLE_LOG_MAX_BYTES: u64 = 256 * 1024;

fn lifecycle_diagnostic_log(event: &str) {
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let directory = PathBuf::from(local_app_data).join("TunBridge").join("logs");
    if fs::create_dir_all(&directory).is_err() {
        return;
    }
    let path = directory.join("lifecycle.log");
    let truncate = path
        .metadata()
        .map(|metadata| metadata.len() >= LIFECYCLE_LOG_MAX_BYTES)
        .unwrap_or(false);
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    let Ok(mut file) = options.open(path) else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let _ = writeln!(
        file,
        "ts={timestamp} version={} build={LIFECYCLE_DIAGNOSTIC_BUILD} desktop_pid={} {event}",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );
}

fn log_listener_snapshot(port: u16) {
    match listener_owner_snapshot(port) {
        Ok(snapshot) => lifecycle_diagnostic_log(&format!(
            "listener_snapshot port={port} ipv4_loopback={} ipv4_unspecified={} ipv6_loopback={} ipv6_unspecified={}",
            snapshot.ipv4_loopback,
            snapshot.ipv4_unspecified,
            snapshot.ipv6_loopback,
            snapshot.ipv6_unspecified
        )),
        Err(error) => lifecycle_diagnostic_log(&format!(
            "listener_snapshot port={port} error={}",
            error.diagnostic_code()
        )),
    }
}

fn log_upstream_identity_error(stage: &str, port: u16, error: &UpstreamIdentityError) {
    lifecycle_diagnostic_log(&format!(
        "{stage}=error port={port} code={}",
        error.diagnostic_code()
    ));
    log_listener_snapshot(port);
}

fn log_client_error(stage: &str, error: &ClientError) {
    let code = match error {
        ClientError::Windows(_) => "windows",
        ClientError::Protocol(_) => "protocol",
        ClientError::Pipe(_) => "pipe",
        ClientError::ProtocolMismatch(_) => "protocol_mismatch",
        ClientError::MissingStatusCapability => "missing_status_capability",
        ClientError::MissingCapability(_) => "missing_capability",
        ClientError::ResponseMismatch => "response_mismatch",
        ClientError::ServerIdentity(_) => "server_identity",
        ClientError::Service { .. } => "service_rejected",
    };
    match error {
        ClientError::Service {
            code: service_code,
            message,
            retryable,
            ..
        } => lifecycle_diagnostic_log(&format!(
            "{stage}=error code={code} service_code={service_code:?} service_detail={} retryable={retryable}",
            fixed_service_detail(message)
        )),
        _ => lifecycle_diagnostic_log(&format!("{stage}=error code={code}")),
    }
}

fn fixed_service_detail(message: &str) -> &'static str {
    match message {
        "the upstream profile is invalid" => "upstream_profile_invalid",
        "the upstream listener endpoint has no matching process owner" => {
            "upstream_listener_mismatch"
        }
        "the upstream listener endpoint has multiple process owners" => {
            "upstream_listener_ambiguous"
        }
        "the upstream listener process changed during validation" => "upstream_listener_changed",
        "the Windows TCP listener table could not be queried" => "tcp_table_query_failed",
        "the Windows TCP listener table changed during validation" => "tcp_table_unstable",
        "the Windows TCP listener table returned invalid data" => "tcp_table_malformed",
        "the upstream listener process could not be inspected" => "upstream_process_query_failed",
        "the upstream listener process identity changed during validation" => {
            "upstream_process_identity_changed"
        }
        _ => "other",
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartSavedProfileInput {
    pub profile_id: String,
    pub expected_store_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleCommandErrorCode {
    Busy,
    ProfileUnavailable,
    UpstreamIdentityUnavailable,
    ServiceUnavailable,
    ServiceIdentityFailed,
    ServiceProtocolError,
    ServiceRejected,
    LeaseUnavailable,
    WorkerFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleCommandError {
    pub code: LifecycleCommandErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_code: Option<ErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_message: Option<String>,
}

impl From<LifecycleCommandErrorCode> for LifecycleCommandError {
    fn from(code: LifecycleCommandErrorCode) -> Self {
        let (safe_message, retryable) = match code {
            LifecycleCommandErrorCode::Busy => ("Another desktop operation is active.", true),
            LifecycleCommandErrorCode::ProfileUnavailable => (
                "The selected saved profile is unavailable or changed.",
                true,
            ),
            LifecycleCommandErrorCode::UpstreamIdentityUnavailable => (
                "The local proxy listener identity could not be verified.",
                true,
            ),
            LifecycleCommandErrorCode::ServiceUnavailable => {
                ("The TunBridge service is unavailable.", true)
            }
            LifecycleCommandErrorCode::ServiceIdentityFailed => (
                "The TunBridge service identity could not be verified.",
                false,
            ),
            LifecycleCommandErrorCode::ServiceProtocolError => {
                ("The TunBridge service returned an invalid response.", false)
            }
            LifecycleCommandErrorCode::ServiceRejected => (
                "The TunBridge service rejected the lifecycle request.",
                false,
            ),
            LifecycleCommandErrorCode::LeaseUnavailable => {
                ("The App lease could not be established safely.", true)
            }
            LifecycleCommandErrorCode::WorkerFailed => {
                ("The App lease worker did not stop safely.", false)
            }
        };
        Self {
            code,
            safe_message,
            retryable,
            service_code: None,
            service_message: None,
        }
    }
}

pub fn start_saved_profile(
    input: StartSavedProfileInput,
    leases: &LeaseManager,
) -> Result<(), LifecycleCommandError> {
    lifecycle_diagnostic_log("start_enter");
    let files = ProfileCoordinatorV2Windows::prepare_production().map_err(|_| {
        lifecycle_diagnostic_log("profile_store_prepare=error");
        LifecycleCommandErrorCode::ProfileUnavailable
    })?;
    let saved = files
        .load_saved(
            &CredentialVault,
            &input.profile_id,
            input.expected_store_revision,
        )
        .map_err(|_| {
            lifecycle_diagnostic_log("profile_load=error");
            LifecycleCommandErrorCode::ProfileUnavailable
        })?;
    let (upstream, local_verification) = match saved.profile.upstream {
        StoredUpstreamV2::LocalListener { port, protocol, .. } => {
            lifecycle_diagnostic_log(&format!("profile_loaded kind=local port={port}"));
            log_listener_snapshot(port);
            let expected_process_id = resolve_unique_loopback_listener_pid(LOOPBACK_HOST, port)
                .map_err(|error| {
                    log_upstream_identity_error("preflight_first", port, &error);
                    LifecycleCommandErrorCode::UpstreamIdentityUnavailable
                })?;
            lifecycle_diagnostic_log(&format!(
                "preflight_first=ok port={port} owner_pid={expected_process_id}"
            ));
            (
                StartUpstreamV3::LocalListener {
                    port,
                    protocol,
                    credentials: saved.secret_material,
                    expected_process_id,
                },
                Some((expected_process_id, port)),
            )
        }
        StoredUpstreamV2::RemoteServer {
            endpoint,
            protocol_config,
            ..
        } => {
            lifecycle_diagnostic_log("profile_loaded kind=remote");
            (
                StartUpstreamV3::RemoteServer {
                    endpoint,
                    protocol_config,
                    secret_material: saved.secret_material,
                },
                None,
            )
        }
    };
    let profile = StartProfileV3 {
        upstream,
        traffic_bypass_domains: Vec::new(),
        traffic_bypass_cidrs: Vec::new(),
        // For local profiles the privileged service derives and adds the
        // verified listener process name. The desktop must not need permission
        // to inspect a higher-integrity proxy process before contacting it.
        traffic_bypass_process_names: Vec::new(),
    };
    if let Some((expected_process_id, port)) = local_verification {
        let current_process_id = resolve_unique_loopback_listener_pid(LOOPBACK_HOST, port)
            .map_err(|error| {
                log_upstream_identity_error("preflight_second", port, &error);
                LifecycleCommandErrorCode::UpstreamIdentityUnavailable
            })?;
        if current_process_id != expected_process_id {
            lifecycle_diagnostic_log(&format!(
                "preflight_second=error port={port} code=owner_changed first_pid={expected_process_id} second_pid={current_process_id}"
            ));
            return Err(LifecycleCommandErrorCode::UpstreamIdentityUnavailable.into());
        }
        lifecycle_diagnostic_log(&format!(
            "preflight_second=ok port={port} owner_pid={current_process_id}"
        ));
    }

    let mut client = ServiceClient::connect().map_err(|error| {
        log_client_error("service_connect", &error);
        map_client_error(error)
    })?;
    lifecycle_diagnostic_log("service_connect=ok");
    let mut recovery_attempted = false;
    if status_requires_recovery(client.status().map_err(|error| {
        log_client_error("service_status", &error);
        map_client_error(error)
    })?) {
        // Match the proven manual Recover -> Start boundary: recovery and
        // start use separate authenticated service sessions.
        drop(client);
        recover_before_start(leases)?;
        client = ServiceClient::connect().map_err(map_client_error)?;
        recovery_attempted = true;
    }
    loop {
        match client.start(profile.clone()) {
            Ok(response) => expect_status(response, Phase::Running, true)?,
            Err(ClientError::Service {
                code: ErrorCode::AlreadyRunning,
                ..
            }) => {
                // Starting the engine and establishing the App lease are separate
                // service operations. If the App is interrupted between them, a
                // retry from the same authenticated owner must be able to resume
                // lease management without restarting the privileged engine.
                expect_status(
                    client.status().map_err(map_client_error)?,
                    Phase::Running,
                    true,
                )?;
            }
            Err(ClientError::Service {
                code: ErrorCode::RecoveryRequired,
                ..
            }) if !recovery_attempted => {
                // Keep exact recovery as the safety boundary, but fold it into
                // the user's Start request so a fault does not require a
                // separate manual Recover action before the switch works.
                drop(client);
                recover_before_start(leases)?;
                client = ServiceClient::connect().map_err(map_client_error)?;
                recovery_attempted = true;
                continue;
            }
            Err(error) => {
                log_client_error("service_start", &error);
                return Err(map_client_error(error));
            }
        }
        break;
    }
    lifecycle_diagnostic_log("service_start=ok");
    let grant = match client.acquire_lease() {
        Ok(grant) => grant,
        Err(_) => {
            lifecycle_diagnostic_log("lease_acquire=error");
            let _ = client.recover();
            return Err(LifecycleCommandErrorCode::LeaseUnavailable.into());
        }
    };
    if let Err(error) = leases.install(grant, input) {
        let _ = client.recover();
        return Err(error);
    }
    lifecycle_diagnostic_log("start_complete");
    Ok(())
}

fn status_requires_recovery(response: ResponseData) -> bool {
    matches!(
        response,
        ResponseData::Status {
            service_phase: Phase::Faulted,
            ..
        }
    )
}

fn recover_before_start(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    expect_status(
        client.recover().map_err(map_client_error)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_without_release()
}

pub fn stop_tunnel(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    expect_status(
        client.stop().map_err(map_client_error)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_and_release()?;
    Ok(())
}

pub fn stop_tunnel_for_exit(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = match ServiceClient::connect() {
        Ok(client) => client,
        Err(ClientError::Windows(_) | ClientError::Pipe(_)) => {
            leases.cancel_without_release()?;
            return Ok(());
        }
        Err(error) => return Err(map_client_error(error)),
    };
    let status = client.status().map_err(map_client_error)?;
    match status {
        ResponseData::Status {
            service_phase: Phase::Stopped,
            engine_running: false,
            ..
        } => {
            leases.cancel_and_release()?;
            Ok(())
        }
        ResponseData::Status {
            service_phase: Phase::Running,
            ..
        } => {
            expect_status(
                client.stop().map_err(map_client_error)?,
                Phase::Stopped,
                false,
            )?;
            leases.cancel_and_release()
        }
        ResponseData::Status {
            service_phase: Phase::Faulted,
            ..
        } => {
            expect_status(
                client.recover().map_err(map_client_error)?,
                Phase::Stopped,
                false,
            )?;
            leases.cancel_without_release()
        }
        _ => Err(LifecycleCommandErrorCode::ServiceRejected.into()),
    }
}

pub fn recover_tunnel(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = ServiceClient::connect().map_err(map_client_error)?;
    expect_status(
        client.recover().map_err(map_client_error)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_without_release()?;
    Ok(())
}

fn expect_status(
    response: ResponseData,
    expected_phase: Phase,
    expected_running: bool,
) -> Result<(), LifecycleCommandError> {
    match response {
        ResponseData::Status {
            service_phase,
            caller_is_owner,
            engine_running,
            ..
        } if service_phase == expected_phase
            && engine_running == expected_running
            && (!expected_running || caller_is_owner) =>
        {
            Ok(())
        }
        _ => Err(LifecycleCommandErrorCode::ServiceProtocolError.into()),
    }
}

fn map_client_error(error: ClientError) -> LifecycleCommandError {
    let code = match error {
        ClientError::ServerIdentity(_) => LifecycleCommandErrorCode::ServiceIdentityFailed,
        ClientError::Protocol(_)
        | ClientError::ProtocolMismatch(_)
        | ClientError::MissingStatusCapability
        | ClientError::MissingCapability(_)
        | ClientError::ResponseMismatch => LifecycleCommandErrorCode::ServiceProtocolError,
        ClientError::Service {
            code,
            message,
            retryable,
        } => {
            let mut error: LifecycleCommandError =
                LifecycleCommandErrorCode::ServiceRejected.into();
            error.retryable = retryable;
            error.service_code = Some(code);
            error.service_message = Some(message);
            return error;
        }
        ClientError::Windows(_) | ClientError::Pipe(_) => {
            LifecycleCommandErrorCode::ServiceUnavailable
        }
    };
    code.into()
}

struct LeaseProofState {
    lease_id: String,
    lease_nonce: String,
    next_seq: u64,
}

impl std::fmt::Debug for LeaseProofState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LeaseProofState([REDACTED])")
    }
}

impl Drop for LeaseProofState {
    fn drop(&mut self) {
        self.lease_id.zeroize();
        self.lease_nonce.zeroize();
    }
}

struct LeaseWorker {
    shutdown: ShutdownToken,
    join: JoinHandle<Option<LeaseProofState>>,
}

type ActiveProfile = Arc<Mutex<Option<StartSavedProfileInput>>>;

#[derive(Default)]
pub struct LeaseManager {
    worker: Mutex<Option<LeaseWorker>>,
    active_profile: ActiveProfile,
}

impl LeaseManager {
    fn install(
        &self,
        response: ResponseData,
        input: StartSavedProfileInput,
    ) -> Result<(), LifecycleCommandError> {
        let proof = parse_grant(response)?;
        self.cancel_without_release()?;
        let shutdown = ShutdownToken::default();
        let worker_shutdown = shutdown.clone();
        let worker_profile = Arc::clone(&self.active_profile);
        let join = thread::spawn(move || run_lease_worker(proof, worker_shutdown, worker_profile));
        *self
            .worker
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)? =
            Some(LeaseWorker { shutdown, join });
        *self
            .active_profile
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)? = Some(input);
        Ok(())
    }

    /// Takes over the lease of a session this App owns but does not renew, for
    /// example after the App was relaunched or the service restarted. The
    /// service never stops the tunnel for a missing App, so this only restores
    /// presence; it never starts or stops anything.
    pub fn ensure_attached(&self) -> Result<(), LifecycleCommandError> {
        if self
            .worker
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)?
            .as_ref()
            .is_some_and(|worker| !worker.join.is_finished())
        {
            return Ok(());
        }
        let Some(proof) = acquire_owned_lease() else {
            return Ok(());
        };
        let _ = self.take_worker()?;
        let shutdown = ShutdownToken::default();
        let worker_shutdown = shutdown.clone();
        let worker_profile = Arc::clone(&self.active_profile);
        let join = thread::spawn(move || run_lease_worker(proof, worker_shutdown, worker_profile));
        *self
            .worker
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)? =
            Some(LeaseWorker { shutdown, join });
        Ok(())
    }

    pub fn active_profile(&self) -> Result<Option<StartSavedProfileInput>, LifecycleCommandError> {
        self.active_profile
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed.into())
            .map(|profile| profile.clone())
    }

    pub fn cancel_and_release(&self) -> Result<(), LifecycleCommandError> {
        if let Some(proof) = self.take_worker()? {
            if let Ok(mut client) = ServiceClient::connect() {
                let _ = client.release_lease(
                    proof.lease_id.clone(),
                    proof.lease_nonce.clone(),
                    proof.next_seq,
                );
            }
        }
        *self
            .active_profile
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)? = None;
        Ok(())
    }

    pub fn cancel_without_release(&self) -> Result<(), LifecycleCommandError> {
        let _ = self.take_worker()?;
        *self
            .active_profile
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)? = None;
        Ok(())
    }

    fn take_worker(&self) -> Result<Option<LeaseProofState>, LifecycleCommandError> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed)?
            .take();
        let Some(worker) = worker else {
            return Ok(None);
        };
        worker.shutdown.cancel();
        worker
            .join
            .join()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed.into())
    }
}

impl Drop for LeaseManager {
    fn drop(&mut self) {
        if let Ok(slot) = self.worker.get_mut() {
            if let Some(worker) = slot.take() {
                worker.shutdown.cancel();
                if let Ok(Some(proof)) = worker.join.join() {
                    if let Ok(mut client) = ServiceClient::connect() {
                        let _ = client.release_lease(
                            proof.lease_id.clone(),
                            proof.lease_nonce.clone(),
                            proof.next_seq,
                        );
                    }
                }
            }
        }
    }
}

fn run_lease_worker(
    mut proof: LeaseProofState,
    shutdown: ShutdownToken,
    active_profile: ActiveProfile,
) -> Option<LeaseProofState> {
    loop {
        for _ in 0..LEASE_RENEW_AFTER_TICKS {
            if shutdown.is_cancelled() {
                return Some(proof);
            }
            thread::sleep(LEASE_TICK);
        }
        if shutdown.is_cancelled() {
            return Some(proof);
        }
        let renewed = ServiceClient::connect().and_then(|mut client| {
            client.renew_lease(
                proof.lease_id.clone(),
                proof.lease_nonce.clone(),
                proof.next_seq,
            )
        });
        match renewed {
            Ok(response) => match parse_grant(response) {
                Ok(next) => proof = next,
                Err(_) => return None,
            },
            Err(ClientError::Service { code, .. }) if code.ends_lease() => {
                // The proof is no longer current (a late renewal raced a
                // takeover, or the service restarted). While the session is
                // still ours, take the lease over; otherwise the session ended,
                // so stop renewing and release the edit lock on the profile.
                if let Some(next) = acquire_owned_lease() {
                    proof = next;
                    continue;
                }
                if let Ok(mut profile) = active_profile.lock() {
                    *profile = None;
                }
                return None;
            }
            Err(_) => {
                // A transport failure is not a release or crash fact. Retain
                // the proof and retry only on the next fixed cadence.
            }
        }
    }
}

/// A fresh lease for the running session when this App owns it.
fn acquire_owned_lease() -> Option<LeaseProofState> {
    let mut client = ServiceClient::connect().ok()?;
    match client.status().ok()? {
        ResponseData::Status {
            service_phase: Phase::Running,
            caller_is_owner: true,
            ..
        } => {}
        _ => return None,
    }
    client
        .acquire_lease()
        .ok()
        .and_then(|response| parse_grant(response).ok())
}

fn parse_grant(response: ResponseData) -> Result<LeaseProofState, LifecycleCommandError> {
    match response {
        ResponseData::Lease {
            lease_id,
            lease_nonce,
            next_seq,
            ttl_ticks,
            renew_after_ticks,
        } if valid_lower_hex_256(&lease_id)
            && valid_lower_hex_256(&lease_nonce)
            && next_seq != 0
            && ttl_ticks == LEASE_TTL_TICKS
            && renew_after_ticks == LEASE_RENEW_AFTER_TICKS =>
        {
            Ok(LeaseProofState {
                lease_id,
                lease_nonce,
                next_seq,
            })
        }
        _ => Err(LifecycleCommandErrorCode::ServiceProtocolError.into()),
    }
}

fn valid_lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> ResponseData {
        ResponseData::Lease {
            lease_id: "ab".repeat(32),
            lease_nonce: "cd".repeat(32),
            next_seq: 1,
            ttl_ticks: LEASE_TTL_TICKS,
            renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
        }
    }

    #[test]
    fn start_schema_rejects_client_identity_and_path_fields() {
        let valid = serde_json::json!({
            "profileId": "00112233445566778899aabbccddeeff",
            "expectedStoreRevision": 1
        });
        serde_json::from_value::<StartSavedProfileInput>(valid.clone()).unwrap();
        for (field, value) in [
            ("pid", serde_json::json!(42)),
            ("path", serde_json::json!("C:\\evil.exe")),
            ("host", serde_json::json!("192.0.2.1")),
            ("command", serde_json::json!("cmd")),
        ] {
            let mut forged = valid.clone();
            forged[field] = value;
            assert!(serde_json::from_value::<StartSavedProfileInput>(forged).is_err());
        }
    }

    #[test]
    fn lease_grant_schema_and_constants_are_strict() {
        let proof = parse_grant(grant()).unwrap();
        assert_eq!(proof.next_seq, 1);
        let mut bad_ttl = grant();
        if let ResponseData::Lease { ttl_ticks, .. } = &mut bad_ttl {
            *ttl_ticks += 1;
        }
        assert!(parse_grant(bad_ttl).is_err());
        let mut uppercase = grant();
        if let ResponseData::Lease { lease_id, .. } = &mut uppercase {
            *lease_id = "AB".repeat(32);
        }
        assert!(parse_grant(uppercase).is_err());
    }

    #[test]
    fn only_faulted_status_requires_recovery_before_start() {
        let status = |service_phase| ResponseData::Status {
            service_phase,
            engine_running: false,
            caller_is_owner: false,
            service_version: "test".into(),
            stop_reason: None,
            degraded_reason: None,
        };

        assert!(status_requires_recovery(status(Phase::Faulted)));
        assert!(!status_requires_recovery(status(Phase::Stopped)));
        assert!(!status_requires_recovery(status(Phase::Running)));
    }

    #[test]
    fn resolves_current_process_loopback_listener_without_process_query() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            resolve_unique_loopback_listener_pid(LOOPBACK_HOST, port).unwrap(),
            std::process::id()
        );
    }

    #[test]
    fn resolves_one_ipv4_wildcard_listener_reachable_through_loopback() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            resolve_unique_loopback_listener_pid(LOOPBACK_HOST, port).unwrap(),
            std::process::id()
        );
        let snapshot = listener_owner_snapshot(port).unwrap();
        assert_eq!(snapshot.ipv4_loopback, 0);
        assert_eq!(snapshot.ipv4_unspecified, 1);
    }

    #[test]
    #[ignore = "requires a user-confirmed local proxy at 127.0.0.1:7078"]
    fn resolves_user_confirmed_local_proxy_7078() {
        let pid = resolve_unique_loopback_listener_pid(LOOPBACK_HOST, 7078).unwrap();
        assert_ne!(pid, 0);
        assert_eq!(
            resolve_unique_loopback_listener_pid(LOOPBACK_HOST, 7078).unwrap(),
            pid
        );
    }

    #[test]
    fn managed_lease_worker_cancels_and_joins_before_first_renewal() {
        let manager = LeaseManager::default();
        let input = StartSavedProfileInput {
            profile_id: "00112233445566778899aabbccddeeff".into(),
            expected_store_revision: 7,
        };
        manager.install(grant(), input.clone()).unwrap();
        assert_eq!(manager.active_profile().unwrap(), Some(input));
        let started = std::time::Instant::now();
        manager.cancel_without_release().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(manager.worker.lock().unwrap().is_none());
        assert_eq!(manager.active_profile().unwrap(), None);
    }

    #[test]
    fn lifecycle_errors_are_fixed_and_redacted() {
        for code in [
            LifecycleCommandErrorCode::Busy,
            LifecycleCommandErrorCode::ProfileUnavailable,
            LifecycleCommandErrorCode::UpstreamIdentityUnavailable,
            LifecycleCommandErrorCode::ServiceUnavailable,
            LifecycleCommandErrorCode::ServiceIdentityFailed,
            LifecycleCommandErrorCode::ServiceProtocolError,
            LifecycleCommandErrorCode::ServiceRejected,
            LifecycleCommandErrorCode::LeaseUnavailable,
            LifecycleCommandErrorCode::WorkerFailed,
        ] {
            let json = serde_json::to_string(&LifecycleCommandError::from(code)).unwrap();
            assert!(!json.contains("PID"));
            assert!(!json.contains("Program Files"));
            assert!(!json.contains("pipe"));
        }
    }
}
