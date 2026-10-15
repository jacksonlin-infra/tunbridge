#[cfg(target_os = "macos")]
use crate::credential_store::KeychainCredentialVault as PlatformCredentialVault;
#[cfg(target_os = "linux")]
use crate::credential_store::SecretServiceCredentialVault as PlatformCredentialVault;
use crate::{
    profile_store_unix::ProfileCoordinator as LegacyProfileCoordinator,
    profile_store_v2_unix::ProfileCoordinatorV2,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tunbridge_core::profile_v2::StoredUpstreamV2;
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ProcessDiscovery};
#[cfg(target_os = "linux")]
use tunbridge_platform_linux::LinuxProcessDiscovery as PlatformProcessDiscovery;
#[cfg(target_os = "macos")]
use tunbridge_platform_macos::MacosProcessDiscovery as PlatformProcessDiscovery;
use tunbridge_service::{
    lease::{LEASE_RENEW_AFTER_TICKS, LEASE_TTL_TICKS},
    protocol::{Command, ErrorCode, ResponseData, StartProfileV3, StartUpstreamV3},
    state::Phase,
};
#[cfg(target_os = "linux")]
use tunbridge_service_linux::{LinuxClientError, LinuxServiceClient};
#[cfg(target_os = "macos")]
use tunbridge_service_macos::{
    client_session::{MacosClientError, MacosServiceClient},
    xpc_client::{NativeXpcClientBackend, MAX_TRANSACTION_TIMEOUT},
    MacosXpcTransport,
};
use zeroize::Zeroize;

const LEASE_TICK: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(40);
#[cfg(target_os = "macos")]
const LIFECYCLE_TIMEOUT: Duration = MAX_TRANSACTION_TIMEOUT;

#[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
fn lifecycle_debug_log(message: &str) {
    use std::{fs::OpenOptions, io::Write};
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tunbridge-lifecycle-m6f.log")
    {
        let _ = writeln!(file, "{message}");
    }
}

#[derive(Debug)]
enum PlatformClientError {
    Adapter(AdapterError),
    Service { code: ErrorCode, retryable: bool },
}

#[cfg(target_os = "linux")]
struct PlatformServiceClient(LinuxServiceClient);

#[cfg(target_os = "macos")]
struct PlatformServiceClient(MacosServiceClient<MacosXpcTransport<NativeXpcClientBackend>>);

impl PlatformServiceClient {
    fn connect_system() -> Result<Self, AdapterError> {
        #[cfg(target_os = "linux")]
        {
            LinuxServiceClient::connect_system().map(Self)
        }
        #[cfg(target_os = "macos")]
        {
            MacosServiceClient::connect_system().map(Self)
        }
    }

    fn send_detailed(
        &mut self,
        command: Command,
        timeout: Duration,
    ) -> Result<ResponseData, PlatformClientError> {
        #[cfg(target_os = "linux")]
        {
            self.0
                .send_detailed(command, timeout)
                .map_err(|error| match error {
                    LinuxClientError::Adapter(error) => PlatformClientError::Adapter(error),
                    LinuxClientError::Service {
                        code, retryable, ..
                    } => PlatformClientError::Service { code, retryable },
                })
        }
        #[cfg(target_os = "macos")]
        {
            self.0.send(command, timeout).map_err(|error| match error {
                MacosClientError::Adapter(error) => PlatformClientError::Adapter(error),
                MacosClientError::Service { code, retryable } => {
                    PlatformClientError::Service { code, retryable }
                }
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
        }
    }
}

pub fn start_saved_profile(
    input: StartSavedProfileInput,
    leases: &LeaseManager,
) -> Result<(), LifecycleCommandError> {
    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
    lifecycle_debug_log("start-enter");
    let legacy = LegacyProfileCoordinator::prepare_production()
        .map_err(|_| LifecycleCommandErrorCode::ProfileUnavailable)?;
    let files = ProfileCoordinatorV2::prepare_production()
        .map_err(|_| LifecycleCommandErrorCode::ProfileUnavailable)?;
    let saved = files
        .load_saved(
            &legacy,
            &PlatformCredentialVault,
            &PlatformCredentialVault,
            &input.profile_id,
            input.expected_store_revision,
        )
        .map_err(|_| LifecycleCommandErrorCode::ProfileUnavailable)?;
    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
    lifecycle_debug_log(match &saved.profile.upstream {
        StoredUpstreamV2::LocalListener { .. } => "profile-loaded kind=local_listener",
        StoredUpstreamV2::RemoteServer { .. } => "profile-loaded kind=remote_server",
    });
    let (upstream, traffic_bypass_process_names) = match saved.profile.upstream {
        StoredUpstreamV2::LocalListener { port, protocol, .. } => {
            let listener = resolve_unique_listener(port)?;
            #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
            lifecycle_debug_log(&format!(
                "listener-resolved pid={} name={:?}",
                listener.0, listener.1
            ));
            (
                StartUpstreamV3::LocalListener {
                    port,
                    protocol,
                    credentials: saved.secret_material,
                    expected_process_id: listener.0,
                },
                listener.1.into_iter().collect(),
            )
        }
        StoredUpstreamV2::RemoteServer {
            endpoint,
            protocol_config,
            ..
        } => (
            StartUpstreamV3::RemoteServer {
                endpoint,
                protocol_config,
                secret_material: saved.secret_material,
            },
            Vec::new(),
        ),
    };
    // The service identifies the verified listener itself: Linux through a
    // route-level transport escape, macOS by its exact executable path.
    // Passing the discovered name would let any program with the same name
    // go direct (and on Linux re-enable racy per-flow procfs matching).
    let _ = &traffic_bypass_process_names;
    let traffic_bypass_process_names = Vec::new();
    let profile = StartProfileV3 {
        upstream,
        traffic_bypass_domains: Vec::new(),
        traffic_bypass_cidrs: Vec::new(),
        traffic_bypass_process_names,
    };
    let mut client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
    let mut recovery_attempted = false;
    if status_requires_recovery(
        client
            .send_detailed(Command::Status, REQUEST_TIMEOUT)
            .map_err(map_client)?,
    ) {
        drop(client);
        recover_before_start(leases)?;
        client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
        recovery_attempted = true;
    }
    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
    lifecycle_debug_log("service-connected");
    loop {
        let start_result = client.send_detailed(
            Command::Start {
                profile: profile.clone(),
            },
            LIFECYCLE_TIMEOUT,
        );
        #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
        lifecycle_debug_log(&format!("start-response={start_result:?}"));
        match start_result {
            Ok(response) => expect_status(response, Phase::Running, true)?,
            Err(PlatformClientError::Service {
                code: ErrorCode::AlreadyRunning,
                ..
            }) => expect_status(
                {
                    let status_result = client.send_detailed(Command::Status, REQUEST_TIMEOUT);
                    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
                    lifecycle_debug_log(&format!("already-running-status={status_result:?}"));
                    status_result.map_err(map_client)?
                },
                Phase::Running,
                true,
            )?,
            Err(PlatformClientError::Service {
                code: ErrorCode::RecoveryRequired,
                ..
            }) if !recovery_attempted => {
                drop(client);
                recover_before_start(leases)?;
                client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
                recovery_attempted = true;
                continue;
            }
            Err(error) => return Err(map_client(error)),
        }
        break;
    }
    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
    lifecycle_debug_log("start-status-accepted");
    let grant = client
        .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
        .map_err(|_error| {
            #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
            lifecycle_debug_log(&format!("lease-response={_error:?}"));
            LifecycleCommandError::from(LifecycleCommandErrorCode::LeaseUnavailable)
        })?;
    #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
    lifecycle_debug_log("lease-response=ok");
    if let Err(error) = leases.install(grant, input) {
        let _ = client.send_detailed(Command::Recover, LIFECYCLE_TIMEOUT);
        return Err(error);
    }
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
    let mut client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
    expect_status(
        client
            .send_detailed(Command::Recover, LIFECYCLE_TIMEOUT)
            .map_err(map_client)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_without_release()
}

pub fn stop_tunnel(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
    expect_status(
        client
            .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
            .map_err(map_client)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_and_release()
}

pub fn recover_tunnel(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let mut client = PlatformServiceClient::connect_system().map_err(map_adapter)?;
    expect_status(
        client
            .send_detailed(Command::Recover, LIFECYCLE_TIMEOUT)
            .map_err(map_client)?,
        Phase::Stopped,
        false,
    )?;
    leases.cancel_without_release()
}

pub fn stop_tunnel_for_exit(leases: &LeaseManager) -> Result<(), LifecycleCommandError> {
    let Ok(mut client) = PlatformServiceClient::connect_system() else {
        return leases.cancel_without_release();
    };
    match client
        .send_detailed(Command::Status, REQUEST_TIMEOUT)
        .map_err(map_client)?
    {
        ResponseData::Status {
            service_phase: Phase::Stopped,
            engine_running: false,
            ..
        } => leases.cancel_and_release(),
        ResponseData::Status {
            service_phase: Phase::Running,
            ..
        } => {
            expect_status(
                client
                    .send_detailed(Command::Stop, LIFECYCLE_TIMEOUT)
                    .map_err(map_client)?,
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
                client
                    .send_detailed(Command::Recover, LIFECYCLE_TIMEOUT)
                    .map_err(map_client)?,
                Phase::Stopped,
                false,
            )?;
            leases.cancel_without_release()
        }
        _ => Err(LifecycleCommandErrorCode::ServiceRejected.into()),
    }
}

fn resolve_unique_listener(port: u16) -> Result<(u32, Option<String>), LifecycleCommandError> {
    let listeners = PlatformProcessDiscovery
        .loopback_listeners()
        .map_err(|_| LifecycleCommandErrorCode::UpstreamIdentityUnavailable)?;
    let mut matches = listeners
        .into_iter()
        .filter(|listener| listener.port == port)
        .filter_map(|listener| listener.process_id.map(|pid| (pid, listener.process_name)));
    let first = matches
        .next()
        .ok_or(LifecycleCommandErrorCode::UpstreamIdentityUnavailable)?;
    if matches.any(|candidate| candidate.0 != first.0) {
        return Err(LifecycleCommandErrorCode::UpstreamIdentityUnavailable.into());
    }
    Ok(first)
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

fn map_adapter(error: tunbridge_desktop_contract::adapter::AdapterError) -> LifecycleCommandError {
    match error.code {
        AdapterErrorCode::IdentityRejected => {
            LifecycleCommandErrorCode::ServiceIdentityFailed.into()
        }
        AdapterErrorCode::InvalidData => LifecycleCommandErrorCode::ServiceProtocolError.into(),
        _ => LifecycleCommandErrorCode::ServiceUnavailable.into(),
    }
}

fn map_client(error: PlatformClientError) -> LifecycleCommandError {
    match error {
        PlatformClientError::Adapter(error) => map_adapter(error),
        PlatformClientError::Service { retryable, .. } => {
            let mut error = LifecycleCommandError::from(LifecycleCommandErrorCode::ServiceRejected);
            error.retryable = retryable;
            error
        }
    }
}

struct LeaseProofState {
    lease_id: String,
    lease_nonce: String,
    next_seq: u64,
}

impl Drop for LeaseProofState {
    fn drop(&mut self) {
        self.lease_id.zeroize();
        self.lease_nonce.zeroize();
    }
}

struct LeaseWorker {
    shutdown: Arc<AtomicBool>,
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
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
            if let Ok(mut client) = PlatformServiceClient::connect_system() {
                let _ = client.send_detailed(
                    Command::ReleaseLease {
                        lease_id: proof.lease_id.clone(),
                        lease_nonce: proof.lease_nonce.clone(),
                        lease_seq: proof.next_seq,
                    },
                    REQUEST_TIMEOUT,
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
        worker.shutdown.store(true, Ordering::SeqCst);
        worker
            .join
            .join()
            .map_err(|_| LifecycleCommandErrorCode::WorkerFailed.into())
    }
}

fn run_lease_worker(
    mut proof: LeaseProofState,
    shutdown: Arc<AtomicBool>,
    active_profile: ActiveProfile,
) -> Option<LeaseProofState> {
    // Renewals are user-initiated work even while the window is hidden. Keep
    // App Nap from deferring this worker; release the activity with the worker.
    #[cfg(target_os = "macos")]
    let _activity = crate::macos_lease_activity::LeaseActivity::new();
    loop {
        for _ in 0..LEASE_RENEW_AFTER_TICKS {
            if shutdown.load(Ordering::SeqCst) {
                return Some(proof);
            }
            thread::sleep(LEASE_TICK);
        }
        let _renew_started = std::time::Instant::now();
        let renewed = PlatformServiceClient::connect_system()
            .map_err(PlatformClientError::Adapter)
            .and_then(|mut client| {
                client.send_detailed(
                    Command::RenewLease {
                        lease_id: proof.lease_id.clone(),
                        lease_nonce: proof.lease_nonce.clone(),
                        lease_seq: proof.next_seq,
                    },
                    REQUEST_TIMEOUT,
                )
            });
        #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
        match &renewed {
            Ok(_) => lifecycle_debug_log(&format!(
                "lease-renew=ok elapsed-ms={}",
                _renew_started.elapsed().as_millis()
            )),
            Err(PlatformClientError::Adapter(error)) => lifecycle_debug_log(&format!(
                "lease-renew=adapter-error code={:?} elapsed-ms={}",
                error.code,
                _renew_started.elapsed().as_millis()
            )),
            Err(PlatformClientError::Service { code, .. }) => lifecycle_debug_log(&format!(
                "lease-renew=service-error code={code:?} elapsed-ms={}",
                _renew_started.elapsed().as_millis()
            )),
        }
        match renewed {
            Ok(response) => match parse_grant(response) {
                Ok(next) => proof = next,
                Err(_) => return None,
            },
            Err(PlatformClientError::Service { code, .. }) if code.ends_lease() => {
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
                if shutdown.load(Ordering::SeqCst) {
                    return Some(proof);
                }
            }
        }
    }
}

/// A fresh lease for the running session when this App owns it.
fn acquire_owned_lease() -> Option<LeaseProofState> {
    let mut client = PlatformServiceClient::connect_system().ok()?;
    match client
        .send_detailed(Command::Status, REQUEST_TIMEOUT)
        .ok()?
    {
        ResponseData::Status {
            service_phase: Phase::Running,
            caller_is_owner: true,
            ..
        } => {}
        _ => return None,
    }
    client
        .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
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
        } if valid_hex(&lease_id)
            && valid_hex(&lease_nonce)
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
        _ => Err(LifecycleCommandErrorCode::LeaseUnavailable.into()),
    }
}

fn valid_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    fn status(phase: Phase, caller_is_owner: bool, engine_running: bool) -> ResponseData {
        ResponseData::Status {
            service_phase: phase,
            caller_is_owner,
            engine_running,
            service_version: env!("CARGO_PKG_VERSION").into(),
            stop_reason: None,
            degraded_reason: None,
        }
    }

    #[test]
    fn lifecycle_status_requires_exact_phase_engine_and_owner() {
        assert!(expect_status(status(Phase::Running, true, true), Phase::Running, true).is_ok());
        for response in [
            status(Phase::Running, false, true),
            status(Phase::Running, true, false),
            status(Phase::Stopped, false, true),
        ] {
            assert_eq!(
                expect_status(response, Phase::Running, true)
                    .unwrap_err()
                    .code,
                LifecycleCommandErrorCode::ServiceProtocolError
            );
        }
    }

    #[test]
    fn only_faulted_status_requires_recovery_before_start() {
        assert!(status_requires_recovery(status(
            Phase::Faulted,
            false,
            false
        )));
        assert!(!status_requires_recovery(status(
            Phase::Stopped,
            false,
            false
        )));
        assert!(!status_requires_recovery(status(
            Phase::Running,
            true,
            true
        )));
    }

    #[test]
    fn lease_grant_is_strict_and_bounded() {
        let valid = ResponseData::Lease {
            lease_id: "a".repeat(64),
            lease_nonce: "b".repeat(64),
            next_seq: 1,
            ttl_ticks: LEASE_TTL_TICKS,
            renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
        };
        let parsed = parse_grant(valid).unwrap();
        assert_eq!(parsed.next_seq, 1);

        for invalid in [
            ResponseData::Lease {
                lease_id: "A".repeat(64),
                lease_nonce: "b".repeat(64),
                next_seq: 1,
                ttl_ticks: LEASE_TTL_TICKS,
                renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
            },
            ResponseData::Lease {
                lease_id: "a".repeat(64),
                lease_nonce: "b".repeat(64),
                next_seq: 0,
                ttl_ticks: LEASE_TTL_TICKS,
                renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
            },
            status(Phase::Running, true, true),
        ] {
            assert_eq!(
                parse_grant(invalid).err().unwrap().code,
                LifecycleCommandErrorCode::LeaseUnavailable
            );
        }
    }

    #[test]
    fn platform_and_service_failures_keep_only_stable_error_contract() {
        let identity = map_adapter(AdapterError {
            code: AdapterErrorCode::IdentityRejected,
            safe_message: "fixture detail",
            retryable: true,
        });
        assert_eq!(
            identity.code,
            LifecycleCommandErrorCode::ServiceIdentityFailed
        );
        assert!(!identity.safe_message.contains("fixture"));

        let rejected = map_client(PlatformClientError::Service {
            code: ErrorCode::NotOwner,
            retryable: true,
        });
        assert_eq!(rejected.code, LifecycleCommandErrorCode::ServiceRejected);
        assert!(rejected.retryable);
    }

    #[test]
    fn managed_lease_tracks_and_clears_the_profile_to_resume() {
        let grant = ResponseData::Lease {
            lease_id: "a".repeat(64),
            lease_nonce: "b".repeat(64),
            next_seq: 1,
            ttl_ticks: LEASE_TTL_TICKS,
            renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
        };
        let input = StartSavedProfileInput {
            profile_id: "00112233445566778899aabbccddeeff".into(),
            expected_store_revision: 7,
        };
        let manager = LeaseManager::default();

        manager.install(grant, input.clone()).unwrap();
        assert_eq!(manager.active_profile().unwrap(), Some(input));
        manager.cancel_without_release().unwrap();
        assert_eq!(manager.active_profile().unwrap(), None);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the netns acceptance driver and a controlled upstream fixture"]
    fn real_safe_exit_stops_owned_tunnel_and_lease_worker() {
        let protocol = match std::env::var("TUNBRIDGE_ACCEPTANCE_PROTOCOL")
            .unwrap()
            .as_str()
        {
            "socks5" => tunbridge_core::upstream::StandardProtocol::Socks5,
            "http" => tunbridge_core::upstream::StandardProtocol::Http,
            _ => panic!("invalid acceptance protocol"),
        };
        let username = std::env::var("TUNBRIDGE_ACCEPTANCE_USERNAME")
            .ok()
            .filter(|value| !value.is_empty());
        let password = std::env::var("TUNBRIDGE_ACCEPTANCE_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty());
        let credentials = match (username, password) {
            (Some(username), Some(password)) => Some(
                tunbridge_core::upstream::SecretMaterialV2::basic_auth(username, password),
            ),
            (None, None) => None,
            _ => panic!("acceptance credentials must provide both username and password"),
        };
        let profile = StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: std::env::var("TUNBRIDGE_ACCEPTANCE_UPSTREAM_PORT")
                    .unwrap()
                    .parse()
                    .unwrap(),
                protocol,
                credentials,
                expected_process_id: std::env::var("TUNBRIDGE_ACCEPTANCE_UPSTREAM_PID")
                    .unwrap()
                    .parse()
                    .unwrap(),
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: Vec::new(),
        };
        let mut client = LinuxServiceClient::connect_system().unwrap();
        client
            .send_detailed(Command::Start { profile }, LIFECYCLE_TIMEOUT)
            .unwrap();
        let grant = client
            .send_detailed(Command::AcquireLease {}, REQUEST_TIMEOUT)
            .unwrap();
        let leases = LeaseManager::default();
        leases
            .install(
                grant,
                StartSavedProfileInput {
                    profile_id: "acceptance-profile".into(),
                    expected_store_revision: 1,
                },
            )
            .unwrap();

        stop_tunnel_for_exit(&leases).unwrap();

        assert!(matches!(
            LinuxServiceClient::connect_system()
                .unwrap()
                .status()
                .unwrap(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                engine_running: false,
                ..
            }
        ));
    }
}
