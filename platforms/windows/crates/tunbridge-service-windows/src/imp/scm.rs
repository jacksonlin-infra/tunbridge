use std::{
    ffi::c_void,
    io,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

#[cfg(feature = "acceptance-rejection")]
use std::io::Write;

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, HANDLE, NO_ERROR, WAIT_OBJECT_0,
    },
    Storage::FileSystem::DELETE,
    System::{
        Com::CoTaskMemFree,
        Power::{
            RegisterPowerSettingNotification, UnregisterPowerSettingNotification,
            POWERBROADCAST_SETTING,
        },
        Services::{
            ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW,
            DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx,
            RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
            StartServiceW, QUERY_SERVICE_CONFIGW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE,
            SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO,
            SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_STOP, SERVICE_AUTO_START,
            SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_FAILURE_ACTIONS,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_INTERROGATE,
            SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL,
            SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_QUERY_CONFIG,
            SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
            SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS, SERVICE_STOP,
            SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        },
        SystemServices::GUID_CONSOLE_DISPLAY_STATE,
        Threading::{CreateEventW, SetEvent, WaitForSingleObject, INFINITE},
    },
    UI::{
        Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
        WindowsAndMessaging::{
            DEVICE_NOTIFY_SERVICE_HANDLE, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND,
            PBT_APMSUSPEND, PBT_POWERSETTINGCHANGE,
        },
    },
};

use crate::{
    protocol::ErrorCode,
    state::{Owner, ServiceState},
    watchdog::WatchdogPolicy,
};

use super::server::{serve_connection_until_shutdown, ServerError};
use super::{
    process::normalized_path, reconcile_owned_engine, ConnectionLimiter, OwnedEngineError,
    RecoveredOwnedEngine, SecurePipeListener, ServiceContext, ShutdownToken,
    SystemLifecycleExecutor, MAX_AUTHENTICATED_CONNECTIONS,
};

pub const SERVICE_NAME: &str = "TunBridgeService";
const FAILURE_RESTART_DELAY_MS: u32 = 5_000;
const FAILURE_RESET_PERIOD_SECONDS: u32 = 24 * 60 * 60;
const SERVICE_DISPLAY_NAME: &str = "TunBridge Privileged Service";
// Empty-feature audit builds remain Status-only. Product and acceptance
// lifecycle publication are explicit, separately evidenced feature sets.
const LIFECYCLE_CAPABILITIES_ENABLED: bool = cfg!(any(
    feature = "production-lifecycle",
    feature = "acceptance-lifecycle"
));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRegistration {
    Absent,
    Exact,
}

/// Read-only setup preflight. An existing registration is accepted only when
/// its SCM command line is the frozen Program Files image plus `run`.
pub fn service_registration() -> Result<ServiceRegistration, ScmError> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_CONFIG) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            return Ok(ServiceRegistration::Absent);
        }
        return Err(ScmError::Windows(error));
    }
    let service = ServiceHandle(raw);
    let configured = query_service_command_line(service.0)?;
    let expected = program_files_directory()?
        .join("TunBridge")
        .join("tunbridge-service.exe");
    if !service_command_line_matches(&configured, &expected) {
        return Err(ScmError::UnsafeInstallPath(
            "TunBridge service command line is not the fixed installed image".into(),
        ));
    }
    Ok(ServiceRegistration::Exact)
}
const PIPE_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(80);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(75);
const SERVICE_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STARTUP_WAIT_HINT_MS: u32 = 30_000;
const PIPE_WAKE_INTERVAL: Duration = Duration::from_millis(25);
const WATCHDOG_ENGINE_INTERVAL: Duration = Duration::from_secs(1);
const WATCHDOG_JOIN_TIMEOUT: Duration = Duration::from_secs(30);

static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static STOP_EVENT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub fn run_dispatcher() -> Result<(), ScmError> {
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: table is terminated by a zeroed entry and remains alive until the
    // dispatcher returns after service_main exits.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    Ok(())
}

/// Run a fixed, feature-gated SCM host that only owns the protected pipe.
///
/// It intentionally has no protocol parser or lifecycle context: the client
/// must reject the anomalous SCM command line before sending Hello. This mode
/// is absent from default, lifecycle, and fault-injection release artifacts.
#[cfg(feature = "acceptance-rejection")]
pub fn run_rejection_dispatcher() -> Result<(), ScmError> {
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(rejection_service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: table is terminated by a zeroed entry and remains alive until
    // the fixed acceptance service exits.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(feature = "acceptance-rejection")]
unsafe extern "system" fn rejection_service_main(_argument_count: u32, _arguments: *mut *mut u16) {
    if rejection_service_main_inner().is_err() {
        let status_handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if !status_handle.is_null() {
            let _ = set_status(status_handle, SERVICE_STOPPED, 0, 1, 0);
        }
    }
}

#[cfg(feature = "acceptance-rejection")]
fn rejection_service_main_inner() -> Result<(), ScmError> {
    let name = wide(SERVICE_NAME);
    // SAFETY: callback and service name remain valid for the service lifetime.
    let status_handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), ptr::null()) };
    if status_handle.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    STATUS_HANDLE.store(status_handle, Ordering::SeqCst);

    // SAFETY: creates a process-local manual-reset event with default security.
    let stop_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if stop_event.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let stop_event_guard = KernelHandle(stop_event);
    STOP_EVENT.store(stop_event, Ordering::SeqCst);
    set_status(status_handle, SERVICE_START_PENDING, 0, 0, 10_000)?;

    super::rejection::prove_session_mismatch_rejected()
        .map_err(|error| ScmError::Runtime(error.to_string()))?;
    let executable = std::env::current_exe().map_err(ScmError::Windows)?;
    let staging = executable.parent().ok_or_else(|| {
        ScmError::Runtime("acceptance rejection host has no parent directory".into())
    })?;
    let marker = staging.join("session-mismatch.ok");
    let mut marker_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .map_err(ScmError::Windows)?;
    marker_file.write_all(b"ok\n").map_err(ScmError::Windows)?;
    marker_file.flush().map_err(ScmError::Windows)?;
    drop(marker_file);

    let _listener =
        SecurePipeListener::bind_first().map_err(|error| ScmError::Runtime(error.to_string()))?;
    set_status(status_handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0)?;

    // SAFETY: stop_event remains valid through stop_event_guard.
    if unsafe { WaitForSingleObject(stop_event, INFINITE) } != WAIT_OBJECT_0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    set_status(status_handle, SERVICE_STOPPED, 0, 0, 0)?;
    STOP_EVENT.store(ptr::null_mut(), Ordering::SeqCst);
    STATUS_HANDLE.store(ptr::null_mut(), Ordering::SeqCst);
    drop(stop_event_guard);
    Ok(())
}

/// Register and start the current binary as an auto-start LocalSystem service.
/// The binary must already be installed under the real Program Files/TunBridge
/// directory; development artifacts and reparse-point escapes are rejected.
pub fn install() -> Result<(), ScmError> {
    let executable = approved_current_executable()?;
    let command_line = service_command_line(&executable)?;
    let manager = open_manager(SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(SERVICE_NAME);
    let display_name = wide(SERVICE_DISPLAY_NAME);
    let binary_path = wide(&command_line);

    // SAFETY: all strings are NUL-terminated for the duration of the call.
    // Null account/password selects LocalSystem for an own-process service.
    let raw = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if raw.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let service = ServiceHandle(raw);
    // Best effort: a service that exits after a runtime error is restarted
    // so startup reconciliation re-adopts or recovers the owned tunnel. The
    // service remains correct, only less self-healing, without it.
    configure_failure_restart(service.0);

    // Installation is transactional: a service that cannot start is removed
    // instead of leaving a broken auto-start entry behind.
    if unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0 {
        let start_error = io::Error::last_os_error();
        if unsafe { DeleteService(service.0) } == 0 {
            let rollback_error = io::Error::last_os_error();
            return Err(ScmError::Runtime(format!(
                "service start failed ({start_error}); registration rollback also failed ({rollback_error})"
            )));
        }
        return Err(ScmError::Windows(start_error));
    }
    Ok(())
}

fn configure_failure_restart(service: SC_HANDLE) {
    let mut actions = [SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: FAILURE_RESTART_DELAY_MS,
    }; 3];
    let failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: FAILURE_RESET_PERIOD_SECONDS,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // Treat an orderly exit with a non-zero code like a crash.
    let on_non_crash_failures = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    // SAFETY: service holds SERVICE_CHANGE_CONFIG; both structures and the
    // action array outlive the calls.
    unsafe {
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failure_actions as *const SERVICE_FAILURE_ACTIONSW as *const c_void,
        );
        ChangeServiceConfig2W(
            service,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            &on_non_crash_failures as *const SERVICE_FAILURE_ACTIONS_FLAG as *const c_void,
        );
    }
}

/// Start the already verified fixed service generation when an upgrade finds
/// its SCM entry stopped. Setup needs the authenticated pipe online so it can
/// recover any exactly owned resources before replacing that generation.
pub fn ensure_service_started() -> Result<(), ScmError> {
    if service_registration()? != ServiceRegistration::Exact {
        return Err(ScmError::UnsafeInstallPath(
            "TunBridge service registration is absent".into(),
        ));
    }
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and name is NUL-terminated. The caller is the
    // elevated setup transaction and requests only start plus status rights.
    let raw = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    if raw.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let service = ServiceHandle(raw);
    let mut status = query_service_status(service.0)?;
    if status.dwCurrentState == SERVICE_STOPPED
        && unsafe { StartServiceW(service.0, 0, ptr::null()) } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(ScmError::Windows(error));
        }
    }

    let deadline = Instant::now() + SERVICE_STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        status = query_service_status(service.0)?;
        if status.dwCurrentState == SERVICE_RUNNING {
            return Ok(());
        }
        if status.dwCurrentState == SERVICE_STOPPED {
            return Err(ScmError::Runtime(format!(
                "service stopped while starting with Windows exit code {}",
                status.dwWin32ExitCode
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(ScmError::Runtime(
        "service did not reach running state before the fixed deadline".into(),
    ))
}

pub fn uninstall() -> Result<(), ScmError> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and name is NUL-terminated.
    let raw = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        )
    };
    if raw.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let service = ServiceHandle(raw);
    let mut status = SERVICE_STATUS::default();
    // A stopped service returns ERROR_SERVICE_NOT_ACTIVE; deletion should still
    // proceed. Other stop failures are fail-closed and leave the registration.
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
            return Err(ScmError::Windows(error));
        }
    }
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    // Removing TunBridge is the user's decision to end the tunnel. Without the
    // service nothing could ever lift the traffic lock, so lift it here.
    super::traffic_lock::remove()
        .map_err(|_| ScmError::Runtime("the traffic lock could not be removed".into()))
}

unsafe extern "system" fn service_main(_argument_count: u32, _arguments: *mut *mut u16) {
    if let Err(error) = service_main_inner() {
        let status_handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if !status_handle.is_null() {
            let _ = set_status(status_handle, SERVICE_STOPPED, 0, 1, 0);
        }
        let _ = error;
    }
}

fn service_main_inner() -> Result<(), ScmError> {
    let name = wide(SERVICE_NAME);
    // SAFETY: callback and service name remain valid for the service lifetime.
    let status_handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), ptr::null()) };
    if status_handle.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    STATUS_HANDLE.store(status_handle, Ordering::SeqCst);
    // Modern Standby keeps the service running while the Desktop is
    // suspended with the display off; observe the console display state.
    // A failed registration leaves sleep/resume events as the only signal.
    // SAFETY: status_handle is a valid service status handle for this
    // process and the GUID is a static constant.
    let display_notification = unsafe {
        RegisterPowerSettingNotification(
            status_handle,
            &GUID_CONSOLE_DISPLAY_STATE,
            DEVICE_NOTIFY_SERVICE_HANDLE,
        )
    };

    // SAFETY: creates a process-local manual-reset event with default security.
    let stop_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if stop_event.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let stop_event_guard = KernelHandle(stop_event);
    STOP_EVENT.store(stop_event, Ordering::SeqCst);
    set_status(
        status_handle,
        SERVICE_START_PENDING,
        0,
        0,
        SERVICE_STARTUP_WAIT_HINT_MS,
    )?;

    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let shutdown = ShutdownToken::default();
    let worker_shutdown = shutdown.clone();
    let worker_stop_event = stop_event as usize;
    let worker = std::thread::spawn(move || {
        let result = run_pipe_server(ready_sender, worker_shutdown);
        if result.is_err() {
            // SAFETY: service_main owns the event until it observes the signal.
            unsafe {
                SetEvent(worker_stop_event as HANDLE);
            }
        }
        result
    });

    match ready_receiver.recv_timeout(SERVICE_STARTUP_TIMEOUT) {
        Ok(Ok(())) => set_status(
            status_handle,
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT,
            0,
            0,
        )?,
        Ok(Err(message)) => {
            shutdown.cancel();
            let _ = join_pipe_worker(worker);
            return Err(ScmError::Runtime(message));
        }
        Err(_) => {
            shutdown.cancel();
            let _ = join_pipe_worker(worker);
            return Err(ScmError::Runtime("pipe server startup timed out".into()));
        }
    }

    // SAFETY: stop_event remains valid through stop_event_guard.
    if unsafe { WaitForSingleObject(stop_event, INFINITE) } != WAIT_OBJECT_0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    shutdown.cancel();
    set_status(status_handle, SERVICE_STOP_PENDING, 0, 0, 90_000)?;
    join_pipe_worker(worker)?;
    if display_notification != 0 {
        // SAFETY: the handle was returned by RegisterPowerSettingNotification.
        unsafe {
            UnregisterPowerSettingNotification(display_notification);
        }
    }
    set_status(status_handle, SERVICE_STOPPED, 0, 0, 0)?;
    STOP_EVENT.store(ptr::null_mut(), Ordering::SeqCst);
    STATUS_HANDLE.store(ptr::null_mut(), Ordering::SeqCst);
    drop(stop_event_guard);
    Ok(())
}

fn run_pipe_server(
    ready: mpsc::SyncSender<Result<(), String>>,
    shutdown: ShutdownToken,
) -> Result<(), ScmError> {
    let initial_state = state_from_recovery(
        reconcile_owned_engine(),
        super::traffic_lock::present().unwrap_or(true),
    );
    let mut listener = match SecurePipeListener::bind_first() {
        Ok(listener) => {
            let _ = ready.send(Ok(()));
            listener
        }
        Err(error) => {
            let message = error.to_string();
            let _ = ready.send(Err(message.clone()));
            return Err(ScmError::Runtime(message));
        }
    };
    let context = Arc::new(ServiceContext::with_lifecycle(
        initial_state,
        Arc::new(SystemLifecycleExecutor),
        LIFECYCLE_CAPABILITIES_ENABLED,
    ));
    let watchdog_context = Arc::clone(&context);
    let watchdog_shutdown = shutdown.clone();
    let watchdog = std::thread::spawn(move || {
        let result = run_runtime_watchdog(&watchdog_context, &watchdog_shutdown);
        if result.is_err() {
            watchdog_shutdown.cancel();
            let _ = super::pipe::connect_client(super::pipe::PIPE_NAME);
        }
        result
    });
    let limiter = ConnectionLimiter::new(MAX_AUTHENTICATED_CONNECTIONS);
    let mut connections = Vec::new();
    let pipe_result = loop {
        if let Err(error) = reap_connection_workers(&mut connections) {
            break Err(error);
        }
        let permit = match limiter.acquire_until_shutdown(&shutdown) {
            Ok(permit) => permit,
            Err(ServerError::ShuttingDown) if shutdown.is_cancelled() => break Ok(()),
            Err(error) => break Err(ScmError::Runtime(error.to_string())),
        };
        let (accepted, next) = match listener.accept_and_rearm_until(&shutdown) {
            Ok(accepted) => accepted,
            Err(super::pipe::PipeError::Shutdown) if shutdown.is_cancelled() => break Ok(()),
            Err(error) => break Err(ScmError::Runtime(error.to_string())),
        };
        listener = next;
        let connection = match accepted {
            Ok(connection) => connection,
            Err(_) if shutdown.is_cancelled() => break Ok(()),
            // One client that disconnected, timed out or failed the hello or
            // identity check must not stop the service and orphan the tunnel.
            Err(_) => continue,
        };
        let context = Arc::clone(&context);
        let connection_shutdown = shutdown.clone();
        connections.push(std::thread::spawn(move || {
            let _permit = permit;
            let _ = serve_connection_until_shutdown(connection, context, connection_shutdown);
        }));
    };
    shutdown.cancel();
    #[cfg(feature = "production-mihomo-logs-v4")]
    context
        .stop_mihomo_log_monitor()
        .map_err(|error| ScmError::Runtime(error.to_string()))?;
    let drain_result = drain_connection_workers(connections, CONNECTION_DRAIN_TIMEOUT);
    let watchdog_result = join_runtime_watchdog(watchdog);
    pipe_result?;
    drain_result?;
    watchdog_result
}

fn run_runtime_watchdog(
    context: &ServiceContext,
    shutdown: &ShutdownToken,
) -> Result<(), ScmError> {
    let mut policy = WatchdogPolicy::default();
    #[cfg(feature = "acceptance-m2b5")]
    let mut telemetry_policy = crate::telemetry::TelemetryPolicy::default();
    #[cfg(feature = "acceptance-m2b5")]
    let mut telemetry_generation = None;
    #[cfg(feature = "acceptance-m2b5")]
    let mut telemetry_next_seq = 1_u64;
    let mut tick = 0_u64;
    let mut sleep_clock = super::power::SleepClock::default();
    let mut wake_hold = super::power::WakeHold::default();
    while wait_for_watchdog_tick(shutdown) {
        // Sample wake facts every tick so a wake is never left pending.
        let slept = sleep_clock.sample();
        let woke = super::power::POWER.take_watchdog_wake() || slept;
        let suspended = super::power::POWER.suspended();
        let phase = context
            .phase()
            .map_err(|error| ScmError::Runtime(error.to_string()))?;
        if phase == crate::state::Phase::Running {
            #[cfg(feature = "production-mihomo-logs-v4")]
            context
                .sync_mihomo_log_monitor()
                .map_err(|error| ScmError::Runtime(error.to_string()))?;
            let include_slow_signals = tick.is_multiple_of(2);
            let sample = super::runtime_watchdog::sample_runtime(include_slow_signals);
            let mut observation = sample.observation;
            if let Some(restarted) = sample.restarted_upstream {
                observation.upstream = if context
                    .rebind_restarted_upstream(restarted)
                    .map_err(|error| ScmError::Runtime(error.to_string()))?
                {
                    crate::watchdog::HealthSignal::Healthy
                } else {
                    crate::watchdog::HealthSignal::Unknown
                };
            }
            let observation = wake_hold.apply(suspended, woke, observation);
            let operation_id = format!(
                "watchdog-{}",
                super::random::random_hex_32()
                    .map_err(|error| ScmError::Runtime(error.to_string()))?
            );
            // A failed evaluation must not end the service: the tunnel it
            // watches would be left without its owner. The next tick retries.
            let _ = context.apply_watchdog_observation(&mut policy, observation, &operation_id);
            #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
            {
                let lease_operation_id = format!(
                    "lease-{}",
                    super::random::random_hex_32()
                        .map_err(|error| ScmError::Runtime(error.to_string()))?
                );
                let _ = context.apply_lease_tick(&lease_operation_id);
            }

            #[cfg(feature = "acceptance-m2b5")]
            {
                if context
                    .phase()
                    .map_err(|error| ScmError::Runtime(error.to_string()))?
                    == crate::state::Phase::Running
                {
                    if let Some(generation) = context
                        .m2b5_generation()
                        .map_err(|error| ScmError::Runtime(error.to_string()))?
                    {
                        if telemetry_generation != Some(generation) {
                            telemetry_generation = Some(generation);
                            telemetry_next_seq = 1;
                        }
                        let owned = super::runtime_telemetry::sample_structured_failures(
                            generation,
                            tick,
                            &mut telemetry_next_seq,
                            observation.controller,
                        );
                        let batch = match &owned {
                            // Controller identity is deliberately sampled on
                            // the existing two-second slow cadence. Preserve
                            // policy state between samples; Disabled remains
                            // reserved for a sampled, intentionally absent
                            // source and still resets the policy.
                            super::runtime_telemetry::OwnedTelemetryBatch::Unsampled => None,
                            super::runtime_telemetry::OwnedTelemetryBatch::Disabled => {
                                Some(crate::telemetry::TelemetryBatch::Disabled)
                            }
                            super::runtime_telemetry::OwnedTelemetryBatch::Unknown => {
                                Some(crate::telemetry::TelemetryBatch::Unknown)
                            }
                            super::runtime_telemetry::OwnedTelemetryBatch::Events(events) => {
                                Some(crate::telemetry::TelemetryBatch::Events(events))
                            }
                        };
                        if let Some(batch) = batch {
                            let telemetry_operation_id = format!(
                                "telemetry-{}",
                                super::random::random_hex_32()
                                    .map_err(|error| ScmError::Runtime(error.to_string()))?
                            );
                            context
                                .apply_telemetry_batch(
                                    &mut telemetry_policy,
                                    tick,
                                    generation,
                                    batch,
                                    &telemetry_operation_id,
                                )
                                .map_err(|error| ScmError::Runtime(error.to_string()))?;
                        }
                    }
                } else {
                    telemetry_policy.reset();
                    telemetry_generation = None;
                    telemetry_next_seq = 1;
                }
            }
        } else {
            #[cfg(feature = "production-mihomo-logs-v4")]
            context
                .sync_mihomo_log_monitor()
                .map_err(|error| ScmError::Runtime(error.to_string()))?;
            policy.reset();
            #[cfg(feature = "acceptance-m2b5")]
            {
                telemetry_policy.reset();
                telemetry_generation = None;
                telemetry_next_seq = 1;
            }
        }
        tick = tick.wrapping_add(1);
    }
    Ok(())
}

fn wait_for_watchdog_tick(shutdown: &ShutdownToken) -> bool {
    let deadline = Instant::now() + WATCHDOG_ENGINE_INTERVAL;
    while Instant::now() < deadline {
        if shutdown.is_cancelled() {
            return false;
        }
        std::thread::sleep(PIPE_WAKE_INTERVAL);
    }
    !shutdown.is_cancelled()
}

fn join_runtime_watchdog(
    worker: std::thread::JoinHandle<Result<(), ScmError>>,
) -> Result<(), ScmError> {
    let deadline = Instant::now() + WATCHDOG_JOIN_TIMEOUT;
    while !worker.is_finished() && Instant::now() < deadline {
        std::thread::sleep(PIPE_WAKE_INTERVAL);
    }
    if !worker.is_finished() {
        return Err(ScmError::Runtime(
            "runtime watchdog did not stop within the fixed shutdown deadline".into(),
        ));
    }
    worker
        .join()
        .map_err(|_| ScmError::Runtime("runtime watchdog panicked during shutdown".into()))?
}

fn join_pipe_worker(worker: std::thread::JoinHandle<Result<(), ScmError>>) -> Result<(), ScmError> {
    let deadline = Instant::now() + PIPE_WORKER_SHUTDOWN_TIMEOUT;
    while !worker.is_finished() && Instant::now() < deadline {
        let _ = super::pipe::connect_client(super::pipe::PIPE_NAME);
        std::thread::sleep(PIPE_WAKE_INTERVAL);
    }
    if !worker.is_finished() {
        return Err(ScmError::Runtime(
            "pipe worker did not stop within the fixed shutdown deadline".into(),
        ));
    }
    worker
        .join()
        .map_err(|_| ScmError::Runtime("pipe worker panicked during shutdown".into()))?
}

fn reap_connection_workers(
    connections: &mut Vec<std::thread::JoinHandle<()>>,
) -> Result<(), ScmError> {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].is_finished() {
            connections
                .swap_remove(index)
                .join()
                .map_err(|_| ScmError::Runtime("connection worker panicked".into()))?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn drain_connection_workers(
    mut connections: Vec<std::thread::JoinHandle<()>>,
    timeout: Duration,
) -> Result<(), ScmError> {
    let deadline = Instant::now() + timeout;
    while !connections.is_empty() && Instant::now() < deadline {
        reap_connection_workers(&mut connections)?;
        if !connections.is_empty() {
            std::thread::sleep(PIPE_WAKE_INTERVAL);
        }
    }
    if connections.is_empty() {
        Ok(())
    } else {
        Err(ScmError::Runtime(
            "connection workers did not stop within the fixed shutdown deadline".into(),
        ))
    }
}

/// `locked` says whether the traffic lock outlived the previous service
/// process. A session that is gone while the lock still holds traffic is a
/// fault the user resolves, never a silent stop.
fn state_from_recovery(
    recovery: Result<RecoveredOwnedEngine, OwnedEngineError>,
    locked: bool,
) -> ServiceState {
    let lost = |locked: bool| ServiceState {
        phase: if locked {
            crate::state::Phase::Faulted
        } else {
            crate::state::Phase::Stopped
        },
        last_error: locked.then_some(ErrorCode::RecoveryRequired),
        last_watchdog_reason: Some(crate::state::WatchdogReason::EngineExited),
        ..ServiceState::default()
    };
    match recovery {
        Ok(RecoveredOwnedEngine::Absent | RecoveredOwnedEngine::ClearedPending) if locked => {
            lost(true)
        }
        Ok(RecoveredOwnedEngine::Absent | RecoveredOwnedEngine::ClearedPending) => {
            ServiceState::default()
        }
        // The engine of the previous session is gone; say so instead of
        // reporting a silent stop.
        Ok(RecoveredOwnedEngine::ClearedExited) => lost(locked),
        Ok(RecoveredOwnedEngine::Running(record)) => ServiceState::recovered_running(Owner {
            principal_id: record.owner_principal_id,
            session_id: record.owner_session_id,
        }),
        Err(_) => ServiceState::recovered_fault(ErrorCode::OwnedProcessMismatch),
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP => {}
        SERVICE_CONTROL_INTERROGATE => return NO_ERROR,
        SERVICE_CONTROL_POWEREVENT => {
            // SAFETY: SCM supplies event_data matching event_type for the
            // duration of this callback.
            unsafe { handle_power_event(event_type, event_data) };
            return NO_ERROR;
        }
        _ => return ERROR_CALL_NOT_IMPLEMENTED,
    }
    let status_handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if !status_handle.is_null() {
        let _ = set_status(status_handle, SERVICE_STOP_PENDING, 0, 0, 90_000);
    }
    let stop_event = STOP_EVENT.load(Ordering::SeqCst);
    if !stop_event.is_null() {
        // SAFETY: event is owned by service_main while the global is non-null.
        unsafe {
            SetEvent(stop_event);
        }
    }
    NO_ERROR
}

/// # Safety
/// `event_data` must be the pointer SCM passed with `event_type`.
unsafe fn handle_power_event(event_type: u32, event_data: *mut c_void) {
    match event_type {
        PBT_APMSUSPEND => super::power::POWER.suspend(),
        PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => super::power::POWER.resume(),
        PBT_POWERSETTINGCHANGE if !event_data.is_null() => {
            // SAFETY: for PBT_POWERSETTINGCHANGE event_data points to a
            // POWERBROADCAST_SETTING whose Data holds DataLength bytes.
            let setting = unsafe { &*(event_data as *const POWERBROADCAST_SETTING) };
            if guid_eq(&setting.PowerSetting, &GUID_CONSOLE_DISPLAY_STATE)
                && setting.DataLength as usize >= std::mem::size_of::<u32>()
            {
                // SAFETY: DataLength covers one DWORD; read it unaligned.
                let state = unsafe { ptr::read_unaligned(setting.Data.as_ptr() as *const u32) };
                super::power::POWER.display_state(state);
            }
        }
        _ => {}
    }
}

fn guid_eq(left: &windows_sys::core::GUID, right: &windows_sys::core::GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn set_status(
    handle: SERVICE_STATUS_HANDLE,
    current_state: u32,
    controls_accepted: u32,
    exit_code: u32,
    wait_hint: u32,
) -> Result<(), ScmError> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    // SAFETY: handle was returned by RegisterServiceCtrlHandlerExW and status
    // is initialized for the duration of the call.
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    Ok(())
}

fn approved_current_executable() -> Result<PathBuf, ScmError> {
    let executable = std::env::current_exe().map_err(ScmError::Windows)?;
    let program_files = program_files_directory()?;
    validate_install_path(&executable, &program_files)
}

fn validate_install_path(executable: &Path, program_files: &Path) -> Result<PathBuf, ScmError> {
    let product_directory = program_files.join("TunBridge");
    let canonical_program_files = program_files.canonicalize().map_err(ScmError::Windows)?;
    let canonical_executable = executable.canonicalize().map_err(ScmError::Windows)?;
    let expected_directory = canonical_program_files.join("TunBridge");
    if canonical_executable.parent() != Some(expected_directory.as_path())
        || !canonical_executable.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .eq_ignore_ascii_case("tunbridge-service.exe")
        })
    {
        return Err(ScmError::UnsafeInstallPath(
            "service binary must be Program Files\\TunBridge\\tunbridge-service.exe".into(),
        ));
    }
    for path in [&product_directory, executable] {
        let metadata = std::fs::symlink_metadata(path).map_err(ScmError::Windows)?;
        if metadata.file_type().is_symlink() {
            return Err(ScmError::UnsafeInstallPath(
                "reparse-point service paths are not allowed".into(),
            ));
        }
    }
    Ok(canonical_executable)
}

pub(super) fn program_files_directory() -> Result<PathBuf, ScmError> {
    let mut raw = ptr::null_mut();
    // SAFETY: raw points to writable storage; the API allocates a UTF-16 path.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut raw) };
    if result < 0 {
        return Err(ScmError::KnownFolder(result));
    }
    let path = wide_ptr_to_path(raw);
    // SAFETY: SHGetKnownFolderPath allocates with the COM task allocator.
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    path
}

fn wide_ptr_to_path(raw: *const u16) -> Result<PathBuf, ScmError> {
    if raw.is_null() {
        return Err(ScmError::KnownFolder(-1));
    }
    let mut length = 0;
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| ScmError::UnsafeInstallPath("Program Files path is invalid UTF-16".into()))?;
    Ok(PathBuf::from(value))
}

fn service_command_line(executable: &Path) -> Result<String, ScmError> {
    let executable = executable.to_string_lossy();
    if executable.contains('"') || executable.contains('\0') {
        return Err(ScmError::UnsafeInstallPath(
            "service binary path contains an unsafe character".into(),
        ));
    }
    Ok(format!("\"{executable}\" run"))
}

/// Prove that a kernel-reported named-pipe server PID belongs to the fixed SCM
/// service and that SCM's administrator-protected configuration contains only
/// the approved Program Files executable plus the fixed `run` mode. This is
/// usable by medium standard users that cannot open a LocalSystem process DACL.
pub(super) fn verify_service_process(process_id: u32) -> Result<(), ScmError> {
    if process_id == 0 {
        return Err(ScmError::UnsafeInstallPath(
            "named pipe server reported a zero PID".into(),
        ));
    }
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: manager is valid and name is NUL-terminated. Both requested
    // rights are read-only and granted to standard authenticated users by the
    // default SCM service security descriptor.
    let raw = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    if raw.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    let service = ServiceHandle(raw);

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: status is writable for its exact byte size and service is valid.
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    if status.dwProcessId != process_id
        || !matches!(
            status.dwCurrentState,
            SERVICE_START_PENDING | SERVICE_RUNNING
        )
    {
        return Err(ScmError::UnsafeInstallPath(
            "named pipe PID is not the running TunBridge service".into(),
        ));
    }

    let configured = query_service_command_line(service.0)?;
    let expected = program_files_directory()?
        .join("TunBridge")
        .join("tunbridge-service.exe");
    if !service_command_line_matches(&configured, &expected) {
        return Err(ScmError::UnsafeInstallPath(
            "TunBridge service command line is not the fixed installed image".into(),
        ));
    }
    Ok(())
}

fn query_service_command_line(service: SC_HANDLE) -> Result<String, ScmError> {
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally supplies no buffer to obtain size.
    unsafe {
        QueryServiceConfigW(service, ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<QUERY_SERVICE_CONFIGW>() as u32 || needed > 65_536 {
        return Err(ScmError::UnsafeInstallPath(
            "service configuration size is invalid".into(),
        ));
    }
    let word_count = (needed as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; word_count];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: the usize buffer is aligned for QUERY_SERVICE_CONFIGW and spans
    // at least `needed` writable bytes for the structure and its strings.
    if unsafe { QueryServiceConfigW(service, config, needed, &mut needed) } == 0 {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    // SAFETY: QueryServiceConfigW initialized the structure in buffer.
    let path = unsafe { (*config).lpBinaryPathName };
    let base = buffer.as_ptr() as usize;
    let end = base + buffer.len() * size_of::<usize>();
    let address = path as usize;
    if path.is_null()
        || address < base
        || address >= end
        || !address.is_multiple_of(size_of::<u16>())
    {
        return Err(ScmError::UnsafeInstallPath(
            "service command line pointer is outside the query buffer".into(),
        ));
    }
    let max_units = (end - address) / size_of::<u16>();
    let mut length = 0_usize;
    // SAFETY: path lies within buffer and each read stays below max_units.
    unsafe {
        while length < max_units && *path.add(length) != 0 {
            length += 1;
        }
    }
    if length == max_units {
        return Err(ScmError::UnsafeInstallPath(
            "service command line is not NUL-terminated".into(),
        ));
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(path, length) })
        .map_err(|_| ScmError::UnsafeInstallPath("service command line is invalid UTF-16".into()))
}

fn query_service_status(service: SC_HANDLE) -> Result<SERVICE_STATUS_PROCESS, ScmError> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0_u32;
    // SAFETY: status is writable for its exact byte size and service is valid.
    if unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    Ok(status)
}

fn service_command_line_matches(command_line: &str, expected: &Path) -> bool {
    let Some(quoted) = command_line.strip_prefix('"') else {
        return false;
    };
    let Some(end_quote) = quoted.find('"') else {
        return false;
    };
    if &quoted[end_quote + 1..] != " run" {
        return false;
    }
    let executable = Path::new(&quoted[..end_quote]);
    executable.is_absolute() && normalized_path(executable) == normalized_path(expected)
}

fn open_manager(access: u32) -> Result<ServiceHandle, ScmError> {
    let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if raw.is_null() {
        return Err(ScmError::Windows(io::Error::last_os_error()));
    }
    Ok(ServiceHandle(raw))
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

struct KernelHandle(HANDLE);

impl Drop for KernelHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ScmError {
    #[error("Windows service operation failed: {0}")]
    Windows(#[source] io::Error),
    #[error("unsafe service install path: {0}")]
    UnsafeInstallPath(String),
    #[error("Windows known-folder lookup failed with HRESULT {0:#x}")]
    KnownFolder(i32),
    #[error("service runtime failed: {0}")]
    Runtime(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_command_line_quotes_path_and_has_fixed_mode() {
        let line = service_command_line(Path::new(
            r"C:\Program Files\TunBridge\tunbridge-service.exe",
        ))
        .unwrap();
        assert_eq!(
            line,
            r#""C:\Program Files\TunBridge\tunbridge-service.exe" run"#
        );
        assert!(service_command_line(Path::new("C:\\bad\"path.exe")).is_err());
    }

    #[test]
    fn queried_service_command_line_accepts_only_fixed_image_and_mode() {
        let expected = Path::new(r"C:\Program Files\TunBridge\tunbridge-service.exe");
        assert!(service_command_line_matches(
            r#""C:\Program Files\TunBridge\tunbridge-service.exe" run"#,
            expected
        ));
        assert!(service_command_line_matches(
            r#""\\?\c:\program files\tunbridge\TUNBRIDGE-SERVICE.EXE" run"#,
            expected
        ));
        assert!(!service_command_line_matches(
            r#""C:\Program Files\TunBridge\tunbridge-service.exe" run --extra"#,
            expected
        ));
        assert!(!service_command_line_matches(
            r#""C:\Program Files\Other\tunbridge-service.exe" run"#,
            expected
        ));
        assert!(!service_command_line_matches(
            r"C:\Program Files\TunBridge\tunbridge-service.exe run",
            expected
        ));
    }

    #[test]
    fn development_binary_is_not_approved_for_system_service_install() {
        let error = approved_current_executable().unwrap_err();
        assert!(matches!(error, ScmError::UnsafeInstallPath(_)));
    }

    #[test]
    fn service_name_and_mode_are_fixed() {
        assert_eq!(SERVICE_NAME, "TunBridgeService");
        assert_eq!(SERVICE_WIN32_OWN_PROCESS, 0x10);
        assert_eq!(SERVICE_AUTO_START, 2);
        assert_eq!(SERVICE_STARTUP_TIMEOUT, Duration::from_secs(30));
        assert_eq!(SERVICE_STARTUP_WAIT_HINT_MS, 30_000);
    }

    #[test]
    fn startup_recovery_maps_owned_identity_without_exposing_details() {
        use super::super::OwnedEngineRecord;

        assert_eq!(
            state_from_recovery(Ok(RecoveredOwnedEngine::Absent), false),
            ServiceState::default()
        );
        let record = OwnedEngineRecord {
            schema_version: 3,
            product_version: env!("CARGO_PKG_VERSION").into(),
            stage: super::super::OwnedEngineStage::Running,
            pid: 42,
            creation_time: 123,
            image_path: PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe"),
            engine_version: "v1.19.28".into(),
            engine_sha256: "a".repeat(64),
            owner_principal_id: "S-1-5-21-owner".into(),
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
        let recovered =
            state_from_recovery(Ok(RecoveredOwnedEngine::Running(Box::new(record))), false);
        assert_eq!(recovered.phase, crate::state::Phase::Running);
        assert_eq!(recovered.owner.unwrap().principal_id, "S-1-5-21-owner");

        let faulted = state_from_recovery(Err(OwnedEngineError::InvalidRecord), false);
        assert_eq!(faulted.phase, crate::state::Phase::Faulted);
        assert_eq!(faulted.last_error, Some(ErrorCode::OwnedProcessMismatch));
        assert!(faulted.owner.is_none());
    }

    #[test]
    fn connection_workers_are_joined_or_rejected_at_a_fixed_deadline() {
        let completed = vec![std::thread::spawn(|| {})];
        drain_connection_workers(completed, Duration::from_secs(1)).unwrap();

        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let blocked = vec![std::thread::spawn(move || {
            let _ = release_receiver.recv();
        })];
        let result = drain_connection_workers(blocked, Duration::from_millis(20));
        assert!(matches!(result, Err(ScmError::Runtime(_))));
        release_sender.send(()).unwrap();
    }

    #[test]
    fn runtime_watchdog_observes_shutdown_and_joins() {
        let context = Arc::new(ServiceContext::status_only(ServiceState::default()));
        let shutdown = ShutdownToken::default();
        let worker_context = Arc::clone(&context);
        let worker_shutdown = shutdown.clone();
        let worker =
            std::thread::spawn(move || run_runtime_watchdog(&worker_context, &worker_shutdown));
        shutdown.cancel();
        join_runtime_watchdog(worker).unwrap();
    }
}
