#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod app_update;
#[cfg(target_os = "linux")]
#[path = "credential_store_linux.rs"]
mod credential_store;
#[cfg(target_os = "macos")]
#[path = "credential_store_macos.rs"]
mod credential_store;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/diagnostics_commands.rs"]
mod diagnostics_commands;
#[cfg(target_os = "linux")]
#[path = "diagnostics_commands_linux.rs"]
mod diagnostics_commands;
#[cfg(target_os = "macos")]
#[path = "diagnostics_commands_macos.rs"]
mod diagnostics_commands;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/installer_commands.rs"]
mod installer_commands;
#[cfg(target_os = "linux")]
#[path = "installer_commands_linux.rs"]
mod installer_commands;
#[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
#[path = "installer_commands_macos.rs"]
mod installer_commands;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/lifecycle_commands.rs"]
mod lifecycle_commands;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "lifecycle_commands_unix.rs"]
mod lifecycle_commands;
pub mod local_proxy;
#[cfg(not(windows))]
mod local_proxy_platform;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/local_proxy_platform.rs"]
mod local_proxy_platform;
#[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
mod macos_dev_installer;
#[cfg(target_os = "macos")]
mod macos_lease_activity;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/profile_commands.rs"]
mod profile_commands;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "profile_commands_linux.rs"]
mod profile_commands;
pub mod profile_store;
#[cfg(windows)]
#[allow(dead_code)] // Legacy profile APIs remain available for v2 migration and recovery.
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/profile_store_files_windows.rs"]
mod profile_store_files_windows;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "profile_store_linux.rs"]
mod profile_store_unix;
pub mod profile_store_v2;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use profile_store_v2 as active_profile_store;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod event_log;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod profile_store_v2_unix;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/profile_store_v2_files_windows.rs"]
mod profile_store_v2_windows;
#[cfg(windows)]
#[allow(dead_code)] // Legacy vault APIs remain available for v2 migration and recovery.
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/profile_store_windows.rs"]
mod profile_store_windows;
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
mod status;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod status_monitor;
#[cfg(all(windows, feature = "production-service"))]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/desktop/traffic_commands.rs"]
mod traffic_commands;
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[path = "traffic_commands_unix.rs"]
mod traffic_commands;

use local_proxy::{DesktopProbeError, DiscoveryResponse, OperationSlot, TestInput, TestResponse};
use serde::{Deserialize, Serialize};
#[cfg(any(
    not(any(windows, target_os = "linux")),
    not(feature = "production-service")
))]
use serde_json::Value;
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
#[cfg(target_os = "macos")]
use tauri::menu::Submenu;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, PhysicalSize, Size, State, WindowEvent,
};

const WINDOW_STATE_FILE: &str = "main-window.json";
const TRAY_NAVIGATE_EVENT: &str = "tunbridge:tray-navigate";
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const TRAY_EXIT_FAILED_EVENT: &str = "tunbridge:tray-exit-failed";
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const EXIT_CONFIRM_EVENT: &str = "tunbridge:exit-confirm";

#[derive(Default)]
struct TrayNavigationState {
    pending: Mutex<Option<&'static str>>,
}

impl TrayNavigationState {
    fn queue(&self, destination: &'static str) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(destination);
        }
    }

    fn take(&self) -> Option<&'static str> {
        self.pending.lock().ok()?.take()
    }
}

#[derive(Default)]
struct ExitRequestState(AtomicBool);

impl ExitRequestState {
    fn begin(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn finish(&self) {
        self.0.store(false, Ordering::Release);
    }
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn is_background_launch<I, S>(arguments: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    arguments
        .into_iter()
        .any(|argument| argument.as_ref() == "--background")
}

fn open_tray_destination(app: &tauri::AppHandle, destination: &'static str) {
    app.state::<TrayNavigationState>().queue(destination);
    show_main_window(app);
    let _ = app.emit(TRAY_NAVIGATE_EVENT, destination);
}

#[tauri::command]
fn take_pending_tray_navigation(state: State<'_, TrayNavigationState>) -> Option<&'static str> {
    state.take()
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn request_safe_exit(app: tauri::AppHandle) {
    if !app.state::<ExitRequestState>().begin() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let slot = Arc::clone(app.state::<Arc<OperationSlot>>().inner());
        let leases = Arc::clone(app.state::<Arc<lifecycle_commands::LeaseManager>>().inner());
        let result = tauri::async_runtime::spawn_blocking(move || {
            let _permit = slot.try_acquire_owned().map_err(|_| {
                lifecycle_commands::LifecycleCommandError::from(
                    lifecycle_commands::LifecycleCommandErrorCode::Busy,
                )
            })?;
            lifecycle_commands::stop_tunnel_for_exit(&leases)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                record_event(&app, event_log::EventLog::user_closed);
                app.exit(0)
            }
            Ok(Err(error)) => {
                app.state::<ExitRequestState>().finish();
                show_main_window(&app);
                let _ = app.emit(TRAY_EXIT_FAILED_EVENT, error.code);
            }
            Err(_) => {
                app.state::<ExitRequestState>().finish();
                show_main_window(&app);
                let _ = app.emit(TRAY_EXIT_FAILED_EVENT, "worker_failed");
            }
        }
    });
}

/// Quitting the App never decides on its own whether the tunnel stops. While
/// a tunnel is up, the window asks: stop it and quit (traffic goes direct, an
/// explicit user choice), or keep it and only close the App. With nothing
/// running the App simply quits.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn prompt_exit(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let tunnel_up = tauri::async_runtime::spawn_blocking(|| {
            status::get_status().is_ok_and(|status| {
                status.service_phase() != tunbridge_service::state::Phase::Stopped
            })
        })
        .await
        .unwrap_or(false);
        if tunnel_up {
            show_main_window(&app);
            let _ = app.emit(EXIT_CONFIRM_EVENT, ());
        } else {
            request_safe_exit(app);
        }
    });
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn prompt_exit(app: tauri::AppHandle) {
    app.exit(0);
}

/// Closes the App and leaves the tunnel to the service. The lease is released
/// so the service knows the App left on purpose; the tunnel keeps running and
/// a relaunched App takes the session back.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn exit_keeping_tunnel(app: tauri::AppHandle) {
    if !app.state::<ExitRequestState>().begin() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let leases = Arc::clone(app.state::<Arc<lifecycle_commands::LeaseManager>>().inner());
        let _ = tauri::async_runtime::spawn_blocking(move || leases.cancel_and_release()).await;
        app.exit(0);
    });
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmExitInput {
    stop_tunnel: bool,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command]
fn confirm_exit(app: tauri::AppHandle, input: ConfirmExitInput) {
    if input.stop_tunnel {
        request_safe_exit(app);
    } else {
        exit_keeping_tunnel(app);
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command]
fn confirm_exit(app: tauri::AppHandle, input: ConfirmExitInput) {
    let _ = input;
    app.exit(0);
}

/// The default macOS application menu quits through NSApp terminate, which
/// skips the tunnel question. Replace its Quit item with one that asks. A
/// system logout or shutdown still terminates the App and keeps the tunnel.
#[cfg(target_os = "macos")]
fn macos_app_menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let quit = MenuItem::with_id(app, "app_quit", "退出 TunBridge", true, Some("CmdOrCtrl+Q"))?;
    let application = Submenu::with_items(
        app,
        "TunBridge",
        true,
        &[
            &PredefinedMenuItem::about(app, None, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let edit = Submenu::with_items(
        app,
        "编辑",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;
    let window = Submenu::with_items(
        app,
        "窗口",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;
    Menu::with_items(app, &[&application, &edit, &window])
}

/// Development builds only. A second launch with `--tb-dev=<action>` drives
/// the running instance, so native acceptance can run over SSH on a test Mac.
/// It has exactly the authority of the same user clicking in the window, and
/// writes its outcome to /tmp/tunbridge-dev-action.txt.
#[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
fn run_development_action(app: &tauri::AppHandle, arguments: &[String]) -> bool {
    let Some(action) = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--tb-dev="))
        .map(str::to_owned)
    else {
        return false;
    };
    // A plain thread, not an async task: the single-instance listener blocks
    // its runtime worker in accept(), so a task spawned from this callback
    // would sit in that worker's LIFO slot until the next launch arrives.
    let app = app.clone();
    std::thread::spawn(move || {
        let leases = Arc::clone(app.state::<Arc<lifecycle_commands::LeaseManager>>().inner());
        let profiles = profile_commands::list_profiles();
        let outcome = match action.split_once(':').unwrap_or((&action, "")) {
            ("profiles", _) => format!("{profiles:?}"),
            ("status", _) => format!("{:?}", status::get_status()),
            ("start", index) => match profiles {
                Ok(list) => match list.profiles.get(index.parse().unwrap_or(0)) {
                    Some(profile) => {
                        let result = lifecycle_commands::start_saved_profile(
                            lifecycle_commands::StartSavedProfileInput {
                                profile_id: profile.profile_id.clone(),
                                expected_store_revision: list.store_revision,
                            },
                            &leases,
                        );
                        if result.is_ok() {
                            record_event(&app, |log| log.user_started(&profile.profile_id));
                        }
                        format!("{result:?}")
                    }
                    None => "no-such-profile".into(),
                },
                Err(error) => format!("{error:?}"),
            },
            ("stop", _) => {
                let result = lifecycle_commands::stop_tunnel(&leases);
                if result.is_ok() {
                    record_event(&app, event_log::EventLog::user_closed);
                }
                format!("{result:?}")
            }
            ("recover", _) => {
                let result = lifecycle_commands::recover_tunnel(&leases);
                if result.is_ok() {
                    record_event(&app, event_log::EventLog::user_recovered);
                }
                format!("{result:?}")
            }
            ("events", _) => match app.try_state::<EventLogState>() {
                Some(state) => state
                    .0
                    .lock()
                    .map(|log| serde_json::to_string(&log.page()).unwrap_or_default())
                    .unwrap_or_default(),
                None => "no event log".into(),
            },
            ("quit-keep", _) => "quitting, tunnel kept".into(),
            ("diag", _) => development_diagnostics(),
            _ => "unknown action".into(),
        };
        let _ = fs::write(
            "/tmp/tunbridge-dev-action.txt",
            format!("{action}: {outcome}\n"),
        );
        if action == "quit-keep" {
            exit_keeping_tunnel(app);
        }
    });
    true
}

/// Runs the website checks, the exit-IP lookup and system information exactly
/// as the WebView commands do, from inside the App process, plus one raw curl
/// probe with its exit code and error text for diagnosis.
#[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
fn development_diagnostics() -> String {
    let mut lines = Vec::new();
    for target in ["github", "google", "youtube", "apple", "claude"] {
        let result = serde_json::from_value::<diagnostics_commands::WebsiteTestInput>(
            serde_json::json!({ "target": target }),
        )
        .map(diagnostics_commands::test_website);
        lines.push(format!("website {target}: {result:?}"));
    }
    lines.push(format!(
        "ip: {:?}",
        diagnostics_commands::get_ip_information()
    ));
    lines.push(format!(
        "system: {:?}",
        diagnostics_commands::get_system_information()
    ));
    let probe = std::process::Command::new("/usr/bin/curl")
        .args([
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "8",
            "--connect-timeout",
            "5",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "https://github.com/",
        ])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output();
    lines.push(match probe {
        Ok(output) => format!(
            "raw curl: status={:?} stdout={:?} stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("raw curl: spawn error {error}"),
    });
    lines.join("\n")
}

#[cfg(windows)]
fn install_update_exit_listener(app: tauri::AppHandle) -> Result<(), std::io::Error> {
    use std::{os::windows::ffi::OsStrExt as _, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{CreateEventW, WaitForSingleObject, INFINITE},
    };

    const UPDATE_EXIT_EVENT: &str = "Local\\com.tunbridge.desktop.prepare-update";
    let name: Vec<u16> = std::ffi::OsStr::new(UPDATE_EXIT_EVENT)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Auto-reset and initially non-signaled. The default DACL binds the event
    // to this interactive user; the elevated setup from the same session can
    // signal it without creating a cross-session process-control surface.
    let event = unsafe { CreateEventW(ptr::null(), 0, 0, name.as_ptr()) };
    if event.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let event_value = event as usize;
    std::thread::spawn(move || {
        let event = event_value as windows_sys::Win32::Foundation::HANDLE;
        if unsafe { WaitForSingleObject(event, INFINITE) } == WAIT_OBJECT_0 {
            request_safe_exit(app);
        }
        unsafe { CloseHandle(event) };
    });
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn request_safe_exit(app: tauri::AppHandle) {
    app.exit(0);
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SavedWindowState {
    width: u32,
    height: u32,
    maximized: bool,
}

fn restore_main_window(app: &tauri::App) {
    let Ok(root) = app.path().app_local_data_dir() else {
        return;
    };
    let Ok(bytes) = fs::read(root.join(WINDOW_STATE_FILE)) else {
        return;
    };
    if bytes.len() > 1024 {
        return;
    }
    let Ok(saved) = serde_json::from_slice::<SavedWindowState>(&bytes) else {
        return;
    };
    if !(960..=7680).contains(&saved.width) || !(680..=4320).contains(&saved.height) {
        return;
    }
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.set_size(Size::Physical(PhysicalSize::new(saved.width, saved.height)));
    if saved.maximized {
        let _ = window.maximize();
    }
}

fn persist_main_window(window: &tauri::Window) {
    let Ok(size) = window.inner_size() else {
        return;
    };
    if size.width < 960 || size.height < 680 {
        return;
    }
    let maximized = window.is_maximized().unwrap_or(false);
    let saved = SavedWindowState {
        width: size.width,
        height: size.height,
        maximized,
    };
    let Ok(root) = window.app_handle().path().app_local_data_dir() else {
        return;
    };
    if fs::create_dir_all(&root).is_err() {
        return;
    }
    if let Ok(bytes) = serde_json::to_vec(&saved) {
        let _ = fs::write(root.join(WINDOW_STATE_FILE), bytes);
    }
}

/// The local tunnel event log, created at startup in the App's data directory.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
struct EventLogState(std::sync::Mutex<event_log::EventLog>);

/// Records into the event log; a missing or poisoned log never blocks the
/// lifecycle operation that produced the event.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub(crate) fn record_event(app: &tauri::AppHandle, record: impl FnOnce(&mut event_log::EventLog)) {
    if let Some(state) = app.try_state::<EventLogState>() {
        if let Ok(mut log) = state.0.lock() {
            record(&mut log);
        }
    }
}

/// Read-only and bounded: the newest events, without addresses or names.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command]
fn get_tunnel_events(
    state: State<'_, EventLogState>,
) -> Result<event_log::TunnelEventPage, String> {
    state
        .0
        .lock()
        .map(|log| log.page())
        .map_err(|_| "event_log_unavailable".to_owned())
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct DiagnosticsOperationSlot {
    inner: Arc<OperationSlot>,
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
fn get_status() -> Result<status::DesktopStatus, status::DesktopError> {
    status::get_status()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn get_status() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("service_status"))
}

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[tauri::command(async)]
async fn get_traffic_snapshot(
) -> Result<traffic_commands::DesktopTrafficSnapshot, traffic_commands::TrafficCommandError> {
    tauri::async_runtime::spawn_blocking(traffic_commands::get_traffic_snapshot)
        .await
        .map_err(|_| {
            traffic_commands::TrafficCommandError::from(
                traffic_commands::TrafficCommandErrorCode::TrafficUnavailable,
            )
        })?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn test_website(
    input: diagnostics_commands::WebsiteTestInput,
    slot: State<'_, DiagnosticsOperationSlot>,
) -> Result<diagnostics_commands::WebsiteTestResult, diagnostics_commands::DiagnosticError> {
    let permit = Arc::clone(&slot.inner)
        .try_acquire_owned()
        .map_err(|_| diagnostics_commands::worker_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        diagnostics_commands::test_website(input)
    })
    .await
    .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn get_ip_information(
    slot: State<'_, DiagnosticsOperationSlot>,
) -> Result<diagnostics_commands::IpInformation, diagnostics_commands::DiagnosticError> {
    let permit = Arc::clone(&slot.inner)
        .try_acquire_owned()
        .map_err(|_| diagnostics_commands::worker_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        diagnostics_commands::get_ip_information()
    })
    .await
    .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn get_system_information(
) -> Result<diagnostics_commands::SystemInformation, diagnostics_commands::DiagnosticError> {
    tauri::async_runtime::spawn_blocking(diagnostics_commands::get_system_information)
        .await
        .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn set_auto_launch(enabled: bool) -> Result<bool, diagnostics_commands::DiagnosticError> {
    tauri::async_runtime::spawn_blocking(move || diagnostics_commands::set_auto_launch(enabled))
        .await
        .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn get_app_update_information(
    slot: State<'_, DiagnosticsOperationSlot>,
) -> Result<app_update::AppUpdateInformation, app_update::AppUpdateError> {
    let permit = Arc::clone(&slot.inner)
        .try_acquire_owned()
        .map_err(|_| app_update::AppUpdateError::busy())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        app_update::get_app_update_information()
    })
    .await
    .map_err(|_| app_update::AppUpdateError::worker_failed())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
fn open_app_releases_page() -> Result<(), app_update::AppUpdateError> {
    app_update::open_releases_page()
}

#[cfg(any(windows, target_os = "linux"))]
#[tauri::command(async)]
async fn get_core_update_information(
    slot: State<'_, DiagnosticsOperationSlot>,
) -> Result<diagnostics_commands::CoreUpdateInformation, diagnostics_commands::DiagnosticError> {
    let permit = Arc::clone(&slot.inner)
        .try_acquire_owned()
        .map_err(|_| diagnostics_commands::worker_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        diagnostics_commands::get_core_update_information()
    })
    .await
    .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(any(windows, target_os = "linux"))]
#[tauri::command(async)]
async fn install_core_update(
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<diagnostics_commands::CoreUpdateInformation, diagnostics_commands::DiagnosticError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| diagnostics_commands::worker_error())?;
    let leases = Arc::clone(leases.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        let resume = leases
            .active_profile()
            .map_err(|_| diagnostics_commands::core_update_failed())?;
        if resume.is_some() {
            lifecycle_commands::stop_tunnel(&leases)
                .map_err(|_| diagnostics_commands::core_update_failed())?;
        }
        let update = diagnostics_commands::install_core_update();
        if let Some(input) = resume {
            if lifecycle_commands::start_saved_profile(input, &leases).is_err() {
                return Err(diagnostics_commands::core_update_failed());
            }
        }
        update
    })
    .await
    .map_err(|_| diagnostics_commands::worker_error())?
}

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[tauri::command(async)]
async fn get_connections_page(
    input: traffic_commands::DesktopConnectionPageInput,
) -> Result<traffic_commands::DesktopConnectionPage, traffic_commands::TrafficCommandError> {
    tauri::async_runtime::spawn_blocking(move || traffic_commands::get_connections_page(input))
        .await
        .map_err(|_| {
            traffic_commands::TrafficCommandError::from(
                traffic_commands::TrafficCommandErrorCode::TrafficUnavailable,
            )
        })?
}

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[tauri::command(async)]
async fn get_mihomo_logs_page(
    input: traffic_commands::DesktopMihomoLogPageInput,
) -> Result<traffic_commands::DesktopMihomoLogPage, traffic_commands::TrafficCommandError> {
    tauri::async_runtime::spawn_blocking(move || traffic_commands::get_mihomo_logs_page(input))
        .await
        .map_err(|_| {
            traffic_commands::TrafficCommandError::from(
                traffic_commands::TrafficCommandErrorCode::TrafficUnavailable,
            )
        })?
}

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[tauri::command(async)]
async fn close_connection(
    input: traffic_commands::CloseConnectionInput,
) -> Result<traffic_commands::CloseConnectionsResult, traffic_commands::TrafficCommandError> {
    tauri::async_runtime::spawn_blocking(move || traffic_commands::close_connection(input))
        .await
        .map_err(|_| {
            traffic_commands::TrafficCommandError::from(
                traffic_commands::TrafficCommandErrorCode::TrafficUnavailable,
            )
        })?
}

#[cfg(all(
    any(windows, target_os = "linux", target_os = "macos"),
    feature = "production-service"
))]
#[tauri::command(async)]
async fn close_all_connections(
) -> Result<traffic_commands::CloseConnectionsResult, traffic_commands::TrafficCommandError> {
    tauri::async_runtime::spawn_blocking(traffic_commands::close_all_connections)
        .await
        .map_err(|_| {
            traffic_commands::TrafficCommandError::from(
                traffic_commands::TrafficCommandErrorCode::TrafficUnavailable,
            )
        })?
}

#[cfg(any(
    not(any(windows, target_os = "linux", target_os = "macos")),
    not(feature = "production-service")
))]
#[tauri::command(async)]
fn get_traffic_snapshot() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("traffic"))
}

#[cfg(any(
    not(any(windows, target_os = "linux", target_os = "macos")),
    not(feature = "production-service")
))]
#[tauri::command(async)]
fn get_connections_page(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("connections"))
}

#[cfg(any(
    not(any(windows, target_os = "linux", target_os = "macos")),
    not(feature = "production-service")
))]
#[tauri::command(async)]
fn get_mihomo_logs_page(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("mihomo_logs"))
}

#[cfg(any(
    not(any(windows, target_os = "linux", target_os = "macos")),
    not(feature = "production-service")
))]
#[tauri::command(async)]
fn close_connection(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("connections"))
}

#[cfg(any(
    not(any(windows, target_os = "linux", target_os = "macos")),
    not(feature = "production-service")
))]
#[tauri::command(async)]
fn close_all_connections() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("connections"))
}

#[cfg(target_os = "macos")]
fn platform_not_ready(capability: &'static str) -> tunbridge_desktop_contract::PlatformError {
    tunbridge_platform_macos::not_ready(capability)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn platform_not_ready(capability: &'static str) -> tunbridge_desktop_contract::PlatformError {
    tunbridge_desktop_contract::PlatformError::not_ready(std::env::consts::OS, capability)
}

#[cfg(all(windows, not(feature = "production-service")))]
fn platform_not_ready(capability: &'static str) -> tunbridge_desktop_contract::PlatformError {
    tunbridge_desktop_contract::PlatformError::not_ready("windows", capability)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn test_website(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("website_diagnostics"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn get_ip_information() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("ip_information"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn get_system_information() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("system_information"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn set_auto_launch(enabled: bool) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = enabled;
    Err(platform_not_ready("auto_launch"))
}

#[cfg(not(any(windows, target_os = "linux")))]
#[tauri::command(async)]
fn get_core_update_information() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("core_update"))
}

#[cfg(not(any(windows, target_os = "linux")))]
#[tauri::command(async)]
fn install_core_update() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("core_update"))
}

#[tauri::command(async)]
async fn discover_upstreams(
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<DiscoveryResponse, DesktopProbeError> {
    let slot = Arc::clone(slot.inner());
    let permit = slot.try_acquire_owned().map_err(DesktopProbeError::from)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        local_proxy_platform::discover_local_proxies()
    })
    .await
    .map_err(|_| local_proxy_platform::worker_failure())
}

#[tauri::command(async)]
async fn test_upstream(
    input: TestInput,
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<TestResponse, DesktopProbeError> {
    let slot = Arc::clone(slot.inner());
    let permit = slot.try_acquire_owned().map_err(DesktopProbeError::from)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        local_proxy_platform::test_local_proxy(input)
    })
    .await
    .map_err(|_| local_proxy_platform::worker_failure())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn list_profiles(
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<active_profile_store::ProfileList, profile_commands::ProfileCommandError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| profile_commands::busy_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        profile_commands::list_profiles()
    })
    .await
    .map_err(|_| profile_commands::internal_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn create_profile(
    input: active_profile_store::CreateProfileInput,
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<active_profile_store::ProfileList, profile_commands::ProfileCommandError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| profile_commands::busy_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        profile_commands::create_profile(input)
    })
    .await
    .map_err(|_| profile_commands::internal_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn update_profile(
    input: active_profile_store::UpdateProfileInput,
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<active_profile_store::ProfileList, profile_commands::ProfileCommandError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| profile_commands::busy_error())?;
    let leases = Arc::clone(leases.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        let active = leases
            .active_profile()
            .map_err(|_| profile_commands::internal_error())?;
        if profile_mutation_is_locked(
            active.as_ref().map(|profile| profile.profile_id.as_str()),
            &input.profile_id,
        ) {
            return Err(profile_commands::active_profile_locked_error());
        }
        profile_commands::update_profile(input)
    })
    .await
    .map_err(|_| profile_commands::internal_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn delete_profile(
    input: active_profile_store::DeleteProfileInput,
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<active_profile_store::ProfileList, profile_commands::ProfileCommandError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| profile_commands::busy_error())?;
    let leases = Arc::clone(leases.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        let active = leases
            .active_profile()
            .map_err(|_| profile_commands::internal_error())?;
        if profile_mutation_is_locked(
            active.as_ref().map(|profile| profile.profile_id.as_str()),
            &input.profile_id,
        ) {
            return Err(profile_commands::active_profile_locked_error());
        }
        profile_commands::delete_profile(input)
    })
    .await
    .map_err(|_| profile_commands::internal_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn profile_mutation_is_locked(active_profile_id: Option<&str>, target_profile_id: &str) -> bool {
    active_profile_id == Some(target_profile_id)
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn test_saved_profile(
    input: profile_commands::TestSavedProfileInput,
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<TestResponse, profile_commands::ProfileCommandError> {
    let permit = Arc::clone(slot.inner())
        .try_acquire_owned()
        .map_err(|_| profile_commands::busy_error())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        profile_commands::test_saved_profile(input)
    })
    .await
    .map_err(|_| profile_commands::internal_error())?
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn start_saved_profile(
    app: tauri::AppHandle,
    input: lifecycle_commands::StartSavedProfileInput,
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<(), lifecycle_commands::LifecycleCommandError> {
    let profile_id = input.profile_id.clone();
    let permit = Arc::clone(slot.inner())
        .acquire_owned_until(std::time::Duration::from_secs(3))
        .map_err(|_| {
            lifecycle_commands::LifecycleCommandError::from(
                lifecycle_commands::LifecycleCommandErrorCode::Busy,
            )
        })?;
    let leases = Arc::clone(leases.inner());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        lifecycle_commands::start_saved_profile(input, &leases)
    })
    .await
    .map_err(|_| {
        lifecycle_commands::LifecycleCommandError::from(
            lifecycle_commands::LifecycleCommandErrorCode::WorkerFailed,
        )
    })?;
    match &result {
        Ok(()) => record_event(&app, |log| log.user_started(&profile_id)),
        Err(error)
            if error.code == lifecycle_commands::LifecycleCommandErrorCode::ServiceRejected =>
        {
            record_event(&app, |log| log.user_start_failed(&profile_id));
        }
        Err(_) => {}
    }
    result
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
fn get_active_profile_id(
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<Option<String>, lifecycle_commands::LifecycleCommandError> {
    leases
        .active_profile()
        .map(|profile| profile.map(|input| input.profile_id))
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn stop_tunnel(
    app: tauri::AppHandle,
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<(), lifecycle_commands::LifecycleCommandError> {
    let permit = Arc::clone(slot.inner())
        .acquire_owned_until(std::time::Duration::from_secs(3))
        .map_err(|_| {
            lifecycle_commands::LifecycleCommandError::from(
                lifecycle_commands::LifecycleCommandErrorCode::Busy,
            )
        })?;
    let leases = Arc::clone(leases.inner());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        lifecycle_commands::stop_tunnel(&leases)
    })
    .await
    .map_err(|_| {
        lifecycle_commands::LifecycleCommandError::from(
            lifecycle_commands::LifecycleCommandErrorCode::WorkerFailed,
        )
    })?;
    if result.is_ok() {
        record_event(&app, event_log::EventLog::user_closed);
    }
    result
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
#[tauri::command(async)]
async fn recover_tunnel(
    app: tauri::AppHandle,
    slot: State<'_, Arc<OperationSlot>>,
    leases: State<'_, Arc<lifecycle_commands::LeaseManager>>,
) -> Result<(), lifecycle_commands::LifecycleCommandError> {
    let permit = Arc::clone(slot.inner())
        .acquire_owned_until(std::time::Duration::from_secs(3))
        .map_err(|_| {
            lifecycle_commands::LifecycleCommandError::from(
                lifecycle_commands::LifecycleCommandErrorCode::Busy,
            )
        })?;
    let leases = Arc::clone(leases.inner());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        lifecycle_commands::recover_tunnel(&leases)
    })
    .await
    .map_err(|_| {
        lifecycle_commands::LifecycleCommandError::from(
            lifecycle_commands::LifecycleCommandErrorCode::WorkerFailed,
        )
    })?;
    if result.is_ok() {
        record_event(&app, event_log::EventLog::user_recovered);
    }
    result
}

#[cfg(any(
    windows,
    target_os = "linux",
    all(target_os = "macos", feature = "macos-development-installer")
))]
#[tauri::command(async)]
async fn install_product(
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<(), installer_commands::InstallerCommandError> {
    let permit = Arc::clone(slot.inner()).try_acquire_owned().map_err(|_| {
        installer_commands::InstallerCommandError::from(
            installer_commands::InstallerCommandErrorCode::Busy,
        )
    })?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        installer_commands::install_product()
    })
    .await
    .map_err(|_| {
        installer_commands::InstallerCommandError::from(
            installer_commands::InstallerCommandErrorCode::WorkerFailed,
        )
    })?
}

#[cfg(any(
    windows,
    target_os = "linux",
    all(target_os = "macos", feature = "macos-development-installer")
))]
#[tauri::command(async)]
async fn uninstall_product(
    slot: State<'_, Arc<OperationSlot>>,
) -> Result<(), installer_commands::InstallerCommandError> {
    let permit = Arc::clone(slot.inner()).try_acquire_owned().map_err(|_| {
        installer_commands::InstallerCommandError::from(
            installer_commands::InstallerCommandErrorCode::Busy,
        )
    })?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = permit;
        installer_commands::uninstall_product()
    })
    .await
    .map_err(|_| {
        installer_commands::InstallerCommandError::from(
            installer_commands::InstallerCommandErrorCode::WorkerFailed,
        )
    })?
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn list_profiles() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("profile_store"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn create_profile(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("profile_store"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn update_profile(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("profile_store"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn delete_profile(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("profile_store"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn test_saved_profile(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("profile_store"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn start_saved_profile(input: Value) -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    let _ = input;
    Err(platform_not_ready("service_lifecycle"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn get_active_profile_id() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("service_lifecycle"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn stop_tunnel() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("service_lifecycle"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
#[tauri::command(async)]
fn recover_tunnel() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("service_lifecycle"))
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    all(target_os = "macos", feature = "macos-development-installer")
)))]
#[tauri::command(async)]
fn install_product() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("product_installer"))
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    all(target_os = "macos", feature = "macos-development-installer")
)))]
#[tauri::command(async)]
fn uninstall_product() -> Result<Value, tunbridge_desktop_contract::PlatformError> {
    Err(platform_not_ready("product_installer"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use status_monitor::TRAY_ID;
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
const TRAY_ID: &str = "main";

pub fn run() {
    let builder = tauri::Builder::default();
    // This must remain the first registered plugin. On Windows it prevents
    // independent UI processes from racing the service lifecycle and lease.
    #[cfg(any(windows, target_os = "macos"))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, arguments, _| {
        #[cfg(all(target_os = "macos", feature = "macos-development-installer"))]
        if run_development_action(app, &arguments) {
            return;
        }
        // A login-item launch must not reveal an already-running window. A
        // deliberate second launch should behave like clicking the tray icon.
        if !is_background_launch(arguments) {
            show_main_window(app);
        }
    }));
    let builder = builder.manage(TrayNavigationState::default());
    let builder = builder.manage(ExitRequestState::default());
    let builder = builder.manage(Arc::new(OperationSlot::default()));
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    let builder = builder.manage(DiagnosticsOperationSlot::default());
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    let builder = builder.manage(Arc::new(lifecycle_commands::LeaseManager::default()));

    #[cfg(target_os = "macos")]
    let builder = builder.menu(macos_app_menu).on_menu_event(|app, event| {
        if event.id.as_ref() == "app_quit" {
            prompt_exit(app.clone());
        }
    });

    builder
        .setup(|app| {
            restore_main_window(app);
            #[cfg(not(target_os = "macos"))]
            let icon = app
                .default_window_icon()
                .cloned()
                .expect("TunBridge window icon is required");
            #[cfg(target_os = "macos")]
            let icon = tauri::include_image!("icons/macos/tray.png");
            let tray_home = MenuItem::with_id(app, "tray_home", "首页", true, None::<&str>)?;
            let tray_settings =
                MenuItem::with_id(app, "tray_settings", "设置", true, None::<&str>)?;
            let tray_separator = PredefinedMenuItem::separator(app)?;
            let tray_exit = MenuItem::with_id(app, "tray_exit", "退出", true, None::<&str>)?;
            let tray_menu = Menu::with_items(
                app,
                &[&tray_home, &tray_settings, &tray_separator, &tray_exit],
            )?;
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(icon)
                .icon_as_template(cfg!(target_os = "macos"))
                .tooltip("TunBridge")
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "tray_home" => open_tray_destination(app, "overview"),
                    "tray_settings" => open_tray_destination(app, "settings"),
                    "tray_exit" => prompt_exit(app.clone()),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            #[cfg(windows)]
            install_update_exit_listener(app.handle().clone())?;
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            {
                let path = app
                    .path()
                    .app_local_data_dir()
                    .ok()
                    .map(|directory| directory.join(event_log::FILE_NAME));
                app.manage(EventLogState(std::sync::Mutex::new(
                    event_log::EventLog::open(path),
                )));
                status_monitor::spawn(app.handle().clone());
            }
            let background = is_background_launch(std::env::args());
            if background {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            #[cfg(target_os = "macos")]
            if !background {
                // Monterey can finish constructing the WKWebView without
                // ordering its NSWindow front when launched by LaunchServices.
                show_main_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                match event {
                    WindowEvent::Resized(_) => persist_main_window(window),
                    WindowEvent::CloseRequested { api, .. } => {
                        persist_main_window(window);
                        api.prevent_close();
                        let _ = window.hide();
                    }
                    _ => {}
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            take_pending_tray_navigation,
            get_traffic_snapshot,
            get_connections_page,
            get_mihomo_logs_page,
            close_connection,
            close_all_connections,
            test_website,
            get_ip_information,
            get_system_information,
            set_auto_launch,
            get_app_update_information,
            open_app_releases_page,
            get_core_update_information,
            install_core_update,
            discover_upstreams,
            test_upstream,
            list_profiles,
            create_profile,
            update_profile,
            delete_profile,
            test_saved_profile,
            start_saved_profile,
            get_active_profile_id,
            stop_tunnel,
            recover_tunnel,
            install_product,
            uninstall_product,
            confirm_exit,
            get_tunnel_events
        ])
        .build(tauri::generate_context!())
        .expect("TunBridge desktop runtime failed")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if matches!(event, tauri::RunEvent::Reopen { .. }) {
                // LaunchServices may reactivate the existing login-item
                // process without spawning a second process.
                show_main_window(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}

#[cfg(test)]
mod launch_argument_tests {
    use super::{
        is_background_launch, profile_mutation_is_locked, ExitRequestState, TrayNavigationState,
    };

    #[test]
    fn detects_login_item_launch() {
        assert!(is_background_launch([
            "/Applications/TunBridge.app/Contents/MacOS/tunbridge-desktop",
            "--background",
        ]));
    }

    #[test]
    fn ordinary_launch_is_visible() {
        assert!(!is_background_launch([
            "/Applications/TunBridge.app/Contents/MacOS/tunbridge-desktop",
        ]));
    }

    #[test]
    fn pending_tray_navigation_is_consumed_once() {
        let state = TrayNavigationState::default();
        state.queue("overview");
        state.queue("settings");
        assert_eq!(state.take(), Some("settings"));
        assert_eq!(state.take(), None);
    }

    #[test]
    fn duplicate_exit_requests_are_suppressed_until_failure_finishes() {
        let state = ExitRequestState::default();
        assert!(state.begin());
        assert!(!state.begin());
        state.finish();
        assert!(state.begin());
    }

    #[test]
    fn only_the_active_profile_is_locked_for_mutation() {
        assert!(profile_mutation_is_locked(Some("profile-a"), "profile-a"));
        assert!(!profile_mutation_is_locked(Some("profile-a"), "profile-b"));
        assert!(!profile_mutation_is_locked(None, "profile-a"));
    }
}
