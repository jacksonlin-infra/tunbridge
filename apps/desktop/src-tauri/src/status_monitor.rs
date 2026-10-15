//! Background status watcher.
//!
//! The WebView polls status only while the window is visible, so an automatic
//! stop or a blocked upstream would otherwise go unnoticed while TunBridge sits
//! in the tray. This watcher keeps the tray tooltip current and raises a system
//! notification for decisions the service made on its own.

use std::{thread, time::Duration};

use tauri::{AppHandle, Manager};
use tunbridge_service::state::{Phase, WatchdogReason};

use crate::status::{self, DesktopStatus};

pub(crate) const TRAY_ID: &str = "main";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(any(windows, target_os = "macos"))]
const APP_IDENTIFIER: &str = "com.tunbridge.desktop";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelView {
    Unavailable,
    Stopped,
    Busy,
    Running,
    Degraded,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Alert {
    pub title: &'static str,
    pub body: &'static str,
}

/// Tracks the last observed status of the session this Desktop owns and
/// reports only transitions the user did not cause. A relaunched Desktop also
/// reports the stop it finds on its first sample, since nobody saw it happen.
#[derive(Debug, Default)]
pub(crate) struct StatusMonitor {
    owned_session: bool,
    degraded: Option<WatchdogReason>,
    observed: bool,
}

impl StatusMonitor {
    pub(crate) fn observe(
        &mut self,
        status: Option<&DesktopStatus>,
    ) -> (TunnelView, Option<Alert>) {
        let Some(status) = status else {
            // The service may be restarting or upgrading; keep the session
            // facts and let the next successful sample decide.
            return (TunnelView::Unavailable, None);
        };
        let first_sample = !self.observed;
        self.observed = true;
        match status.service_phase() {
            Phase::Running => {
                if status.caller_is_owner() {
                    self.owned_session = true;
                }
                let degraded = status.degraded_reason();
                let alert = match (self.owned_session, self.degraded, degraded) {
                    (true, previous, Some(reason)) if previous != Some(reason) => {
                        Some(degraded_alert(reason))
                    }
                    (true, Some(previous), None) => Some(resumed_alert(previous)),
                    _ => None,
                };
                self.degraded = degraded;
                let view = if degraded.is_some() {
                    TunnelView::Degraded
                } else {
                    TunnelView::Running
                };
                (view, alert)
            }
            Phase::Starting | Phase::Stopping | Phase::Recovering => (TunnelView::Busy, None),
            phase @ (Phase::Stopped | Phase::Faulted) => {
                let alert = if self.owned_session || first_sample {
                    status
                        .stop_reason()
                        .map(|reason| stopped_alert(reason, phase == Phase::Faulted))
                } else {
                    None
                };
                self.owned_session = false;
                self.degraded = None;
                let view = if phase == Phase::Faulted {
                    TunnelView::Faulted
                } else {
                    TunnelView::Stopped
                };
                (view, alert)
            }
        }
    }
}

const DEGRADED: Alert = Alert {
    title: "上游代理不可达",
    body: "系统 TUN 保持开启，流量已阻断而不会直连；代理恢复后自动继续。",
};

const RESUMED: Alert = Alert {
    title: "上游代理已恢复",
    body: "流量已恢复经由上游代理转发。",
};

/// The session keeps running through every degradation; nothing here ever
/// stops the tunnel.
fn degraded_alert(reason: WatchdogReason) -> Alert {
    match reason {
        WatchdogReason::UpstreamUnavailable => DEGRADED,
        WatchdogReason::EngineExited | WatchdogReason::AdapterMissing => Alert {
            title: "隧道内核意外退出，正在重启",
            body: "隧道保持开启，流量不会直连；内核重启完成后自动恢复。",
        },
        WatchdogReason::ControllerUnavailable => Alert {
            title: "隧道内核无响应",
            body: "隧道保持开启，流量不会直连；内核恢复响应后自动继续。",
        },
        WatchdogReason::RuntimeIdentityMismatch
        | WatchdogReason::LeaseExpired
        | WatchdogReason::ConnectionStorm => Alert {
            title: "隧道运行异常",
            body: "隧道保持开启，流量不会直连。请打开 TunBridge 查看。",
        },
    }
}

fn resumed_alert(previous: WatchdogReason) -> Alert {
    match previous {
        WatchdogReason::UpstreamUnavailable => RESUMED,
        _ => Alert {
            title: "隧道已恢复",
            body: "流量已恢复经由上游代理转发。",
        },
    }
}

fn stopped_alert(reason: WatchdogReason, faulted: bool) -> Alert {
    let title = match reason {
        WatchdogReason::LeaseExpired => "TunBridge 失去响应，隧道已自动停止",
        WatchdogReason::EngineExited => "隧道内核意外退出",
        WatchdogReason::ControllerUnavailable => "隧道内核无响应",
        WatchdogReason::AdapterMissing => "隧道网卡已消失",
        WatchdogReason::RuntimeIdentityMismatch => "无法验证正在运行的隧道",
        WatchdogReason::UpstreamUnavailable => "上游代理不可用，隧道已停止",
        WatchdogReason::ConnectionStorm => "检测到连接风暴，隧道已停止",
    };
    let body = if faulted {
        "隧道保持原状，流量不会直连。请打开 TunBridge 恢复网络。"
    } else {
        "TunBridge 已还原之前的网络状态。请打开 TunBridge 重新开启隧道。"
    };
    Alert { title, body }
}

fn tooltip(view: TunnelView) -> &'static str {
    match view {
        TunnelView::Unavailable => "TunBridge · 服务不可用",
        TunnelView::Stopped => "TunBridge · 已停止",
        TunnelView::Busy => "TunBridge · 处理中",
        TunnelView::Running => "TunBridge · 运行中",
        TunnelView::Degraded => "TunBridge · 异常，流量已阻断，等待恢复",
        TunnelView::Faulted => "TunBridge · 需要处理",
    }
}

pub(crate) fn spawn(app: AppHandle) {
    prepare_notifications();
    let _ = thread::Builder::new()
        .name("tunbridge-status-monitor".to_owned())
        .spawn(move || {
            let mut monitor = StatusMonitor::default();
            let mut last_view = None;
            loop {
                let status = status::get_status().ok();
                // The service keeps an owned session running while this App
                // is gone; after a relaunch, take its lease back.
                if status.as_ref().is_some_and(|status| {
                    status.service_phase() == Phase::Running && status.caller_is_owner()
                }) {
                    let leases =
                        app.state::<std::sync::Arc<crate::lifecycle_commands::LeaseManager>>();
                    let _ = leases.ensure_attached();
                }
                let observation = status.as_ref().map(event_observation);
                crate::record_event(&app, |log| log.observe(observation));
                #[cfg(feature = "production-service")]
                if observation.is_some_and(|observed| {
                    observed.owned && observed.phase == crate::event_log::ObservedPhase::Running
                }) {
                    sample_session_traffic(&app);
                }
                let (view, alert) = monitor.observe(status.as_ref());
                if last_view != Some(view) {
                    if let Some(tray) = app.tray_by_id(TRAY_ID) {
                        let _ = tray.set_tooltip(Some(tooltip(view)));
                    }
                    last_view = Some(view);
                }
                if let Some(alert) = alert {
                    show_notification(alert);
                }
                thread::sleep(POLL_INTERVAL);
            }
        });
}

fn event_observation(status: &DesktopStatus) -> crate::event_log::Observation {
    use crate::event_log::ObservedPhase;
    let (phase, phase_name) = match status.service_phase() {
        Phase::Running => (ObservedPhase::Running, "running"),
        Phase::Starting => (ObservedPhase::Busy, "starting"),
        Phase::Stopping => (ObservedPhase::Busy, "stopping"),
        Phase::Recovering => (ObservedPhase::Busy, "recovering"),
        Phase::Stopped => (ObservedPhase::Stopped, "stopped"),
        Phase::Faulted => (ObservedPhase::Faulted, "faulted"),
    };
    crate::event_log::Observation {
        phase,
        phase_name,
        owned: status.caller_is_owner(),
        degraded: status.degraded_reason().map(reason_code),
        stop_reason: status.stop_reason().map(reason_code),
    }
}

fn reason_code(reason: WatchdogReason) -> &'static str {
    match reason {
        WatchdogReason::EngineExited => "engine_exited",
        WatchdogReason::UpstreamUnavailable => "upstream_unavailable",
        WatchdogReason::ControllerUnavailable => "controller_unavailable",
        WatchdogReason::AdapterMissing => "adapter_missing",
        WatchdogReason::RuntimeIdentityMismatch => "runtime_identity_mismatch",
        WatchdogReason::LeaseExpired => "lease_expired",
        WatchdogReason::ConnectionStorm => "connection_storm",
    }
}

/// Keeps the session's traffic totals so a stop can record them; the engine
/// is gone by the time the stop is observed.
#[cfg(feature = "production-service")]
fn sample_session_traffic(app: &AppHandle) {
    let Ok(snapshot) = crate::traffic_commands::get_traffic_snapshot() else {
        return;
    };
    let Ok(value) = serde_json::to_value(&snapshot) else {
        return;
    };
    let generation = value
        .get("engineGeneration")
        .and_then(|value| value.as_str());
    let download = value.get("downloadTotal").and_then(|value| value.as_u64());
    let upload = value.get("uploadTotal").and_then(|value| value.as_u64());
    if let (Some(generation), Some(download), Some(upload)) = (generation, download, upload) {
        crate::record_event(app, |log| log.sample_traffic(generation, download, upload));
    }
}

fn show_notification(alert: Alert) {
    let mut notification = notify_rust::Notification::new();
    notification.summary(alert.title).body(alert.body);
    #[cfg(windows)]
    notification.app_id(APP_IDENTIFIER);
    #[cfg(target_os = "linux")]
    notification.appname("TunBridge").icon("tunbridge-desktop");
    let _ = notification.show();
}

#[cfg(target_os = "macos")]
fn prepare_notifications() {
    // Without an explicit bundle the notification backend posts as Finder.
    let _ = notify_rust::set_application(APP_IDENTIFIER);
}

/// Unpackaged Win32 apps need a registered AppUserModelID for toasts; the
/// Setup shortcuts do not carry one, so register it for the current user.
#[cfg(windows)]
fn prepare_notifications() {
    use windows_sys::Win32::{
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
            REG_OPTION_NON_VOLATILE, REG_SZ,
        },
        UI::Shell::SetCurrentProcessExplicitAppUserModelID,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let id = wide(APP_IDENTIFIER);
    // SAFETY: id is a NUL-terminated UTF-16 string valid for the call.
    unsafe {
        SetCurrentProcessExplicitAppUserModelID(id.as_ptr());
    }
    let subkey = wide(&format!(
        r"Software\Classes\AppUserModelId\{APP_IDENTIFIER}"
    ));
    let name = wide("DisplayName");
    let value = wide("TunBridge");
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: all pointers reference live NUL-terminated buffers; the key is
    // closed below and only the fixed DisplayName value is written.
    unsafe {
        if RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        ) == 0
        {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr() as *const u8,
                (value.len() * std::mem::size_of::<u16>()) as u32,
            );
            RegCloseKey(key);
        }
    }
}

#[cfg(target_os = "linux")]
fn prepare_notifications() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(owner: bool, degraded: bool) -> DesktopStatus {
        DesktopStatus::for_test(
            Phase::Running,
            owner,
            None,
            degraded.then_some(WatchdogReason::UpstreamUnavailable),
        )
    }

    #[test]
    fn manual_stop_and_unowned_sessions_stay_quiet() {
        let mut monitor = StatusMonitor::default();
        assert_eq!(monitor.observe(Some(&running(true, false))).1, None);
        let stopped = DesktopStatus::for_test(Phase::Stopped, false, None, None);
        assert_eq!(monitor.observe(Some(&stopped)), (TunnelView::Stopped, None));

        let mut other = StatusMonitor::default();
        other.observe(Some(&running(false, false)));
        let auto = DesktopStatus::for_test(
            Phase::Stopped,
            false,
            Some(WatchdogReason::LeaseExpired),
            None,
        );
        assert_eq!(other.observe(Some(&auto)).1, None);
    }

    #[test]
    fn degraded_upstream_alerts_once_and_announces_recovery() {
        let mut monitor = StatusMonitor::default();
        monitor.observe(Some(&running(true, false)));
        assert_eq!(
            monitor.observe(Some(&running(true, true))),
            (TunnelView::Degraded, Some(DEGRADED))
        );
        assert_eq!(monitor.observe(Some(&running(true, true))).1, None);
        assert_eq!(monitor.observe(None), (TunnelView::Unavailable, None));
        assert_eq!(monitor.observe(Some(&running(true, true))).1, None);
        assert_eq!(
            monitor.observe(Some(&running(true, false))),
            (TunnelView::Running, Some(RESUMED))
        );
    }

    #[test]
    fn engine_restart_alerts_with_its_own_reason_and_recovery() {
        let mut monitor = StatusMonitor::default();
        monitor.observe(Some(&running(true, false)));
        let restarting = DesktopStatus::for_test(
            Phase::Running,
            true,
            None,
            Some(WatchdogReason::EngineExited),
        );
        let (view, alert) = monitor.observe(Some(&restarting));
        assert_eq!(view, TunnelView::Degraded);
        assert!(alert.unwrap().body.contains("不会直连"));
        assert_eq!(monitor.observe(Some(&restarting)).1, None);
        // A different reason is a new event.
        assert_eq!(
            monitor.observe(Some(&running(true, true))).1,
            Some(DEGRADED)
        );
        assert_eq!(
            monitor.observe(Some(&running(true, false))).1,
            Some(RESUMED)
        );
    }

    #[test]
    fn relaunched_desktop_reports_a_stop_it_did_not_see() {
        let mut monitor = StatusMonitor::default();
        let stopped = DesktopStatus::for_test(
            Phase::Stopped,
            false,
            Some(WatchdogReason::EngineExited),
            None,
        );
        assert!(monitor.observe(Some(&stopped)).1.is_some());
        assert_eq!(monitor.observe(Some(&stopped)).1, None);
    }

    #[test]
    fn automatic_stop_and_fault_of_the_owned_session_alert() {
        let mut monitor = StatusMonitor::default();
        monitor.observe(Some(&running(true, false)));
        let busy = DesktopStatus::for_test(Phase::Recovering, false, None, None);
        assert_eq!(monitor.observe(Some(&busy)), (TunnelView::Busy, None));
        let stopped = DesktopStatus::for_test(
            Phase::Stopped,
            false,
            Some(WatchdogReason::EngineExited),
            None,
        );
        let (view, alert) = monitor.observe(Some(&stopped));
        assert_eq!(view, TunnelView::Stopped);
        assert_eq!(alert.unwrap().title, "隧道内核意外退出");
        assert_eq!(monitor.observe(Some(&stopped)).1, None);

        monitor.observe(Some(&running(true, false)));
        let faulted = DesktopStatus::for_test(
            Phase::Faulted,
            false,
            Some(WatchdogReason::RuntimeIdentityMismatch),
            None,
        );
        let (view, alert) = monitor.observe(Some(&faulted));
        assert_eq!(view, TunnelView::Faulted);
        assert!(alert.unwrap().body.contains("不会直连"));
    }
}
