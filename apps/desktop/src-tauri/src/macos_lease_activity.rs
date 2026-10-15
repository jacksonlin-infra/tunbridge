use objc2::{rc::Retained, runtime::ProtocolObject};
use objc2_foundation::{NSActivityOptions, NSObjectProtocol, NSProcessInfo, NSString};

// Avoid App Nap without preventing the user from putting the Mac to sleep.
const OPTIONS: NSActivityOptions = NSActivityOptions::UserInitiatedAllowingIdleSystemSleep;

pub(crate) struct LeaseActivity {
    process_info: Retained<NSProcessInfo>,
    token: Retained<ProtocolObject<dyn NSObjectProtocol>>,
}

impl LeaseActivity {
    pub(crate) fn new() -> Self {
        let process_info = NSProcessInfo::processInfo();
        let reason = NSString::from_str("Keep the user-owned TunBridge tunnel lease alive");
        let token = process_info.beginActivityWithOptions_reason(OPTIONS, &reason);
        Self {
            process_info,
            token,
        }
    }
}

impl Drop for LeaseActivity {
    fn drop(&mut self) {
        // SAFETY: this exact retained token came from beginActivity on this
        // process_info instance and is ended once, when the worker exits.
        unsafe { self.process_info.endActivity(&self.token) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_activity_allows_system_and_display_sleep() {
        assert!(!OPTIONS.contains(NSActivityOptions::IdleSystemSleepDisabled));
        assert!(!OPTIONS.contains(NSActivityOptions::IdleDisplaySleepDisabled));
        assert_eq!(
            OPTIONS,
            NSActivityOptions::UserInitiatedAllowingIdleSystemSleep
        );
    }

    #[test]
    fn native_activity_can_begin_and_end_on_a_worker_thread() {
        std::thread::spawn(|| {
            objc2::rc::autoreleasepool(|_| {
                let activity = LeaseActivity::new();
                drop(activity);
                // Starting another activity also exercises the balanced end path.
                let _next = LeaseActivity::new();
            });
        })
        .join()
        .expect("native lease activity worker should exit cleanly");
    }
}
