//! System power facts delivered through the SCM control handler.
//!
//! The Desktop renews its lease from a user-mode thread that Windows freezes
//! during sleep and suspends through the Desktop Activity Moderator while a
//! Modern Standby system has its display off. The service keeps running in
//! that state, so lease ticks pause while the system is in low power and the
//! lease gets a bounded grace when it returns.
//!
//! NDIS also brings every miniport, including the Wintun adapter, back through
//! a power transition on wake. For a few seconds the TUN interface is not
//! reported as up and connected even though it was never removed, so the
//! runtime watchdog must not treat adapter or controller loss as final while
//! the system sleeps or right after it wakes.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::watchdog::{HealthSignal, RuntimeObservation};

#[derive(Debug, Default)]
pub(super) struct PowerState {
    suspended: AtomicBool,
    display_off: AtomicBool,
    resume_pending: AtomicBool,
    watchdog_wake_pending: AtomicBool,
}

pub(super) static POWER: PowerState = PowerState {
    suspended: AtomicBool::new(false),
    display_off: AtomicBool::new(false),
    resume_pending: AtomicBool::new(false),
    watchdog_wake_pending: AtomicBool::new(false),
};

/// GUID_CONSOLE_DISPLAY_STATE payload values.
const DISPLAY_OFF: u32 = 0;

/// Watchdog ticks (one second each) after a wake during which adapter and
/// controller loss is not acted on. Adapter loss still converges after the
/// hold once the regular consecutive-failure threshold is met.
pub(super) const WATCHDOG_WAKE_HOLD_TICKS: u32 = 20;

/// Growth of interrupt-time bias between two watchdog ticks that proves the
/// system slept, in 100 ns units (2 seconds).
const SLEEP_BIAS_THRESHOLD: u64 = 20_000_000;

impl PowerState {
    pub(super) fn suspend(&self) {
        self.suspended.store(true, Ordering::SeqCst);
    }

    pub(super) fn resume(&self) {
        self.suspended.store(false, Ordering::SeqCst);
        self.resume_pending.store(true, Ordering::SeqCst);
        self.watchdog_wake_pending.store(true, Ordering::SeqCst);
    }

    pub(super) fn display_state(&self, state: u32) {
        let off = state == DISPLAY_OFF;
        let was_off = self.display_off.swap(off, Ordering::SeqCst);
        if was_off && !off {
            self.resume_pending.store(true, Ordering::SeqCst);
            self.watchdog_wake_pending.store(true, Ordering::SeqCst);
        }
    }

    pub(super) fn suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Consumes a pending wake for the runtime watchdog. Independent of the
    /// lease so neither consumer can swallow the other's grace.
    pub(super) fn take_watchdog_wake(&self) -> bool {
        self.watchdog_wake_pending.swap(false, Ordering::SeqCst)
    }

    /// Lease ticks do not advance while the Desktop may be frozen.
    pub(super) fn lease_clock_paused(&self) -> bool {
        self.suspended.load(Ordering::SeqCst) || self.display_off.load(Ordering::SeqCst)
    }

    /// Consumes a pending wake so the lease receives one resume grace.
    pub(super) fn take_resume(&self) -> bool {
        self.resume_pending.swap(false, Ordering::SeqCst)
    }
}

/// Detects that the system slept between two samples without relying on the
/// SCM power broadcast, which can arrive after service threads resume.
///
/// Interrupt time advances during sleep while unbiased interrupt time does
/// not, so their difference only grows across a sleep.
#[derive(Debug, Default)]
pub(super) struct SleepClock {
    last_bias: Option<u64>,
}

impl SleepClock {
    pub(super) fn sample(&mut self) -> bool {
        self.observe(sleep_bias())
    }

    fn observe(&mut self, bias: Option<u64>) -> bool {
        let Some(bias) = bias else {
            return false;
        };
        let slept = self
            .last_bias
            .is_some_and(|last| bias.saturating_sub(last) > SLEEP_BIAS_THRESHOLD);
        self.last_bias = Some(bias);
        slept
    }
}

fn sleep_bias() -> Option<u64> {
    use windows_sys::Win32::System::WindowsProgramming::{
        QueryInterruptTime, QueryUnbiasedInterruptTime,
    };

    let mut unbiased = 0_u64;
    // SAFETY: unbiased is writable storage for the returned 100 ns count.
    if unsafe { QueryUnbiasedInterruptTime(&mut unbiased) } == 0 {
        return None;
    }
    let mut interrupt = 0_u64;
    // SAFETY: interrupt is writable storage for the returned 100 ns count.
    unsafe { QueryInterruptTime(&mut interrupt) };
    interrupt.checked_sub(unbiased)
}

/// Masks wake-transient adapter and controller samples for the watchdog.
///
/// Engine exit stays authoritative, and upstream loss only degrades the
/// session, so neither is masked.
#[derive(Debug, Default)]
pub(super) struct WakeHold {
    remaining: u32,
}

impl WakeHold {
    pub(super) fn apply(
        &mut self,
        suspended: bool,
        woke: bool,
        observation: RuntimeObservation,
    ) -> RuntimeObservation {
        if suspended || woke {
            self.remaining = WATCHDOG_WAKE_HOLD_TICKS;
        }
        if !suspended {
            if self.remaining == 0 {
                return observation;
            }
            self.remaining -= 1;
        }
        RuntimeObservation {
            controller: hold_signal(observation.controller),
            adapter: hold_signal(observation.adapter),
            ..observation
        }
    }
}

fn hold_signal(signal: HealthSignal) -> HealthSignal {
    match signal {
        HealthSignal::Healthy => HealthSignal::Healthy,
        HealthSignal::Unhealthy | HealthSignal::Unknown | HealthSignal::NotSampled => {
            HealthSignal::NotSampled
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_and_display_off_pause_lease_ticks_until_one_resume() {
        let power = PowerState::default();
        assert!(!power.lease_clock_paused());
        power.suspend();
        assert!(power.lease_clock_paused());
        power.resume();
        assert!(!power.lease_clock_paused());
        assert!(power.take_resume());
        assert!(!power.take_resume());

        power.display_state(DISPLAY_OFF);
        assert!(power.lease_clock_paused());
        assert!(!power.take_resume());
        power.display_state(2); // dimmed is still on
        assert!(!power.lease_clock_paused());
        assert!(power.take_resume());
        power.display_state(1);
        assert!(!power.take_resume());
    }

    #[test]
    fn lease_and_watchdog_consume_wakes_independently() {
        let power = PowerState::default();
        power.suspend();
        assert!(power.suspended());
        power.resume();
        assert!(!power.suspended());
        assert!(power.take_resume());
        assert!(power.take_watchdog_wake());
        assert!(!power.take_watchdog_wake());

        power.display_state(DISPLAY_OFF);
        power.display_state(1);
        assert!(power.take_watchdog_wake());
        assert!(power.take_resume());
    }

    #[test]
    fn sleep_clock_reports_only_a_bias_jump() {
        let mut clock = SleepClock::default();
        assert!(!clock.observe(Some(1_000)));
        assert!(!clock.observe(Some(1_000 + SLEEP_BIAS_THRESHOLD)));
        assert!(clock.observe(Some(2_000 + 2 * SLEEP_BIAS_THRESHOLD)));
        assert!(!clock.observe(None));
        assert!(!clock.observe(Some(2_000 + 2 * SLEEP_BIAS_THRESHOLD)));
        // The live clock pair is readable and never reports a sleep across
        // two immediate samples.
        let mut live = SleepClock::default();
        assert!(sleep_bias().is_some());
        live.sample();
        assert!(!live.sample());
    }

    #[test]
    fn wake_hold_masks_only_adapter_and_controller_loss() {
        let lost = RuntimeObservation {
            engine: HealthSignal::Unhealthy,
            upstream: HealthSignal::Unhealthy,
            controller: HealthSignal::Unhealthy,
            adapter: HealthSignal::Unknown,
        };
        let mut hold = WakeHold::default();
        assert_eq!(hold.apply(false, false, lost), lost);

        let held = hold.apply(true, false, lost);
        assert_eq!(held.engine, HealthSignal::Unhealthy);
        assert_eq!(held.upstream, HealthSignal::Unhealthy);
        assert_eq!(held.controller, HealthSignal::NotSampled);
        assert_eq!(held.adapter, HealthSignal::NotSampled);
        assert_eq!(
            hold.apply(false, false, RuntimeObservation::healthy()),
            RuntimeObservation::healthy()
        );
    }

    #[test]
    fn adapter_reconnecting_after_wake_does_not_restore_the_network() {
        use crate::{
            state::{Phase, WatchdogReason},
            watchdog::{WatchdogDecision, WatchdogPolicy},
        };

        let adapter_down = RuntimeObservation {
            adapter: HealthSignal::Unhealthy,
            ..RuntimeObservation::healthy()
        };
        let mut policy = WatchdogPolicy::default();
        let mut hold = WakeHold::default();

        // Wake from S3: the adapter reports down on the first samples.
        let mut woke = true;
        for _ in 0..WATCHDOG_WAKE_HOLD_TICKS {
            let observation = hold.apply(false, woke, adapter_down);
            woke = false;
            assert_eq!(
                policy.evaluate(Phase::Running, observation),
                WatchdogDecision::Healthy
            );
        }
        // An adapter that is really gone is still restarted after the hold.
        let observation = hold.apply(false, false, adapter_down);
        assert!(matches!(
            policy.evaluate(Phase::Running, observation),
            WatchdogDecision::Hold { .. }
        ));
        let observation = hold.apply(false, false, adapter_down);
        assert_eq!(
            policy.evaluate(Phase::Running, observation),
            WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing)
        );
    }
}
