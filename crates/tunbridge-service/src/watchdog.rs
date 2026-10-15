//! Pure runtime watchdog policy.
//!
//! Platform samplers provide bounded facts; this module applies fixed,
//! per-signal hysteresis and never performs process or network side effects.

use crate::state::{Phase, WatchdogReason};

pub const ENGINE_FAILURE_THRESHOLD: u8 = 1;
pub const UPSTREAM_FAILURE_THRESHOLD: u8 = 3;
pub const CONTROLLER_FAILURE_THRESHOLD: u8 = 3;
pub const ADAPTER_FAILURE_THRESHOLD: u8 = 2;
pub const UNKNOWN_FAILURE_THRESHOLD: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthSignal {
    Healthy,
    Unhealthy,
    Unknown,
    /// This signal is intentionally not sampled on the current scheduler
    /// tick. Its existing streak is preserved without incrementing it.
    NotSampled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeObservation {
    pub engine: HealthSignal,
    pub upstream: HealthSignal,
    pub controller: HealthSignal,
    pub adapter: HealthSignal,
}

impl RuntimeObservation {
    pub const fn healthy() -> Self {
        Self {
            engine: HealthSignal::Healthy,
            upstream: HealthSignal::Healthy,
            controller: HealthSignal::Healthy,
            adapter: HealthSignal::Healthy,
        }
    }

    pub const fn engine_only(engine: HealthSignal) -> Self {
        Self {
            engine,
            upstream: HealthSignal::NotSampled,
            controller: HealthSignal::NotSampled,
            adapter: HealthSignal::NotSampled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogDecision {
    Dormant,
    Healthy,
    Hold {
        reason: WatchdogReason,
        consecutive: u8,
        threshold: u8,
    },
    /// The owned engine or its adapter is gone. The platform restarts the
    /// engine for the same session; it never tears the session down.
    RestartEngine(WatchdogReason),
    FaultClosed(WatchdogReason),
    /// The owned engine and adapter are intact but the upstream is unusable.
    /// The tunnel must stay up so traffic fails closed instead of escaping
    /// directly; the platform reports the reason until a healthy sample.
    Degraded(WatchdogReason),
}

/// Watchdog ticks after a system wake during which adapter and controller
/// loss is not acted on. Drivers and the engine can need several seconds to
/// bring the TUN back; restarting the engine meanwhile only delays that.
pub const WAKE_HOLD_TICKS: u32 = 20;

/// Masks adapter and controller failures while the system is suspended and
/// for `WAKE_HOLD_TICKS` after it wakes. Engine exit and the upstream signal
/// pass through unchanged; existing streaks are preserved, so a loss that
/// outlasts the hold is still acted on.
#[derive(Debug, Default)]
pub struct WakeHold {
    remaining: u32,
}

impl WakeHold {
    pub fn apply(
        &mut self,
        suspended: bool,
        woke: bool,
        observation: RuntimeObservation,
    ) -> RuntimeObservation {
        if suspended || woke {
            self.remaining = WAKE_HOLD_TICKS;
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

#[derive(Debug, Default)]
pub struct WatchdogPolicy {
    engine: SignalStreak,
    upstream: SignalStreak,
    controller: SignalStreak,
    adapter: SignalStreak,
}

impl WatchdogPolicy {
    pub fn evaluate(&mut self, phase: Phase, observation: RuntimeObservation) -> WatchdogDecision {
        if phase != Phase::Running {
            self.reset();
            return WatchdogDecision::Dormant;
        }

        let engine = self.engine.observe(observation.engine);
        let upstream = self.upstream.observe(observation.upstream);
        let controller = self.controller.observe(observation.controller);
        let adapter = self.adapter.observe(observation.adapter);

        // Unknown means the service cannot prove runtime identity or asset
        // state. It has priority over availability cleanup because terminating
        // or deleting an unverified target would cross the ownership boundary.
        let unknown = [engine, upstream, controller, adapter]
            .into_iter()
            .filter_map(StreakCount::unknown)
            .max()
            .unwrap_or(0);
        if unknown >= UNKNOWN_FAILURE_THRESHOLD {
            return WatchdogDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch);
        }
        if unknown > 0 {
            return WatchdogDecision::Hold {
                reason: WatchdogReason::RuntimeIdentityMismatch,
                consecutive: unknown,
                threshold: UNKNOWN_FAILURE_THRESHOLD,
            };
        }

        // Tearing the tunnel down for any of these would restore the original
        // routes and send traffic directly. A dead engine or a lost adapter is
        // restarted; everything else keeps the tunnel up and fails closed.
        if engine.unhealthy >= ENGINE_FAILURE_THRESHOLD {
            return WatchdogDecision::RestartEngine(WatchdogReason::EngineExited);
        }
        if adapter.unhealthy >= ADAPTER_FAILURE_THRESHOLD {
            return WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing);
        }
        // A busy engine can stop answering its controller while it still
        // forwards traffic; killing it would only make things worse.
        if controller.unhealthy >= CONTROLLER_FAILURE_THRESHOLD {
            return WatchdogDecision::Degraded(WatchdogReason::ControllerUnavailable);
        }
        if upstream.unhealthy >= UPSTREAM_FAILURE_THRESHOLD {
            return WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable);
        }

        for (count, threshold, reason) in [
            (
                upstream.unhealthy,
                UPSTREAM_FAILURE_THRESHOLD,
                WatchdogReason::UpstreamUnavailable,
            ),
            (
                controller.unhealthy,
                CONTROLLER_FAILURE_THRESHOLD,
                WatchdogReason::ControllerUnavailable,
            ),
            (
                adapter.unhealthy,
                ADAPTER_FAILURE_THRESHOLD,
                WatchdogReason::AdapterMissing,
            ),
        ] {
            if count > 0 {
                return WatchdogDecision::Hold {
                    reason,
                    consecutive: count,
                    threshold,
                };
            }
        }
        WatchdogDecision::Healthy
    }

    pub fn reset(&mut self) {
        self.engine.reset();
        self.upstream.reset();
        self.controller.reset();
        self.adapter.reset();
    }
}

#[derive(Debug, Default)]
struct SignalStreak {
    signal: Option<HealthSignal>,
    count: u8,
}

impl SignalStreak {
    fn observe(&mut self, signal: HealthSignal) -> StreakCount {
        if signal == HealthSignal::NotSampled {
            return self.current();
        }
        if signal == HealthSignal::Healthy {
            self.reset();
            return StreakCount::default();
        }
        if self.signal == Some(signal) {
            self.count = self.count.saturating_add(1);
        } else {
            self.signal = Some(signal);
            self.count = 1;
        }
        match signal {
            HealthSignal::Healthy => StreakCount::default(),
            HealthSignal::Unhealthy => StreakCount {
                unhealthy: self.count,
                unknown: 0,
            },
            HealthSignal::Unknown => StreakCount {
                unhealthy: 0,
                unknown: self.count,
            },
            HealthSignal::NotSampled => unreachable!("handled before streak mutation"),
        }
    }

    fn current(&self) -> StreakCount {
        match self.signal {
            Some(HealthSignal::Unhealthy) => StreakCount {
                unhealthy: self.count,
                unknown: 0,
            },
            Some(HealthSignal::Unknown) => StreakCount {
                unhealthy: 0,
                unknown: self.count,
            },
            Some(HealthSignal::Healthy) | Some(HealthSignal::NotSampled) | None => {
                StreakCount::default()
            }
        }
    }

    fn reset(&mut self) {
        self.signal = None;
        self.count = 0;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct StreakCount {
    unhealthy: u8,
    unknown: u8,
}

impl StreakCount {
    fn unknown(self) -> Option<u8> {
        (self.unknown > 0).then_some(self.unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhealthy(
        engine: HealthSignal,
        upstream: HealthSignal,
        controller: HealthSignal,
        adapter: HealthSignal,
    ) -> RuntimeObservation {
        RuntimeObservation {
            engine,
            upstream,
            controller,
            adapter,
        }
    }

    #[test]
    fn non_running_phases_are_dormant_and_reset_streaks() {
        let mut policy = WatchdogPolicy::default();
        let upstream_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, upstream_down),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
        assert_eq!(
            policy.evaluate(Phase::Recovering, upstream_down),
            WatchdogDecision::Dormant
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, upstream_down),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
    }

    #[test]
    fn engine_exit_converges_immediately() {
        let mut policy = WatchdogPolicy::default();
        let observation = unhealthy(
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        assert_eq!(
            policy.evaluate(Phase::Running, observation),
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
    }

    #[test]
    fn upstream_and_controller_require_independent_consecutive_failures() {
        let mut policy = WatchdogPolicy::default();
        let upstream_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        for consecutive in 1..UPSTREAM_FAILURE_THRESHOLD {
            assert_eq!(
                policy.evaluate(Phase::Running, upstream_down),
                WatchdogDecision::Hold {
                    reason: WatchdogReason::UpstreamUnavailable,
                    consecutive,
                    threshold: UPSTREAM_FAILURE_THRESHOLD,
                }
            );
        }
        assert_eq!(
            policy.evaluate(Phase::Running, upstream_down),
            WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
        );

        let controller_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, controller_down),
            WatchdogDecision::Hold {
                reason: WatchdogReason::ControllerUnavailable,
                consecutive: 1,
                ..
            }
        ));
    }

    #[test]
    fn a_healthy_sample_resets_only_its_own_streak() {
        let mut policy = WatchdogPolicy::default();
        let both_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
        );
        policy.evaluate(Phase::Running, both_down);
        policy.evaluate(Phase::Running, both_down);

        let upstream_recovers = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
        );
        assert_eq!(
            policy.evaluate(Phase::Running, upstream_recovers),
            WatchdogDecision::Degraded(WatchdogReason::ControllerUnavailable)
        );
    }

    #[test]
    fn adapter_requires_two_failures_and_health_resets_it() {
        let mut policy = WatchdogPolicy::default();
        let adapter_missing = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, adapter_missing),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
        assert_eq!(
            policy.evaluate(Phase::Running, RuntimeObservation::healthy()),
            WatchdogDecision::Healthy
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, adapter_missing),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
        assert_eq!(
            policy.evaluate(Phase::Running, adapter_missing),
            WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing)
        );
    }

    #[test]
    fn unknown_runtime_identity_fails_closed_without_convergence() {
        let mut policy = WatchdogPolicy::default();
        let unknown = unhealthy(
            HealthSignal::Unknown,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        for consecutive in 1..UNKNOWN_FAILURE_THRESHOLD {
            assert_eq!(
                policy.evaluate(Phase::Running, unknown),
                WatchdogDecision::Hold {
                    reason: WatchdogReason::RuntimeIdentityMismatch,
                    consecutive,
                    threshold: UNKNOWN_FAILURE_THRESHOLD,
                }
            );
        }
        assert_eq!(
            policy.evaluate(Phase::Running, unknown),
            WatchdogDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
        );
    }

    #[test]
    fn unknown_asset_identity_suppresses_otherwise_immediate_cleanup() {
        let mut policy = WatchdogPolicy::default();
        let engine_exited_but_adapter_unknown = unhealthy(
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unknown,
        );
        assert_eq!(
            policy.evaluate(Phase::Running, engine_exited_but_adapter_unknown),
            WatchdogDecision::Hold {
                reason: WatchdogReason::RuntimeIdentityMismatch,
                consecutive: 1,
                threshold: UNKNOWN_FAILURE_THRESHOLD,
            }
        );
    }

    #[test]
    fn switching_between_unknown_and_unhealthy_does_not_combine_counts() {
        let mut policy = WatchdogPolicy::default();
        let unknown = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unknown,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        let unavailable = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        policy.evaluate(Phase::Running, unknown);
        policy.evaluate(Phase::Running, unavailable);
        assert!(matches!(
            policy.evaluate(Phase::Running, unknown),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
    }

    #[test]
    fn wake_hold_defers_adapter_and_controller_loss_but_not_engine_exit() {
        let mut policy = WatchdogPolicy::default();
        let mut hold = WakeHold::default();
        let tun_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Unhealthy,
        );
        // Woke up: the adapter and controller are missing for the whole hold.
        let mut woke = true;
        for _ in 0..WAKE_HOLD_TICKS {
            let decision = policy.evaluate(Phase::Running, hold.apply(false, woke, tun_down));
            assert!(!matches!(decision, WatchdogDecision::RestartEngine(_)));
            woke = false;
        }
        // A loss that outlasts the hold converges as before.
        assert_eq!(
            policy.evaluate(Phase::Running, hold.apply(false, false, tun_down)),
            WatchdogDecision::Hold {
                reason: WatchdogReason::ControllerUnavailable,
                consecutive: 1,
                threshold: CONTROLLER_FAILURE_THRESHOLD,
            }
        );
        assert_eq!(
            policy.evaluate(Phase::Running, hold.apply(false, false, tun_down)),
            WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing)
        );

        let mut policy = WatchdogPolicy::default();
        let mut hold = WakeHold::default();
        let engine_gone = RuntimeObservation::engine_only(HealthSignal::Unhealthy);
        assert_eq!(
            policy.evaluate(Phase::Running, hold.apply(false, true, engine_gone)),
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
    }

    #[test]
    fn unavailable_upstream_keeps_the_tunnel_until_it_returns() {
        let mut policy = WatchdogPolicy::default();
        let upstream_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        for _ in 1..UPSTREAM_FAILURE_THRESHOLD {
            policy.evaluate(Phase::Running, upstream_down);
        }
        for _ in 0..20 {
            assert_eq!(
                policy.evaluate(Phase::Running, upstream_down),
                WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
            );
            assert_eq!(
                policy.evaluate(
                    Phase::Running,
                    RuntimeObservation::engine_only(HealthSignal::Healthy)
                ),
                WatchdogDecision::Degraded(WatchdogReason::UpstreamUnavailable)
            );
        }
        assert_eq!(
            policy.evaluate(Phase::Running, RuntimeObservation::healthy()),
            WatchdogDecision::Healthy
        );
    }

    #[test]
    fn tunnel_faults_still_converge_while_the_upstream_is_degraded() {
        let mut policy = WatchdogPolicy::default();
        let upstream_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        for _ in 0..UPSTREAM_FAILURE_THRESHOLD {
            policy.evaluate(Phase::Running, upstream_down);
        }
        assert_eq!(
            policy.evaluate(
                Phase::Running,
                unhealthy(
                    HealthSignal::Unhealthy,
                    HealthSignal::Unhealthy,
                    HealthSignal::Healthy,
                    HealthSignal::Healthy,
                )
            ),
            WatchdogDecision::RestartEngine(WatchdogReason::EngineExited)
        );
        let mut policy = WatchdogPolicy::default();
        for _ in 0..ADAPTER_FAILURE_THRESHOLD {
            policy.evaluate(
                Phase::Running,
                unhealthy(
                    HealthSignal::Healthy,
                    HealthSignal::Unhealthy,
                    HealthSignal::Healthy,
                    HealthSignal::Unhealthy,
                ),
            );
        }
        assert_eq!(
            policy.evaluate(
                Phase::Running,
                unhealthy(
                    HealthSignal::Healthy,
                    HealthSignal::Unhealthy,
                    HealthSignal::Healthy,
                    HealthSignal::Unhealthy,
                )
            ),
            WatchdogDecision::RestartEngine(WatchdogReason::AdapterMissing)
        );
    }

    #[test]
    fn unsampled_slow_signals_preserve_without_incrementing_streaks() {
        let mut policy = WatchdogPolicy::default();
        let upstream_down = unhealthy(
            HealthSignal::Healthy,
            HealthSignal::Unhealthy,
            HealthSignal::Healthy,
            HealthSignal::Healthy,
        );
        assert!(matches!(
            policy.evaluate(Phase::Running, upstream_down),
            WatchdogDecision::Hold { consecutive: 1, .. }
        ));
        for _ in 0..3 {
            assert_eq!(
                policy.evaluate(
                    Phase::Running,
                    RuntimeObservation::engine_only(HealthSignal::Healthy)
                ),
                WatchdogDecision::Hold {
                    reason: WatchdogReason::UpstreamUnavailable,
                    consecutive: 1,
                    threshold: UPSTREAM_FAILURE_THRESHOLD,
                }
            );
        }
        assert!(matches!(
            policy.evaluate(Phase::Running, upstream_down),
            WatchdogDecision::Hold { consecutive: 2, .. }
        ));
    }
}
