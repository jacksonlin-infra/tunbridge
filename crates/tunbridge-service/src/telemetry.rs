//! Pure connection-storm telemetry policy.
//!
//! Only a trusted platform adapter may construct validated failure events.
//! This module groups opaque per-generation target digests in fixed windows and
//! never accepts raw destinations, logs or client-provided thresholds.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::state::WatchdogReason;

pub const STORM_SCHEMA_VERSION: u16 = 1;
pub const STORM_WINDOW_TICKS: u64 = 10;
pub const STORM_FAILURE_THRESHOLD: u16 = 64;
pub const STORM_CLEAR_TICKS: u64 = 30;
pub const STORM_MAX_TARGETS: usize = 256;
pub const STORM_MAX_EVENTS_PER_BATCH: usize = 128;
pub const TELEMETRY_UNKNOWN_THRESHOLD: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenerationId([u8; 32]);

impl GenerationId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for GenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationId([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetDigest([u8; 32]);

impl TargetDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TargetDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetDigest([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    ConnectFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureEvent {
    pub schema_version: u16,
    pub engine_generation: GenerationId,
    pub event_seq: u64,
    pub monotonic_tick: u64,
    pub target_digest: TargetDigest,
    pub class: FailureClass,
}

#[derive(Debug, Clone, Copy)]
pub enum TelemetryBatch<'a> {
    Disabled,
    Unknown,
    Events(&'a [FailureEvent]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryDecision {
    Disabled,
    Healthy,
    Hold,
    HoldUnknown { consecutive: u8, threshold: u8 },
    Converge(WatchdogReason),
    FaultClosed(WatchdogReason),
}

#[derive(Debug, Clone, Default)]
pub struct TelemetryPolicy {
    generation: Option<GenerationId>,
    next_event_seq: u64,
    last_tick: Option<u64>,
    unknown_streak: u8,
    buckets: BTreeMap<TargetDigest, TargetBucket>,
}

#[derive(Debug, Clone)]
struct TargetBucket {
    window_start: u64,
    last_event: u64,
    failures: u16,
    consumed: bool,
}

impl TelemetryPolicy {
    pub fn observe(
        &mut self,
        now: u64,
        current_generation: GenerationId,
        batch: TelemetryBatch<'_>,
    ) -> TelemetryDecision {
        if self.last_tick.is_some_and(|previous| now < previous) {
            return self.observe_unknown();
        }
        self.last_tick = Some(now);

        if matches!(batch, TelemetryBatch::Disabled) {
            self.reset();
            return TelemetryDecision::Disabled;
        }
        if self.generation != Some(current_generation) {
            self.begin_generation(current_generation);
        }
        match batch {
            TelemetryBatch::Disabled => unreachable!("handled before generation setup"),
            TelemetryBatch::Unknown => self.observe_unknown(),
            TelemetryBatch::Events(events) => match self.validate_batch(now, events) {
                Ok(()) => self.apply_events(now, events),
                Err(()) => self.observe_unknown(),
            },
        }
    }

    pub fn reset(&mut self) {
        self.generation = None;
        self.next_event_seq = 0;
        self.last_tick = None;
        self.unknown_streak = 0;
        self.buckets.clear();
    }

    fn begin_generation(&mut self, generation: GenerationId) {
        self.generation = Some(generation);
        self.next_event_seq = 1;
        self.unknown_streak = 0;
        self.buckets.clear();
    }

    fn validate_batch(&self, now: u64, events: &[FailureEvent]) -> Result<(), ()> {
        if events.len() > STORM_MAX_EVENTS_PER_BATCH {
            return Err(());
        }
        let generation = self.generation.ok_or(())?;
        let mut expected_seq = self.next_event_seq;
        let mut previous_tick = None;
        let mut new_targets = BTreeSet::new();
        for event in events {
            if event.schema_version != STORM_SCHEMA_VERSION
                || event.engine_generation != generation
                || event.event_seq != expected_seq
                || event.monotonic_tick > now
                || previous_tick.is_some_and(|tick| event.monotonic_tick < tick)
                || event.class != FailureClass::ConnectFailure
            {
                return Err(());
            }
            if !self.buckets.contains_key(&event.target_digest) {
                new_targets.insert(event.target_digest);
            }
            expected_seq = expected_seq.checked_add(1).ok_or(())?;
            previous_tick = Some(event.monotonic_tick);
        }
        if self.buckets.len() + new_targets.len() > STORM_MAX_TARGETS {
            return Err(());
        }
        Ok(())
    }

    fn apply_events(&mut self, now: u64, events: &[FailureEvent]) -> TelemetryDecision {
        self.unknown_streak = 0;
        self.buckets
            .retain(|_, bucket| now - bucket.last_event < STORM_CLEAR_TICKS);
        let mut converged = false;
        for event in events {
            let bucket = self
                .buckets
                .entry(event.target_digest)
                .or_insert(TargetBucket {
                    window_start: event.monotonic_tick,
                    last_event: event.monotonic_tick,
                    failures: 0,
                    consumed: false,
                });
            if event.monotonic_tick - bucket.window_start >= STORM_WINDOW_TICKS {
                bucket.window_start = event.monotonic_tick;
                bucket.failures = 0;
                bucket.consumed = false;
            }
            bucket.last_event = event.monotonic_tick;
            bucket.failures = bucket.failures.saturating_add(1);
            if bucket.failures >= STORM_FAILURE_THRESHOLD && !bucket.consumed {
                bucket.consumed = true;
                converged = true;
            }
            self.next_event_seq += 1;
        }
        if converged {
            TelemetryDecision::Converge(WatchdogReason::ConnectionStorm)
        } else if events.is_empty() {
            TelemetryDecision::Healthy
        } else {
            TelemetryDecision::Hold
        }
    }

    fn observe_unknown(&mut self) -> TelemetryDecision {
        self.unknown_streak = self.unknown_streak.saturating_add(1);
        if self.unknown_streak >= TELEMETRY_UNKNOWN_THRESHOLD {
            TelemetryDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
        } else {
            TelemetryDecision::HoldUnknown {
                consecutive: self.unknown_streak,
                threshold: TELEMETRY_UNKNOWN_THRESHOLD,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u8) -> GenerationId {
        GenerationId::from_bytes([value; 32])
    }

    fn digest(value: u8) -> TargetDigest {
        TargetDigest::from_bytes([value; 32])
    }

    fn events(
        generation: GenerationId,
        first_seq: u64,
        tick: u64,
        target: TargetDigest,
        count: usize,
    ) -> Vec<FailureEvent> {
        (0..count)
            .map(|index| FailureEvent {
                schema_version: STORM_SCHEMA_VERSION,
                engine_generation: generation,
                event_seq: first_seq + index as u64,
                monotonic_tick: tick,
                target_digest: target,
                class: FailureClass::ConnectFailure,
            })
            .collect()
    }

    #[test]
    fn transient_failures_hold_and_exact_threshold_converges() {
        let generation = generation(1);
        let target = digest(1);
        let mut policy = TelemetryPolicy::default();
        let first = events(
            generation,
            1,
            10,
            target,
            STORM_FAILURE_THRESHOLD as usize - 1,
        );
        assert_eq!(
            policy.observe(10, generation, TelemetryBatch::Events(&first)),
            TelemetryDecision::Hold
        );
        let threshold = events(generation, STORM_FAILURE_THRESHOLD as u64, 19, target, 1);
        assert_eq!(
            policy.observe(19, generation, TelemetryBatch::Events(&threshold)),
            TelemetryDecision::Converge(WatchdogReason::ConnectionStorm)
        );
    }

    #[test]
    fn different_targets_never_combine() {
        let generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        let mut mixed = Vec::new();
        for index in 0..STORM_FAILURE_THRESHOLD as usize {
            let target = if index % 2 == 0 { digest(1) } else { digest(2) };
            mixed.extend(events(generation, index as u64 + 1, 10, target, 1));
        }
        assert_eq!(
            policy.observe(10, generation, TelemetryBatch::Events(&mixed)),
            TelemetryDecision::Hold
        );
    }

    #[test]
    fn window_boundary_resets_only_that_target() {
        let generation = generation(1);
        let target = digest(1);
        let mut policy = TelemetryPolicy::default();
        let first = events(generation, 1, 10, target, 40);
        policy.observe(10, generation, TelemetryBatch::Events(&first));
        let second = events(generation, 41, 20, target, 30);
        assert_eq!(
            policy.observe(20, generation, TelemetryBatch::Events(&second)),
            TelemetryDecision::Hold
        );
    }

    #[test]
    fn new_generation_clears_counts_and_sequence() {
        let first_generation = generation(1);
        let second_generation = generation(2);
        let target = digest(1);
        let mut policy = TelemetryPolicy::default();
        let first = events(first_generation, 1, 10, target, 63);
        policy.observe(10, first_generation, TelemetryBatch::Events(&first));

        let after_recovery = events(second_generation, 1, 11, target, 1);
        assert_eq!(
            policy.observe(
                11,
                second_generation,
                TelemetryBatch::Events(&after_recovery)
            ),
            TelemetryDecision::Hold
        );
    }

    #[test]
    fn unknown_source_faults_closed_after_three_without_converging() {
        let generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        for consecutive in 1..TELEMETRY_UNKNOWN_THRESHOLD {
            assert_eq!(
                policy.observe(
                    10 + u64::from(consecutive),
                    generation,
                    TelemetryBatch::Unknown
                ),
                TelemetryDecision::HoldUnknown {
                    consecutive,
                    threshold: TELEMETRY_UNKNOWN_THRESHOLD,
                }
            );
        }
        assert_eq!(
            policy.observe(13, generation, TelemetryBatch::Unknown),
            TelemetryDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
        );
    }

    #[test]
    fn malformed_schema_generation_sequence_and_time_are_unknown() {
        let current_generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        let mut event = events(current_generation, 1, 10, digest(1), 1)[0];
        event.schema_version = 99;
        assert!(matches!(
            policy.observe(10, current_generation, TelemetryBatch::Events(&[event])),
            TelemetryDecision::HoldUnknown { .. }
        ));

        let wrong_generation = events(generation(2), 1, 11, digest(1), 1);
        assert!(matches!(
            policy.observe(
                11,
                current_generation,
                TelemetryBatch::Events(&wrong_generation)
            ),
            TelemetryDecision::HoldUnknown { .. }
        ));

        let skipped = events(current_generation, 2, 12, digest(1), 1);
        assert_eq!(
            policy.observe(12, current_generation, TelemetryBatch::Events(&skipped)),
            TelemetryDecision::FaultClosed(WatchdogReason::RuntimeIdentityMismatch)
        );
    }

    #[test]
    fn invalid_batch_is_atomic_and_does_not_advance_sequence() {
        let generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        let invalid = vec![
            events(generation, 1, 10, digest(1), 1)[0],
            events(generation, 3, 10, digest(1), 1)[0],
        ];
        assert!(matches!(
            policy.observe(10, generation, TelemetryBatch::Events(&invalid)),
            TelemetryDecision::HoldUnknown { .. }
        ));
        let valid = events(generation, 1, 11, digest(1), 1);
        assert_eq!(
            policy.observe(11, generation, TelemetryBatch::Events(&valid)),
            TelemetryDecision::Hold
        );
    }

    #[test]
    fn high_cardinality_and_oversized_batches_are_unknown() {
        let generation = generation(1);
        let mut all_events = Vec::new();
        for index in 0..=STORM_MAX_TARGETS {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
            all_events.push(FailureEvent {
                schema_version: STORM_SCHEMA_VERSION,
                engine_generation: generation,
                event_seq: index as u64 + 1,
                monotonic_tick: 10,
                target_digest: TargetDigest::from_bytes(bytes),
                class: FailureClass::ConnectFailure,
            });
        }
        let oversized = &all_events[..STORM_MAX_EVENTS_PER_BATCH + 1];
        let mut policy = TelemetryPolicy::default();
        assert!(matches!(
            policy.observe(10, generation, TelemetryBatch::Events(oversized)),
            TelemetryDecision::HoldUnknown { .. }
        ));

        let mut policy = TelemetryPolicy::default();
        let first = &all_events[..STORM_MAX_EVENTS_PER_BATCH];
        let second = &all_events[STORM_MAX_EVENTS_PER_BATCH..STORM_MAX_TARGETS];
        let overflow = &all_events[STORM_MAX_TARGETS..];
        assert_eq!(
            policy.observe(10, generation, TelemetryBatch::Events(first)),
            TelemetryDecision::Hold
        );
        assert_eq!(
            policy.observe(10, generation, TelemetryBatch::Events(second)),
            TelemetryDecision::Hold
        );
        assert!(matches!(
            policy.observe(10, generation, TelemetryBatch::Events(overflow)),
            TelemetryDecision::HoldUnknown { .. }
        ));
    }

    #[test]
    fn disabled_source_is_not_treated_as_healthy_or_unknown() {
        let generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        assert_eq!(
            policy.observe(10, generation, TelemetryBatch::Disabled),
            TelemetryDecision::Disabled
        );
        assert_eq!(
            policy.observe(1, generation, TelemetryBatch::Unknown),
            TelemetryDecision::HoldUnknown {
                consecutive: 1,
                threshold: TELEMETRY_UNKNOWN_THRESHOLD,
            }
        );
    }

    #[test]
    fn clock_regression_is_unknown_and_never_converges() {
        let generation = generation(1);
        let mut policy = TelemetryPolicy::default();
        let event = events(generation, 1, 10, digest(1), 1);
        policy.observe(10, generation, TelemetryBatch::Events(&event));
        assert!(matches!(
            policy.observe(9, generation, TelemetryBatch::Events(&[])),
            TelemetryDecision::HoldUnknown { .. }
        ));
    }

    #[test]
    fn consumed_bucket_triggers_only_once() {
        let generation = generation(1);
        let target = digest(1);
        let mut policy = TelemetryPolicy::default();
        let threshold = events(generation, 1, 10, target, STORM_FAILURE_THRESHOLD as usize);
        assert!(matches!(
            policy.observe(10, generation, TelemetryBatch::Events(&threshold)),
            TelemetryDecision::Converge(_)
        ));
        let more = events(
            generation,
            STORM_FAILURE_THRESHOLD as u64 + 1,
            11,
            target,
            1,
        );
        assert_eq!(
            policy.observe(11, generation, TelemetryBatch::Events(&more)),
            TelemetryDecision::Hold
        );
    }
}
