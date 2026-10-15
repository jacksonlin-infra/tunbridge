use crate::{
    telemetry::{FailureClass, FailureEvent, GenerationId, TargetDigest, STORM_SCHEMA_VERSION},
    watchdog::HealthSignal,
};

use super::m2b5_acceptance::{active_selector, M2b5Selector};

const ACCEPTANCE_EVENTS_PER_TICK: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OwnedTelemetryBatch {
    Unsampled,
    Disabled,
    Unknown,
    Events(Vec<FailureEvent>),
}

pub(super) fn sample_structured_failures(
    generation: GenerationId,
    tick: u64,
    next_seq: &mut u64,
    controller: HealthSignal,
) -> OwnedTelemetryBatch {
    if controller == HealthSignal::Unknown {
        return OwnedTelemetryBatch::Unknown;
    }
    if controller == HealthSignal::NotSampled {
        return OwnedTelemetryBatch::Unsampled;
    }
    if controller != HealthSignal::Healthy {
        return OwnedTelemetryBatch::Disabled;
    }
    let selector = match active_selector() {
        Ok(None) => return OwnedTelemetryBatch::Disabled,
        Ok(Some(selector)) => selector,
        Err(_) => return OwnedTelemetryBatch::Unknown,
    };
    match selector {
        M2b5Selector::TelemetryUnknown => OwnedTelemetryBatch::Unknown,
        M2b5Selector::TelemetryTargetA | M2b5Selector::TelemetryAlternatingTargets => {
            let mut events = Vec::with_capacity(ACCEPTANCE_EVENTS_PER_TICK);
            for index in 0..ACCEPTANCE_EVENTS_PER_TICK {
                let target = match selector {
                    M2b5Selector::TelemetryTargetA => TargetDigest::from_bytes([0xa5; 32]),
                    M2b5Selector::TelemetryAlternatingTargets if index % 2 == 0 => {
                        TargetDigest::from_bytes([0xa5; 32])
                    }
                    M2b5Selector::TelemetryAlternatingTargets => {
                        TargetDigest::from_bytes([0x5a; 32])
                    }
                    M2b5Selector::TelemetryUnknown => unreachable!("handled before event loop"),
                };
                events.push(FailureEvent {
                    schema_version: STORM_SCHEMA_VERSION,
                    engine_generation: generation,
                    event_seq: *next_seq,
                    monotonic_tick: tick,
                    target_digest: target,
                    class: FailureClass::ConnectFailure,
                });
                *next_seq = next_seq
                    .checked_add(1)
                    .expect("acceptance event sequence cannot overflow in a service lifetime");
            }
            OwnedTelemetryBatch::Events(events)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsampled_slow_cadence_is_distinct_from_disabled_source() {
        let generation = GenerationId::from_bytes([0x11; 32]);
        let mut next_seq = 1;
        assert_eq!(
            sample_structured_failures(generation, 1, &mut next_seq, HealthSignal::NotSampled),
            OwnedTelemetryBatch::Unsampled
        );
        assert_eq!(next_seq, 1);
        assert_eq!(
            sample_structured_failures(generation, 2, &mut next_seq, HealthSignal::Unhealthy),
            OwnedTelemetryBatch::Disabled
        );
        assert_eq!(next_seq, 1);
    }
}
