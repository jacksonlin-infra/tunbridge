import type { TrafficError } from "../../types";

/**
 * Right after a start the engine is still bringing every connection back up
 * and the service answers "temporarily unavailable" for the first samples.
 * That is expected, so a retryable error is shown only once it lasts.
 */
export const OBSERVATION_WARMUP_MS = 15_000;
/** Consecutive retryable failures tolerated before one is shown. */
export const OBSERVATION_FAILURE_TOLERANCE = 3;

export interface ObservationGate {
  since: number;
  failures: number;
  hasData: boolean;
}

export const newObservationGate = (now: number, hasData = false): ObservationGate => ({
  since: now,
  failures: 0,
  hasData,
});

export const observationSucceeded = (gate: ObservationGate): void => {
  gate.failures = 0;
  gate.hasData = true;
};

/** Records a failed poll and returns the error to show, or null to keep waiting. */
export const observationFailed = (
  gate: ObservationGate,
  error: TrafficError,
  now: number,
): TrafficError | null => {
  gate.failures += 1;
  if (!error.retryable) return error;
  if (gate.failures < OBSERVATION_FAILURE_TOLERANCE) return null;
  if (!gate.hasData && now - gate.since < OBSERVATION_WARMUP_MS) return null;
  return error;
};
