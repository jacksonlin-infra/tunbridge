import { describe, expect, it } from "vitest";
import type { TrafficError } from "../../types";
import {
  newObservationGate,
  OBSERVATION_WARMUP_MS,
  observationFailed,
  observationSucceeded,
} from "./observation-gate";

const unavailable: TrafficError = {
  code: "traffic_unavailable",
  safeMessage: "Local traffic data is temporarily unavailable.",
  retryable: true,
};
const identity: TrafficError = {
  code: "service_identity_failed",
  safeMessage: "The TunBridge service identity could not be verified.",
  retryable: false,
};

describe("observation gate", () => {
  it("waits out the warm-up of a just-started session", () => {
    const gate = newObservationGate(0);
    for (let second = 1; second < OBSERVATION_WARMUP_MS / 1_000; second += 1) {
      expect(observationFailed(gate, unavailable, second * 1_000)).toBeNull();
    }
    expect(observationFailed(gate, unavailable, OBSERVATION_WARMUP_MS)).toBe(unavailable);
  });

  it("shows a lasting outage once data has arrived", () => {
    const gate = newObservationGate(0);
    observationSucceeded(gate);
    expect(observationFailed(gate, unavailable, 1_000)).toBeNull();
    expect(observationFailed(gate, unavailable, 2_000)).toBeNull();
    expect(observationFailed(gate, unavailable, 3_000)).toBe(unavailable);
    observationSucceeded(gate);
    expect(observationFailed(gate, unavailable, 4_000)).toBeNull();
  });

  it("shows errors that will not go away at once", () => {
    expect(observationFailed(newObservationGate(0), identity, 0)).toBe(identity);
  });
});
