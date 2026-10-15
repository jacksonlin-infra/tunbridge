import type { ProfileAvailability } from "../../profile-availability";

export type AvailabilityTone = "accent" | "danger" | "neutral";

/** Short reason for a failed upstream test (English catalog keys). */
export const testErrorLabel = (errorCode: string | null): string => {
  switch (errorCode) {
    case "connect_failed":
      return "Connection refused";
    case "authentication_failed":
      return "Authentication failed";
    case "protocol_mismatch":
      return "Protocol mismatch";
    case "upstream_timeout":
      return "Timed out";
    case "test_target_unavailable":
      return "Test target unreachable";
    case "invalid_response":
      return "Invalid response";
    case "credential_unavailable":
      return "Credential unavailable";
    default:
      return "Unavailable";
  }
};

/** Status text for a saved upstream. `{ms}` is filled by the caller. */
export const availabilityCopy = (
  availability: ProfileAvailability | undefined,
): { label: string; tone: AvailabilityTone; latencyMs: number | null } => {
  switch (availability?.state) {
    case "available":
      return {
        label: availability.latencyMs === null ? "Available" : "Available · {ms} ms",
        tone: "accent",
        latencyMs: availability.latencyMs,
      };
    case "unavailable":
      return { label: testErrorLabel(availability.errorCode), tone: "danger", latencyMs: null };
    case "testing":
      return { label: "Testing…", tone: "neutral", latencyMs: null };
    default:
      return { label: "Not tested yet", tone: "neutral", latencyMs: null };
  }
};
