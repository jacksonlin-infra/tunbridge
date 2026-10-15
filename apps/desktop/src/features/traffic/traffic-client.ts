import { invoke } from "../../bridge";
import type { TrafficError, TrafficErrorCode, TrafficSnapshot } from "../../types";

const messages: Record<TrafficErrorCode, string> = {
  service_unavailable: "The TunBridge service is unavailable.",
  service_identity_failed: "The TunBridge service identity could not be verified.",
  service_protocol_error: "The TunBridge service returned invalid traffic data.",
  not_running: "TunBridge is not running.",
  not_owner: "Traffic details are available only to the session that started TunBridge.",
  traffic_unavailable: "Local traffic data is temporarily unavailable.",
  connection_not_found: "The connection is no longer active.",
};

export const loadTrafficSnapshot = (): Promise<TrafficSnapshot> =>
  invoke<TrafficSnapshot>("get_traffic_snapshot");

export const normalizeTrafficError = (value: unknown): TrafficError => {
  if (value && typeof value === "object") {
    const candidate = value as Partial<TrafficError>;
    if (
      typeof candidate.code === "string" &&
      candidate.code in messages &&
      typeof candidate.retryable === "boolean"
    ) {
      const code = candidate.code as TrafficErrorCode;
      return { code, safeMessage: messages[code], retryable: candidate.retryable };
    }
  }
  return {
    code: "service_protocol_error",
    safeMessage: messages.service_protocol_error,
    retryable: false,
  };
};
