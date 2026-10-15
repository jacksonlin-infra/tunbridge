import { invoke } from "./bridge";
import type { LifecycleError, LifecycleErrorCode, ServicePhase } from "./types";

const messages: Record<LifecycleErrorCode, string> = {
  busy: "Another desktop operation is active.",
  profile_unavailable: "The selected saved profile is unavailable or changed.",
  upstream_identity_unavailable: "The local proxy listener identity could not be verified.",
  service_unavailable: "The TunBridge service is unavailable.",
  service_identity_failed: "The TunBridge service identity could not be verified.",
  service_protocol_error: "The TunBridge service returned an invalid response.",
  service_rejected: "The TunBridge service rejected the lifecycle request.",
  lease_unavailable: "The App lease could not be established safely.",
  worker_failed: "The App lease worker did not stop safely.",
};

export const normalizeLifecycleError = (value: unknown): LifecycleError => {
  const candidate = value && typeof value === "object" ? value as Partial<LifecycleError> : {};
  const code = typeof candidate.code === "string" && candidate.code in messages
    ? candidate.code as LifecycleErrorCode
    : "service_protocol_error";
  return {
    code,
    safeMessage: messages[code],
    retryable: typeof candidate.retryable === "boolean" ? candidate.retryable : false,
    serviceCode: typeof candidate.serviceCode === "string" ? candidate.serviceCode : undefined,
    serviceMessage: typeof candidate.serviceMessage === "string" ? candidate.serviceMessage : undefined,
  };
};

/**
 * The service's own wording is English and terse, so known messages and codes
 * map to catalog keys; anything else falls back to the command's message.
 */
const serviceMessages: Record<string, string> = {
  "the upstream proxy preflight failed": "The upstream proxy did not pass the startup check.",
  "the fixed engine controller port is unavailable": "Another program is using the engine's control port.",
  "a pre-existing TunBridge adapter blocks startup": "A TUN adapter left from an earlier session blocks the start.",
  "the controlled engine controller did not become ready": "The engine did not become ready in time.",
  "the controlled TUN adapter did not become ready": "The TUN adapter did not become ready in time.",
  "the transparent network self-test failed": "The network self-test through TUN failed.",
  "the controlled engine exited during startup": "The engine exited while starting.",
};

const serviceCodeMessages: Record<string, string> = {
  access_denied: "The TunBridge service denied this request.",
  timeout: "The TunBridge service did not answer in time.",
  operation_in_progress: "Another TunBridge operation is in progress. Try again in a moment.",
  already_running: "System TUN is already running.",
  not_running: "System TUN is not running.",
  not_owner: "System TUN was turned on by another user session.",
  config_validation_failed: "A startup check failed.",
  recovery_required: "Restore the previous network before turning TUN on again.",
  engine_integrity_failed: "The bundled engine failed its integrity check.",
  capability_unavailable: "The TunBridge service does not support this request.",
  lease_already_active: "Another TunBridge window already controls the tunnel.",
  internal_error: "The TunBridge service hit an internal error.",
};

/** Every catalog key `lifecycleErrorMessage` can return besides the fixed messages. */
export const lifecycleServiceMessageKeys = [...Object.values(serviceMessages), ...Object.values(serviceCodeMessages)];

export const lifecycleErrorMessage = (error: LifecycleError): string =>
  (error.serviceMessage ? serviceMessages[error.serviceMessage] : undefined)
  ?? (error.serviceCode ? serviceCodeMessages[error.serviceCode] : undefined)
  ?? error.safeMessage;

export const startSavedProfile = (
  profileId: string,
  expectedStoreRevision: number,
): Promise<void> => invoke("start_saved_profile", {
  input: { profileId, expectedStoreRevision },
});

export const loadActiveProfileId = (): Promise<string | null> =>
  invoke<string | null>("get_active_profile_id");

export const stopTunnel = (): Promise<void> => invoke("stop_tunnel");

export const recoverTunnel = (): Promise<void> => invoke("recover_tunnel");

export const canRequestStart = (phase: ServicePhase): boolean =>
  phase === "stopped" || phase === "faulted";
