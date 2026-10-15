import { invoke } from "./bridge";
import type { InstallerError, InstallerErrorCode } from "./types";

const messages: Record<InstallerErrorCode, string> = {
  busy: "Another desktop operation is active.",
  installer_unavailable: "The verified TunBridge installer is unavailable.",
  installer_identity_failed: "The TunBridge installer failed identity verification.",
  elevation_cancelled: "Administrator approval was not granted.",
  installer_timeout: "The TunBridge installer exceeded its fixed deadline.",
  installer_failed: "The TunBridge installer did not complete.",
  worker_failed: "The TunBridge installer worker failed.",
};

export const normalizeInstallerError = (value: unknown): InstallerError => {
  const candidate = value && typeof value === "object" ? value as Partial<InstallerError> : {};
  const code = typeof candidate.code === "string" && candidate.code in messages
    ? candidate.code as InstallerErrorCode
    : "installer_failed";
  return {
    code,
    safeMessage: messages[code],
    retryable: typeof candidate.retryable === "boolean" ? candidate.retryable : false,
  };
};

export const installProduct = (): Promise<void> => invoke("install_product");

export const uninstallProduct = (): Promise<void> => invoke("uninstall_product");
