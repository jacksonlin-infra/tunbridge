import { invoke } from "../../bridge";
import type {
  AppUpdateError,
  AppUpdateErrorCode,
  AppUpdateInformation,
} from "../../types";

export const loadAppUpdateInformation = (): Promise<AppUpdateInformation> =>
  invoke<AppUpdateInformation>("get_app_update_information");

export const openAppReleasesPage = (): Promise<void> =>
  invoke<void>("open_app_releases_page");

const appUpdateErrorCodes = new Set<AppUpdateErrorCode>([
  "busy",
  "update_unavailable",
  "invalid_response",
  "unsupported_target",
  "release_page_unavailable",
  "worker_failed",
]);

export function normalizeAppUpdateError(error: unknown): AppUpdateError {
  if (typeof error === "object" && error !== null) {
    const value = error as Partial<AppUpdateError>;
    if (
      typeof value.code === "string"
      && appUpdateErrorCodes.has(value.code as AppUpdateErrorCode)
      && typeof value.safeMessage === "string"
      && typeof value.retryable === "boolean"
    ) {
      return value as AppUpdateError;
    }
  }
  return {
    code: "invalid_response",
    safeMessage: "The TunBridge release channel returned an invalid response.",
    retryable: true,
  };
}
