import { invoke } from "../../bridge";
import type {
  DiagnosticError,
  DiagnosticErrorCode,
  CoreUpdateInformation,
  IpInformation,
  SystemInformation,
  WebsiteTarget,
  WebsiteTestResult,
} from "../../types";

export const runWebsiteTest = (
  target: WebsiteTarget,
): Promise<WebsiteTestResult> =>
  invoke<WebsiteTestResult>("test_website", { input: { target } });

export const loadIpInformation = (): Promise<IpInformation> =>
  invoke<IpInformation>("get_ip_information");

export const loadSystemInformation = (): Promise<SystemInformation> =>
  invoke<SystemInformation>("get_system_information");

export const setAutoLaunch = (enabled: boolean): Promise<boolean> =>
  invoke<boolean>("set_auto_launch", { enabled });

export const loadCoreUpdateInformation = (): Promise<CoreUpdateInformation> =>
  invoke<CoreUpdateInformation>("get_core_update_information");

export const installCoreUpdate = (): Promise<CoreUpdateInformation> =>
  invoke<CoreUpdateInformation>("install_core_update");

const diagnosticCodes = new Set<DiagnosticErrorCode>([
  "network_unavailable",
  "provider_unavailable",
  "invalid_response",
  "system_info_unavailable",
  "core_update_unavailable",
  "core_update_identity_failed",
  "core_update_failed",
]);

export const normalizeDiagnosticError = (error: unknown): DiagnosticError => {
  if (typeof error === "object" && error !== null) {
    const value = error as Partial<DiagnosticError>;
    if (
      typeof value.code === "string"
      && diagnosticCodes.has(value.code as DiagnosticErrorCode)
      && typeof value.safeMessage === "string"
      && typeof value.retryable === "boolean"
    ) {
      return value as DiagnosticError;
    }
  }
  return {
    code: "invalid_response",
    safeMessage: "The diagnostics request returned an invalid response.",
    retryable: true,
  };
};
