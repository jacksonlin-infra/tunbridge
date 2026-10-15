import type { ProxyError, ProxyErrorCode } from "./types";

const ERROR_MESSAGES: Record<ProxyErrorCode, string> = {
  invalid_input: "The local proxy input is invalid.",
  busy: "Another local proxy operation is already active.",
  connect_failed: "The local proxy connection failed.",
  authentication_failed: "The local proxy rejected the supplied credentials.",
  protocol_mismatch: "The local endpoint did not match the selected proxy protocol.",
  upstream_timeout: "The local proxy test timed out.",
  test_target_unavailable: "The fixed connectivity test target was unavailable.",
  invalid_response: "The local proxy returned an invalid test response.",
};

const isProxyErrorCode = (value: unknown): value is ProxyErrorCode =>
  typeof value === "string" && Object.hasOwn(ERROR_MESSAGES, value);

export const normalizeProxyError = (value: unknown): ProxyError => {
  const code =
    typeof value === "object" && value !== null && "code" in value && isProxyErrorCode(value.code)
      ? value.code
      : "invalid_response";
  return { code, safeMessage: ERROR_MESSAGES[code] };
};
