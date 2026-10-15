import { describe, expect, it } from "vitest";
import { canRequestStart, lifecycleErrorMessage, normalizeLifecycleError } from "./lifecycle-client";

describe("lifecycle error message", () => {
  const rejected = normalizeLifecycleError({ code: "service_rejected", retryable: true });
  it("words known service messages and codes in the catalog", () => {
    expect(lifecycleErrorMessage({ ...rejected, serviceCode: "config_validation_failed", serviceMessage: "the upstream proxy preflight failed" }))
      .toBe("The upstream proxy did not pass the startup check.");
    expect(lifecycleErrorMessage({ ...rejected, serviceCode: "config_validation_failed", serviceMessage: "something new" }))
      .toBe("A startup check failed.");
  });
  it("falls back to the fixed message instead of service text", () => {
    expect(lifecycleErrorMessage({ ...rejected, serviceCode: "unheard_of", serviceMessage: "raw detail" }))
      .toBe("The TunBridge service rejected the lifecycle request.");
  });
});

describe("lifecycle error boundary", () => {
  it("maps only fixed typed errors", () => {
    expect(normalizeLifecycleError({ code: "lease_unavailable", retryable: true })).toEqual({
      code: "lease_unavailable",
      safeMessage: "The App lease could not be established safely.",
      retryable: true,
    });
  });

  it("does not surface backend text", () => {
    const error = normalizeLifecycleError({
      code: "unknown",
      safeMessage: "C:\\Program Files\\secret PID 42",
      retryable: "yes",
    });
    expect(error).toEqual({
      code: "service_protocol_error",
      safeMessage: "The TunBridge service returned an invalid response.",
      retryable: false,
    });
  });
});

describe("start availability", () => {
  it("keeps Start available when exact recovery is required", () => {
    expect(canRequestStart("stopped")).toBe(true);
    expect(canRequestStart("faulted")).toBe(true);
  });

  it("blocks Start while another lifecycle state owns the switch", () => {
    expect(canRequestStart("starting")).toBe(false);
    expect(canRequestStart("stopping")).toBe(false);
    expect(canRequestStart("recovering")).toBe(false);
    expect(canRequestStart("running")).toBe(false);
  });
});
