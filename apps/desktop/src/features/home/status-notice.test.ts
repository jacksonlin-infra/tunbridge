import { describe, expect, it } from "vitest";
import type { DesktopStatus } from "../../types";
import { statusNotice } from "./status-notice";

const base: DesktopStatus = {
  schemaVersion: 3,
  servicePhase: "running",
  engineRunning: true,
  callerIsOwner: true,
  serviceVersion: "0.3.18",
  readOnly: false,
  capabilities: ["status", "start", "stop", "recover", "lease"],
  stopReason: null,
  degradedReason: null,
};

describe("status notice", () => {
  it("stays quiet for healthy and manually stopped sessions", () => {
    expect(statusNotice(undefined)).toBeNull();
    expect(statusNotice(base)).toBeNull();
    expect(statusNotice({ ...base, servicePhase: "stopped", engineRunning: false })).toBeNull();
  });

  it("explains a degraded session that keeps failing closed", () => {
    const notice = statusNotice({ ...base, degradedReason: "upstream_unavailable" });
    expect(notice?.tone).toBe("warning");
    expect(notice?.detail).toContain("instead of sending it directly");
  });

  it("explains an engine restart as degraded, never as a stop", () => {
    const notice = statusNotice({ ...base, degradedReason: "engine_exited" });
    expect(notice?.tone).toBe("warning");
    expect(notice?.title).toContain("restarting");
    expect(notice?.detail).toContain("instead of sending it directly");
    expect(statusNotice({ ...base, degradedReason: "controller_unavailable" })?.detail)
      .toContain("never sent directly");
  });

  it("explains automatic stops and faults", () => {
    expect(statusNotice({
      ...base,
      servicePhase: "stopped",
      engineRunning: false,
      stopReason: "lease_expired",
    })).toMatchObject({ tone: "error", title: "The tunnel stopped because TunBridge stopped responding." });
    expect(statusNotice({
      ...base,
      servicePhase: "faulted",
      engineRunning: false,
      stopReason: "runtime_identity_mismatch",
    })?.detail).toContain("Recover network");
  });
});
