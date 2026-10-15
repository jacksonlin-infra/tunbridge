import { describe, expect, it } from "vitest";
import type { DesktopError, DesktopStatus, ServicePhase } from "../../types";
import { appearanceTone, failedHop, startBlockedReason, tunnelAppearance } from "./overview-model";

const status = (servicePhase: ServicePhase, patch: Partial<DesktopStatus> = {}): DesktopStatus => ({
  schemaVersion: 3,
  servicePhase,
  engineRunning: servicePhase === "running",
  callerIsOwner: true,
  serviceVersion: "0.3.18",
  readOnly: false,
  capabilities: [],
  stopReason: null,
  degradedReason: null,
  ...patch,
});

const error: DesktopError = {
  code: "service_unavailable",
  safeMessage: "The TunBridge service is unavailable.",
  retryable: true,
};

const ready = (value: DesktopStatus) => ({ kind: "ready" as const, status: value, refreshedAt: 1 });

describe("tunnel appearance", () => {
  it("separates running from blocked by the degraded reason", () => {
    expect(tunnelAppearance(ready(status("running")), true)).toEqual({ kind: "running", owned: true });
    expect(tunnelAppearance(ready(status("running", { degradedReason: "upstream_unavailable" })), true))
      .toEqual({ kind: "blocked", reason: "upstream_unavailable", owned: true });
  });

  it("never falls back to stopped when the state is unknown or in flux", () => {
    expect(tunnelAppearance({ kind: "boot" }, true).kind).toBe("checking");
    expect(tunnelAppearance({ kind: "loading" }, true).kind).toBe("checking");
    expect(tunnelAppearance({ kind: "failure", error, failedAt: 1 }, true).kind).toBe("unavailable");
    expect(tunnelAppearance({ kind: "failure", error, previous: status("running"), failedAt: 1 }, true))
      .toMatchObject({ kind: "unknown", last: { servicePhase: "running" } });
    for (const phase of ["starting", "stopping", "recovering"] as const) {
      expect(tunnelAppearance(ready(status(phase)), true)).toEqual({ kind: "transition", phase });
    }
    expect(tunnelAppearance(ready(status("faulted", { stopReason: "engine_exited" })), true))
      .toEqual({ kind: "faulted", reason: "engine_exited", owned: true });
  });

  it("keeps showing the previous status while a refresh is loading", () => {
    expect(tunnelAppearance({ kind: "loading", previous: status("running") }, true).kind).toBe("running");
  });

  it("reports first use only once the profile store is known to be empty", () => {
    expect(tunnelAppearance(ready(status("stopped")), false)).toMatchObject({ kind: "stopped", firstUse: true });
    expect(tunnelAppearance(ready(status("stopped")), null)).toMatchObject({ kind: "stopped", firstUse: false });
    expect(tunnelAppearance(ready(status("stopped", { stopReason: "lease_expired" })), true))
      .toMatchObject({ kind: "stopped", autoStopReason: "lease_expired" });
  });

  it("marks sessions opened by another user session", () => {
    expect(tunnelAppearance(ready(status("running", { callerIsOwner: false })), true))
      .toEqual({ kind: "running", owned: false });
  });

  it("maps tones and failed hops", () => {
    expect(appearanceTone({ kind: "running", owned: true })).toBe("accent");
    expect(appearanceTone({ kind: "blocked", reason: "upstream_unavailable", owned: true })).toBe("amber");
    expect(appearanceTone({ kind: "faulted", reason: null, owned: true })).toBe("danger");
    expect(appearanceTone({ kind: "stopped", firstUse: false, autoStopReason: null })).toBe("neutral");
    expect(failedHop("upstream_unavailable")).toBe("upstream");
    expect(failedHop("engine_exited")).toBe("tun");
  });
});

describe("start blocked reason", () => {
  const base = { lifecycleBusy: false, readOnly: false, hasProfile: true, testing: false, availability: "available" as const };
  it("explains every reason the start button is disabled", () => {
    expect(startBlockedReason(base)).toBeNull();
    expect(startBlockedReason({ ...base, lifecycleBusy: true })).toBeNull();
    expect(startBlockedReason({ ...base, readOnly: true })).toBe("This account can only view the tunnel status");
    expect(startBlockedReason({ ...base, hasProfile: false })).toBe("Choose an upstream first");
    expect(startBlockedReason({ ...base, testing: true })).toBe("Testing the upstream…");
    expect(startBlockedReason({ ...base, availability: "pending" })).toBe("Waiting for the upstream test");
    expect(startBlockedReason({ ...base, availability: "unavailable" })).toMatch(/not answering/);
  });
});
