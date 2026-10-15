import { describe, expect, it } from "vitest";
import type { TunnelEvent } from "../../types";
import { blockDurationBefore, currentSession, lastSession, openBlock, sessionProfileId } from "./history-model";

const at = (minutes: number) => Date.UTC(2026, 9, 12, 10, minutes);
const event = (minutes: number, kind: TunnelEvent["kind"], actor: TunnelEvent["actor"] = "service", patch: Partial<TunnelEvent> = {}): TunnelEvent => ({
  atUnixMs: at(minutes), kind, actor, ...patch,
});

const session: TunnelEvent[] = [
  event(0, "app_started", "observed", { phase: "stopped" }),
  event(1, "started", "user", { profileId: "a".repeat(32) }),
  event(10, "blocked", "service", { reason: "upstream_unavailable" }),
  event(14, "resumed", "service", { reason: "upstream_unavailable" }),
  event(20, "blocked", "service", { reason: "upstream_unavailable" }),
  event(21, "app_started", "observed", { phase: "running" }),
  event(25, "resumed", "service"),
  event(30, "stopped", "user", { downloadTotal: 500, uploadTotal: 50 }),
];

describe("tunnel history", () => {
  it("finds the running session and whether its start is exact", () => {
    expect(currentSession(session.slice(0, 4))).toEqual({ startedAt: at(1), exact: true, profileId: "a".repeat(32) });
    expect(currentSession(session)).toBeNull();
    expect(currentSession([event(0, "app_started", "observed"), event(0, "started", "observed")]))
      .toMatchObject({ exact: false });
  });

  it("knows the running profile only from a start recorded in this App", () => {
    // Kept across an App restart that left the tunnel running.
    expect(sessionProfileId(session.slice(0, 7))).toBe("a".repeat(32));
    expect(sessionProfileId([event(0, "app_started", "observed"), event(0, "started", "observed")])).toBeNull();
    expect(sessionProfileId(session)).toBeNull();
    expect(sessionProfileId([])).toBeNull();
  });

  it("finds an unresolved block, across an App restart", () => {
    expect(openBlock(session.slice(0, 3))).toEqual({ since: at(10), reason: "upstream_unavailable" });
    expect(openBlock(session.slice(0, 4))).toBeNull();
    expect(openBlock(session.slice(0, 6))).toEqual({ since: at(20), reason: "upstream_unavailable" });
  });

  it("summarises the last session", () => {
    expect(lastSession(session)).toEqual({
      startedAt: at(1),
      exactStart: true,
      endedAt: at(30),
      endedBy: "user",
      endKind: "stopped",
      reason: undefined,
      profileId: "a".repeat(32),
      outages: 2,
      blockedMs: 9 * 60_000,
      downloadTotal: 500,
      uploadTotal: 50,
    });
    expect(lastSession(session.slice(0, 4))).toBeNull();
  });

  it("counts a block that was still open when the session ended", () => {
    const summary = lastSession([event(0, "started", "user"), event(5, "blocked"), event(8, "stopped", "service", { reason: "lease_expired" })]);
    expect(summary).toMatchObject({ outages: 1, blockedMs: 3 * 60_000, endedBy: "service", reason: "lease_expired" });
  });

  it("measures a block for its resumed entry", () => {
    expect(blockDurationBefore(session, 3)).toBe(4 * 60_000);
    expect(blockDurationBefore(session, 6)).toBe(5 * 60_000);
    expect(blockDurationBefore(session, 1)).toBeNull();
  });
});
