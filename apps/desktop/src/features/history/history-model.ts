import type { TunnelEvent } from "../../types";

const closes = (event: TunnelEvent) => event.kind === "stopped" || event.kind === "recovered";

/** The running session according to the log; `exact` is false when the App only noticed it. */
export interface CurrentSession {
  startedAt: number;
  exact: boolean;
  profileId?: string;
}

export const currentSession = (events: TunnelEvent[]): CurrentSession | null => {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (closes(event)) return null;
    if (event.kind === "started") {
      return { startedAt: event.atUnixMs, exact: event.actor === "user", profileId: event.profileId };
    }
  }
  return null;
};

/**
 * The saved profile of the open session when this App recorded starting it.
 * The record outlives an App restart that kept the tunnel; a session found
 * already running, or started by anything else, has no known profile.
 */
export const sessionProfileId = (events: TunnelEvent[]): string | null => {
  const session = currentSession(events);
  return session?.exact ? session.profileId ?? null : null;
};

/** An unresolved block in the current session. */
export const openBlock = (events: TunnelEvent[]): { since: number; reason?: TunnelEvent["reason"] } | null => {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event.kind === "blocked") return { since: event.atUnixMs, reason: event.reason };
    if (event.kind === "resumed" || event.kind === "started" || closes(event)) return null;
  }
  return null;
};

export interface SessionSummary {
  startedAt: number | null;
  exactStart: boolean;
  endedAt: number;
  endedBy: TunnelEvent["actor"];
  endKind: "stopped" | "recovered";
  reason?: TunnelEvent["reason"];
  profileId?: string;
  outages: number;
  blockedMs: number;
  downloadTotal?: number;
  uploadTotal?: number;
}

/** The most recent finished session, with its outages and traffic. */
export const lastSession = (events: TunnelEvent[]): SessionSummary | null => {
  let endIndex = -1;
  for (let index = events.length - 1; index >= 0; index -= 1) {
    if (closes(events[index])) {
      endIndex = index;
      break;
    }
  }
  if (endIndex < 0) return null;
  const end = events[endIndex];
  let startIndex = -1;
  for (let index = endIndex - 1; index >= 0; index -= 1) {
    if (closes(events[index])) break;
    if (events[index].kind === "started") {
      startIndex = index;
      break;
    }
  }
  let outages = 0;
  let blockedMs = 0;
  let blockedSince: number | null = null;
  for (let index = Math.max(0, startIndex); index < endIndex; index += 1) {
    const event = events[index];
    if (event.kind === "blocked" && blockedSince === null) {
      outages += 1;
      blockedSince = event.atUnixMs;
    } else if (event.kind === "resumed" && blockedSince !== null) {
      blockedMs += event.atUnixMs - blockedSince;
      blockedSince = null;
    }
  }
  if (blockedSince !== null) blockedMs += end.atUnixMs - blockedSince;
  const start = startIndex >= 0 ? events[startIndex] : null;
  return {
    startedAt: start?.atUnixMs ?? null,
    exactStart: start?.actor === "user",
    endedAt: end.atUnixMs,
    endedBy: end.actor,
    endKind: end.kind as "stopped" | "recovered",
    reason: end.reason,
    profileId: start?.profileId,
    outages,
    blockedMs,
    downloadTotal: end.downloadTotal,
    uploadTotal: end.uploadTotal,
  };
};

/**
 * How long the block that a "resumed" entry ends lasted. App restarts in the
 * middle of an outage are skipped; a change of reason does not restart it.
 */
export const blockDurationBefore = (events: TunnelEvent[], index: number): number | null => {
  let first: number | null = null;
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const kind = events[cursor].kind;
    if (kind === "blocked") first = cursor;
    else if (kind !== "app_started") break;
  }
  return first === null ? null : events[index].atUnixMs - events[first].atUnixMs;
};

export const durationParts = (milliseconds: number) => {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  return { hours: Math.floor(seconds / 3600), minutes: Math.floor((seconds % 3600) / 60), seconds: seconds % 60 };
};
