import type {
  DesktopError,
  DesktopStatus,
  StatusViewState,
  WatchdogReason,
} from "../../types";

/**
 * How the overview and the sidebar present the tunnel. Only `stopped` means
 * traffic goes directly; every other state that is not provably stopped keeps
 * its own appearance so the UI never claims the tunnel is off when it may not be.
 */
export type TunnelAppearance =
  | { kind: "checking" }
  | { kind: "unavailable"; error: DesktopError }
  | { kind: "unknown"; error: DesktopError; last: DesktopStatus }
  | { kind: "transition"; phase: "starting" | "stopping" | "recovering" }
  | { kind: "faulted"; reason: WatchdogReason | null; owned: boolean }
  | { kind: "running"; owned: boolean }
  | { kind: "blocked"; reason: WatchdogReason; owned: boolean }
  | { kind: "stopped"; firstUse: boolean; autoStopReason: WatchdogReason | null };

export type TunnelTone = "accent" | "amber" | "danger" | "neutral";

const appearanceOf = (status: DesktopStatus, hasProfiles: boolean | null): TunnelAppearance => {
  const owned = status.callerIsOwner;
  switch (status.servicePhase) {
    case "running":
      return status.degradedReason
        ? { kind: "blocked", reason: status.degradedReason, owned }
        : { kind: "running", owned };
    case "faulted":
      return { kind: "faulted", reason: status.stopReason, owned };
    case "starting":
    case "stopping":
    case "recovering":
      return { kind: "transition", phase: status.servicePhase };
    case "stopped":
      return {
        kind: "stopped",
        firstUse: hasProfiles === false,
        autoStopReason: status.stopReason,
      };
  }
};

/**
 * @param hasProfiles `null` while the profile store is still loading, so a
 *   slow load is never mistaken for first use.
 */
export const tunnelAppearance = (
  state: StatusViewState,
  hasProfiles: boolean | null,
): TunnelAppearance => {
  switch (state.kind) {
    case "boot":
      return { kind: "checking" };
    case "loading":
      return state.previous ? appearanceOf(state.previous, hasProfiles) : { kind: "checking" };
    case "ready":
      return appearanceOf(state.status, hasProfiles);
    case "failure":
      return state.previous
        ? { kind: "unknown", error: state.error, last: state.previous }
        : { kind: "unavailable", error: state.error };
  }
};

export const appearanceTone = (appearance: TunnelAppearance): TunnelTone => {
  switch (appearance.kind) {
    case "running":
      return "accent";
    case "blocked":
    case "unknown":
      return "amber";
    case "faulted":
    case "unavailable":
      return "danger";
    default:
      return "neutral";
  }
};

/**
 * Whether a fault is one the service declared while the tunnel was running,
 * when it keeps TUN in place to hold traffic back. A fault without a reason
 * is left by a start, stop or recovery that did not finish: the service may
 * already have rolled the network back, so nothing can be said about whether
 * traffic is held.
 */
export const faultHoldsTraffic = (reason: WatchdogReason | null): boolean => reason !== null;

/** The hop in the app → TUN → upstream → exit chain that a degraded reason points at. */
export const failedHop = (reason: WatchdogReason): "tun" | "upstream" =>
  reason === "upstream_unavailable" ? "upstream" : "tun";

/**
 * Why "Turn on TUN" cannot be pressed right now, as an English catalog key,
 * so the stopped card always tells the user what happens next.
 */
export const startBlockedReason = (input: {
  lifecycleBusy: boolean;
  readOnly: boolean;
  hasProfile: boolean;
  testing: boolean;
  availability: "pending" | "testing" | "available" | "unavailable";
}): string | null => {
  if (input.lifecycleBusy) return null;
  if (input.readOnly) return "This account can only view the tunnel status";
  if (!input.hasProfile) return "Choose an upstream first";
  if (input.testing || input.availability === "testing") return "Testing the upstream…";
  if (input.availability === "pending") return "Waiting for the upstream test";
  if (input.availability === "unavailable") return "The chosen upstream is not answering. Start its proxy app, or choose another one; it is re-tested automatically";
  return null;
};
