import type { ServicePhase, WatchdogReason } from "../../types";
import type { TunnelAppearance } from "./overview-model";

/** Short reason shown next to a blocked tunnel (English catalog keys). */
export const reasonLabel = (reason: WatchdogReason | null): string => {
  switch (reason) {
    case "upstream_unavailable":
      return "Upstream unreachable";
    case "engine_exited":
      return "Engine restarting";
    case "adapter_missing":
      return "TUN adapter lost; engine restarting";
    case "controller_unavailable":
      return "Engine not responding";
    default:
      return "Tunnel not working normally";
  }
};

/** Title and one-line detail for the sidebar summary (English catalog keys). */
export const tunnelSummary = (appearance: TunnelAppearance): { title: string; detail: string } => {
  switch (appearance.kind) {
    case "checking":
      return { title: "Checking…", detail: "Reading the service status" };
    case "unavailable":
      return { title: "Service not ready", detail: "Install or repair it in Settings" };
    case "unknown":
      return { title: "Status unknown", detail: "Cannot read the service status" };
    case "transition":
      return appearance.phase === "starting"
        ? { title: "Starting TUN…", detail: "Testing the upstream and capturing traffic" }
        : appearance.phase === "stopping"
          ? { title: "Stopping TUN…", detail: "Restoring the previous network" }
          : { title: "Recovering the network…", detail: "Restoring the previous network" };
    case "faulted":
      return appearance.reason
        ? { title: "Fault hold · not direct", detail: "Waiting for you to recover" }
        : { title: "Operation did not finish", detail: "Restore the network to clean up" };
    case "running":
      return { title: "TUN running", detail: appearance.owned ? "Routing through the upstream" : "Opened by another session" };
    case "blocked":
      return { title: "Blocked · not direct", detail: reasonLabel(appearance.reason) };
    case "stopped":
      return { title: "TUN stopped", detail: "System traffic goes directly" };
  }
};

export const lastKnownLabels: Record<ServicePhase, string> = {
  stopped: "stopped",
  starting: "starting",
  running: "running",
  stopping: "stopping",
  recovering: "recovering",
  faulted: "fault hold",
};

export const blockedTitles: Partial<Record<WatchdogReason, string>> = {
  upstream_unavailable: "Upstream unreachable; traffic is blocked",
  engine_exited: "Engine exited; traffic is blocked while it restarts",
  adapter_missing: "TUN adapter lost; traffic is blocked while it restarts",
  controller_unavailable: "Engine not responding; traffic is blocked",
};

export const blockedFallbackTitle = "The tunnel is not working normally; traffic is blocked";
