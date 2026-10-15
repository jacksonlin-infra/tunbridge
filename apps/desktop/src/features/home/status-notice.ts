import type { DesktopStatus, WatchdogReason } from "../../types";

export interface StatusNotice {
  tone: "warning" | "error";
  title: string;
  detail: string;
}

const stopTitles: Record<WatchdogReason, string> = {
  engine_exited: "The tunnel engine exited unexpectedly.",
  upstream_unavailable: "The tunnel stopped because the upstream proxy became unavailable.",
  controller_unavailable: "The tunnel engine stopped responding.",
  adapter_missing: "The tunnel network adapter disappeared.",
  runtime_identity_mismatch: "TunBridge could not verify the running tunnel.",
  lease_expired: "The tunnel stopped because TunBridge stopped responding.",
  connection_storm: "The tunnel stopped after a connection storm.",
};

const degradedNotices: Partial<Record<WatchdogReason, Omit<StatusNotice, "tone">>> = {
  upstream_unavailable: {
    title: "The upstream proxy is unreachable.",
    detail: "The system tunnel stays on and blocks traffic instead of sending it directly. It resumes automatically when the proxy is back.",
  },
  engine_exited: {
    title: "The tunnel engine exited unexpectedly and is restarting.",
    detail: "The system tunnel stays on and blocks traffic instead of sending it directly. It resumes automatically after the restart.",
  },
  adapter_missing: {
    title: "The tunnel network adapter disappeared; the engine is restarting.",
    detail: "The system tunnel stays on and blocks traffic instead of sending it directly. It resumes automatically after the restart.",
  },
  controller_unavailable: {
    title: "The tunnel engine stopped responding.",
    detail: "The system tunnel stays on and traffic is never sent directly. It resumes automatically when the engine responds again.",
  },
};

/**
 * Explains a service-side automatic decision. Manual starts and stops clear
 * the reason in the service, so a notice always describes something the user
 * did not do. A degraded session always keeps the tunnel up.
 */
export const statusNotice = (status: DesktopStatus | undefined): StatusNotice | null => {
  if (!status) return null;
  if (status.servicePhase === "running" && status.degradedReason) {
    const notice = degradedNotices[status.degradedReason] ?? {
      title: "The tunnel is not working normally.",
      detail: "The system tunnel stays on and traffic is never sent directly.",
    };
    return { tone: "warning", ...notice };
  }
  const reason = status.stopReason;
  if (!reason) return null;
  if (status.servicePhase === "faulted") {
    return {
      tone: "error",
      title: stopTitles[reason],
      detail: "The tunnel was left in place. Use Recover network to restore the previous network state.",
    };
  }
  if (status.servicePhase === "stopped") {
    return {
      tone: "error",
      title: stopTitles[reason],
      detail: "TunBridge restored the previous network state. Turn the tunnel on again when ready.",
    };
  }
  return null;
};
