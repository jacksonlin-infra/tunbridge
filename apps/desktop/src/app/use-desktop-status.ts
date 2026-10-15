import { useEffect, useMemo, useState } from "react";
import { invoke } from "../bridge";
import { StatusController } from "../status-controller";
import type { DesktopStatus, StatusViewState } from "../types";

const POLL_INTERVAL_MS = 5_000;

const loadStatus = (): Promise<DesktopStatus> => invoke<DesktopStatus>("get_status");

export const latestStatus = (state: StatusViewState): DesktopStatus | undefined => {
  if (state.kind === "ready") return state.status;
  if (state.kind === "loading") return state.previous;
  return undefined;
};

/** Polls the service status while the window is visible. */
export function useDesktopStatus() {
  const [state, setState] = useState<StatusViewState>({ kind: "boot" });
  const controller = useMemo(() => new StatusController(loadStatus, setState), []);

  useEffect(() => {
    controller.setVisible(document.visibilityState === "visible");
    void controller.refresh();
    const timer = window.setInterval(() => void controller.refresh(), POLL_INTERVAL_MS);
    const onVisibility = () => {
      const visible = document.visibilityState === "visible";
      controller.setVisible(visible);
      if (visible) void controller.refresh();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      controller.setVisible(false);
    };
  }, [controller]);

  return { state, controller };
}
