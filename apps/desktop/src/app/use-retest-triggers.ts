import { useEffect, useRef } from "react";

const PERIODIC_RETEST_MS = 30_000;

interface RetestTriggers {
  /** The overview appearance kind; becoming "stopped" means the service answers again. */
  appearanceKind: string;
  /** The service installer or repair is running. */
  installerBusy: boolean;
  /** Keep re-testing while the user is choosing an upstream. */
  periodic: boolean;
}

/**
 * Asks for the saved upstreams to be tested again whenever an earlier result
 * may be stale: the service became reachable, an install or repair finished,
 * the window came back, or (for upstreams that are not available) when a block
 * ended by itself and periodically while an upstream is being chosen.
 */
export function useRetestTriggers(
  bump: () => void,
  bumpUnavailable: () => void,
  { appearanceKind, installerBusy, periodic }: RetestTriggers,
) {
  const previousKind = useRef(appearanceKind);
  useEffect(() => {
    if (previousKind.current !== appearanceKind && appearanceKind === "stopped") bump();
    // The tunnel resumed by itself, so the upstream answers again: replace the
    // failure recorded while it was blocked.
    if (previousKind.current === "blocked" && appearanceKind === "running") bumpUnavailable();
    previousKind.current = appearanceKind;
  }, [appearanceKind]);

  const previousInstaller = useRef(installerBusy);
  useEffect(() => {
    if (previousInstaller.current && !installerBusy) bump();
    previousInstaller.current = installerBusy;
  }, [installerBusy]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === "visible") bump();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  useEffect(() => {
    if (!periodic) return;
    // Only upstreams that are not available yet, so a working choice is not
    // disturbed (and the start button not greyed out) every few seconds.
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") bumpUnavailable();
    }, PERIODIC_RETEST_MS);
    return () => window.clearInterval(timer);
  }, [periodic]);
}
