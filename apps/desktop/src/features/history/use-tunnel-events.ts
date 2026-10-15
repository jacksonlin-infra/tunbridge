import { useEffect, useState } from "react";
import type { TunnelEvent } from "../../types";
import { loadTunnelEvents } from "./history-client";

const POLL_MS = 5_000;

/**
 * The local event log, refreshed periodically while visible and immediately
 * whenever `changeKey` (the tunnel state) changes.
 */
export function useTunnelEvents(changeKey: string) {
  const [events, setEvents] = useState<TunnelEvent[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    let active = true;
    const refresh = () => {
      if (document.visibilityState !== "visible") return;
      void loadTunnelEvents()
        .then((page) => {
          if (active) setEvents(page.events);
        })
        .catch(() => undefined)
        .finally(() => {
          if (active) setLoaded(true);
        });
    };
    refresh();
    const timer = window.setInterval(refresh, POLL_MS);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [changeKey, generation]);

  return { events, loaded, refresh: () => setGeneration((value) => value + 1) };
}

/** A clock that ticks once a second while `active`. */
export function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}
