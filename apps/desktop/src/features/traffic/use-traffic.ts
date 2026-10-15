import { useEffect, useState } from "react";
import type { TrafficError, TrafficSnapshot } from "../../types";
import { newObservationGate, observationFailed, observationSucceeded } from "./observation-gate";
import { loadTrafficSnapshot, normalizeTrafficError } from "./traffic-client";
import { appendTrafficPoint, type TrafficPoint } from "./traffic-model";

/** Samples the owned engine once per second while the tunnel is observable. */
export function useTraffic(canObserve: boolean) {
  const [snapshot, setSnapshot] = useState<TrafficSnapshot | null>(null);
  const [history, setHistory] = useState<TrafficPoint[]>([]);
  const [error, setError] = useState<TrafficError | null>(null);

  useEffect(() => {
    if (!canObserve) {
      setSnapshot(null);
      setHistory([]);
      setError(null);
      return;
    }
    let active = true;
    let inFlight = false;
    const gate = newObservationGate(Date.now());
    const refresh = async () => {
      if (!active || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      try {
        const next = await loadTrafficSnapshot();
        if (!active) return;
        observationSucceeded(gate);
        setSnapshot(next);
        setHistory((points) => appendTrafficPoint(points, next));
        setError(null);
      } catch (loadError) {
        if (active) setError(observationFailed(gate, normalizeTrafficError(loadError), Date.now()));
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1_000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [canObserve]);

  return { snapshot, history, error };
}
