import { useEffect, useState } from "react";
import { loadIpInformation, normalizeDiagnosticError } from "../features/home/home-client";
import type { DiagnosticError, IpInformation } from "../types";

/**
 * The public exit address seen through the running tunnel. Fetched each time
 * the tunnel becomes usable; cleared while it is not, so a stale direct-route
 * address is never shown as the tunnel exit.
 */
export function useExitIp(tunnelUsable: boolean) {
  const [info, setInfo] = useState<IpInformation | null>(null);
  const [error, setError] = useState<DiagnosticError | null>(null);
  const [loading, setLoading] = useState(false);
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    if (!tunnelUsable) {
      setInfo(null);
      setError(null);
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    setError(null);
    void loadIpInformation()
      .then((value) => {
        if (active) setInfo(value);
      })
      .catch((loadError) => {
        if (active) setError(normalizeDiagnosticError(loadError));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [tunnelUsable, generation]);

  return { info, error, loading, refresh: () => setGeneration((value) => value + 1) };
}

export type ExitIpApi = ReturnType<typeof useExitIp>;
