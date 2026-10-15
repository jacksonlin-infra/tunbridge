import { useEffect, useState } from "react";
import { loadActiveProfileId } from "../lifecycle-client";
import type { ServicePhase } from "../types";

/**
 * The profile the user wants for the next start, and the exact profile the
 * running session was started with.
 */
export function useTunnelSelection(phase: ServicePhase, callerIsOwner: boolean | undefined) {
  const [desiredProfileId, setDesiredProfileId] = useState<string | null>(() =>
    localStorage.getItem("tunbridge.desiredProfileId"),
  );
  const [activeProfileId, setActiveProfileId] = useState<string | null>(null);

  useEffect(() => {
    if (desiredProfileId) {
      localStorage.setItem("tunbridge.desiredProfileId", desiredProfileId);
    } else {
      localStorage.removeItem("tunbridge.desiredProfileId");
    }
  }, [desiredProfileId]);

  useEffect(() => {
    let active = true;
    if (phase !== "running" || callerIsOwner !== true) {
      setActiveProfileId(null);
      return () => { active = false; };
    }
    void loadActiveProfileId()
      .then((profileId) => {
        // Preserve the exact profile recorded after a completed start
        // if the read-side lease snapshot is briefly unavailable.
        if (active && profileId) setActiveProfileId(profileId);
      })
      .catch(() => undefined);
    return () => { active = false; };
  }, [phase, callerIsOwner]);

  return { desiredProfileId, setDesiredProfileId, activeProfileId, setActiveProfileId };
}
