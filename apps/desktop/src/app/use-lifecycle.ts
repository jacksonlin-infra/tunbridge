import { useState } from "react";
import {
  normalizeLifecycleError,
  recoverTunnel,
  startSavedProfile,
  stopTunnel,
} from "../lifecycle-client";
import type { StatusController } from "../status-controller";
import type { LifecycleError, SavedProfile, ServicePhase } from "../types";

export type ConfirmKind = "exit" | "recover" | "faulted-start" | "stop-blocked";

export type LifecycleOperation = "start" | "stop" | "recover";

/**
 * Which question must be answered before an operation that would let traffic
 * go directly. Leaving a fault (directly, or by starting again) removes the
 * tunnel that is holding traffic back; stopping a blocked tunnel exposes the
 * real address. A plain stop of a healthy tunnel needs no question.
 */
export const confirmationFor = (
  operation: LifecycleOperation,
  phase: ServicePhase,
  blocked: boolean,
): ConfirmKind | null => {
  if (operation === "recover") return "recover";
  if (operation === "start" && phase === "faulted") return "faulted-start";
  if (operation === "stop" && blocked) return "stop-blocked";
  return null;
};

interface LifecycleOptions {
  controller: StatusController;
  phase: ServicePhase;
  homeProfile: SavedProfile | undefined;
  storeRevision: number;
  profileOperationBusy: boolean;
  /** The running tunnel is blocking traffic; stopping it restores direct access. */
  blocked: boolean;
  onStarted: (profileId: string) => void;
}

export function useLifecycle({
  controller,
  phase,
  homeProfile,
  storeRevision,
  profileOperationBusy,
  blocked,
  onStarted,
}: LifecycleOptions) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LifecycleError | null>(null);
  // Every way of ending the tunnel other than its own switch asks first: the
  // tunnel is what keeps traffic from going directly.
  const [confirmDialog, setConfirmDialog] = useState<ConfirmKind | null>(null);

  const run = async (operation: LifecycleOperation, confirmed = false) => {
    if (busy) return;
    if (operation === "start" && profileOperationBusy) return;
    if (operation === "start" && !homeProfile) return;
    const confirmation = confirmed ? null : confirmationFor(operation, phase, blocked);
    if (confirmation) {
      setConfirmDialog(confirmation);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (operation === "start" && homeProfile) {
        await startSavedProfile(homeProfile.profileId, storeRevision);
        onStarted(homeProfile.profileId);
      } else if (operation === "stop") {
        await stopTunnel();
      } else {
        await recoverTunnel();
      }
      controller.invalidate();
      await controller.refresh();
    } catch (lifecycleError) {
      setError(normalizeLifecycleError(lifecycleError));
      controller.invalidate();
      await controller.refresh();
    } finally {
      setBusy(false);
    }
  };

  return { busy, error, confirmDialog, setConfirmDialog, run };
}

export type LifecycleApi = ReturnType<typeof useLifecycle>;
