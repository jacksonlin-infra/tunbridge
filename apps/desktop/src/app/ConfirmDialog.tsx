import { useEffect } from "react";
import { useI18n } from "../i18n";
import type { ConfirmKind } from "./use-lifecycle";

interface ConfirmDialogProps {
  kind: ConfirmKind;
  onCancel: () => void;
  onExit: (stopTunnel: boolean) => void;
  onConfirmRecovery: (operation: "recover" | "start") => void;
  onConfirmStop: () => void;
  /** Words the stop question for an unreachable upstream rather than a generic block. */
  upstreamUnreachable: boolean;
  /** The fault was left by an unfinished operation, so no tunnel is known to hold traffic. */
  faultUnconfirmed: boolean;
}

/**
 * Every way of ending the tunnel other than its own stop button asks here.
 * The focused default is always the choice that keeps traffic blocked.
 */
export function ConfirmDialog({ kind, onCancel, onExit, onConfirmRecovery, onConfirmStop, upstreamUnreachable, faultUnconfirmed }: ConfirmDialogProps) {
  const { t } = useI18n();

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel]);

  if (kind === "exit") {
    return (
      <div className="dialog-overlay" role="presentation">
        <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-body">
          <h2 id="confirm-dialog-title">{t("Quit TunBridge?")}</h2>
          <p id="confirm-dialog-body">{t("System TUN is running.")}</p>
          <div className="dialog-options">
            <button type="button" className="dialog-option recommended" autoFocus onClick={() => onExit(false)}>
              <strong>{t("Keep TUN, close the window only")} <span>{t("Recommended")}</span></strong>
              <span>{t("Traffic keeps going through the upstream. Open the app again to manage it.")}</span>
            </button>
            <button type="button" className="dialog-option" onClick={() => onExit(true)}>
              <strong>{t("Stop TUN and quit")}</strong>
              <span>{t("Restores the original network; system traffic then goes directly.")}</span>
            </button>
          </div>
          <div className="dialog-actions">
            <button type="button" className="btn" onClick={onCancel}>{t("Cancel")}</button>
          </div>
        </div>
      </div>
    );
  }

  if (kind === "stop-blocked") {
    const stopBody = t(upstreamUnreachable
      ? "The upstream is unreachable right now. After stopping, system traffic {direct}, and your real IP is exposed to the services you visit."
      : "Traffic is being blocked right now. After stopping, system traffic {direct}, and your real IP is exposed to the services you visit.").split("{direct}");
    return (
      <div className="dialog-overlay" role="presentation">
        <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-body">
          <h2 id="confirm-dialog-title">{t("Stop TUN and go direct?")}</h2>
          <p id="confirm-dialog-body">{stopBody[0]}<span className="warning-text">{t("reaches the network directly without the proxy")}</span>{stopBody[1]}</p>
          <div className="dialog-actions">
            <button type="button" className="btn btn-primary" autoFocus onClick={onCancel}>{t("Keep blocking")}</button>
            <button type="button" className="btn btn-danger" onClick={onConfirmStop}>{t("Stop and go direct")}</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="dialog-overlay" role="presentation">
      <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-body">
        <h2 id="confirm-dialog-title">{t("Restore the previous network?")}</h2>
        <p id="confirm-dialog-body">{t(faultUnconfirmed
          ? "Recovering cleans up what the unfinished operation left behind and restores the previous network. Until you turn the tunnel on again, traffic goes directly without the proxy."
          : "Recovering removes the system tunnel that is holding traffic. Until you turn the tunnel on again, traffic goes directly without the proxy.")}</p>
        <div className="dialog-actions">
          <button type="button" className="btn btn-primary" autoFocus onClick={onCancel}>{t(faultUnconfirmed ? "Cancel" : "Keep blocking")}</button>
          <button type="button" className="btn btn-danger" onClick={() => onConfirmRecovery(kind === "recover" ? "recover" : "start")}>{t("Recover and continue")}</button>
        </div>
      </div>
    </div>
  );
}
