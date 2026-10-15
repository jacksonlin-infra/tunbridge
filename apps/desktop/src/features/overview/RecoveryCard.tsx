import type { ReactNode } from "react";
import { useI18n } from "../../i18n";
import type { ProfileAvailability } from "../../profile-availability";
import type { SavedProfile, WatchdogReason } from "../../types";
import { testErrorLabel } from "../upstreams/availability-copy";
import { profileEndpointLabel } from "../upstreams/profile-format";

type CheckState = "ok" | "fail" | "pending";

interface RecoveryCardProps {
  reason: WatchdogReason;
  engineRunning: boolean;
  profile: SavedProfile | undefined;
  availability: ProfileAvailability;
  checking: boolean;
  onEditProfile: (profileId: string) => void;
  onOpenDiagnostics: () => void;
}

function Check({ state, children }: { state: CheckState; children: ReactNode }) {
  const { t } = useI18n();
  return (
    <li className={`check-row check-${state}`}>
      <span className="check-mark" aria-label={t(state === "ok" ? "OK" : state === "fail" ? "Failed" : "Not checked")}>
        {state === "ok" ? "✓" : state === "fail" ? "×" : "…"}
      </span>
      <span>{children}</span>
    </li>
  );
}

/** What is known about the outage, from sources the UI already has. */
export function RecoveryCard({ reason, engineRunning, profile, availability, checking, onEditProfile, onOpenDiagnostics }: RecoveryCardProps) {
  const { t, tf, language } = useI18n();
  const checkedAt = availability.state === "available" || availability.state === "unavailable" ? availability.checkedAt : undefined;
  const endpoint = profile ? profileEndpointLabel(profile.upstream) : null;
  const upstreamCheck: { state: CheckState; text: ReactNode } = checking
    ? { state: "pending", text: t("Testing the upstream…") }
    : availability.state === "unavailable"
    ? {
        state: "fail",
        text: <><strong>{endpoint ? `${endpoint} · ${t(testErrorLabel(availability.errorCode))}` : t(testErrorLabel(availability.errorCode))}</strong><span className="muted"> · {t(availability.errorCode === "connect_failed" ? "your proxy client may have exited" : "check the upstream settings")}</span></>,
      }
    : availability.state === "available"
      ? { state: "ok", text: t("The upstream answers again; waiting for the service to resume") }
      : availability.state === "testing"
        ? { state: "pending", text: t("Testing the upstream…") }
        : { state: "pending", text: t("The upstream has not been tested yet") };
  return (
    <section className="panel recovery-card">
      <div className="panel-head">
        <h3>{t("How to recover")}</h3>
        {checkedAt && !checking && (
          <span className="panel-meta">{tf("Checked {time}", { time: new Intl.DateTimeFormat(language, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(checkedAt) })}</span>
        )}
      </div>
      <div className="panel-body">
        <ul className="check-list">
          {reason === "upstream_unavailable" && <Check state={upstreamCheck.state}>{upstreamCheck.text}</Check>}
          <Check state={engineRunning ? "ok" : "fail"}>
            {t(engineRunning ? "TUN and the engine are running" : "The engine is not running; the service is restarting it")}
          </Check>
        </ul>
        <ol className="recovery-steps">
          {reason === "upstream_unavailable" ? (
            <li>{t("Start or restart your proxy client. This page turns green once the upstream is back.")}</li>
          ) : (
            <li>{t("Wait a moment: the service restarts the engine and traffic resumes on its own.")}</li>
          )}
          {profile && (
            <li>
              {t("Did the port change?")}{" "}
              <button type="button" className="btn btn-link inline" onClick={() => onEditProfile(profile.profileId)}>{tf("Edit upstream “{name}”", { name: profile.displayName })}</button>
            </li>
          )}
          <li>
            {t("Still not working?")}{" "}
            <button type="button" className="btn btn-link inline" onClick={onOpenDiagnostics}>{t("Run diagnostics")}</button>
          </li>
        </ol>
      </div>
    </section>
  );
}
