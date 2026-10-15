import { useI18n } from "../../i18n";
import type { ProfileAvailability, ProfileAvailabilityMap } from "../../profile-availability";
import type { LocalProxyCandidate, SavedProfile } from "../../types";
import { availabilityCopy } from "../upstreams/availability-copy";
import { profileEndpointLabel, profileProtocolOf } from "../upstreams/profile-format";

export const protocolLabel = (profile: SavedProfile): string => {
  const protocol = profileProtocolOf(profile.upstream).toUpperCase();
  return profile.upstream.kind === "remote_server" && profile.upstream.protocolConfig.tls
    ? `${protocol} + TLS`
    : protocol;
};

export function AvailabilityText({ availability, className = "" }: { availability: ProfileAvailability | undefined; className?: string }) {
  const { t, tf } = useI18n();
  const copy = availabilityCopy(availability);
  return (
    <span className={`availability tone-${copy.tone} ${className}`.trim()}>
      {copy.latencyMs === null ? t(copy.label) : tf(copy.label, { ms: copy.latencyMs })}
    </span>
  );
}

interface CurrentUpstreamCardProps {
  title: string;
  profile: SavedProfile | undefined;
  availability: ProfileAvailability | undefined;
  footnote: string;
  onManage: () => void;
}

export function CurrentUpstreamCard({ title, profile, availability, footnote, onManage }: CurrentUpstreamCardProps) {
  const { t } = useI18n();
  const copy = availabilityCopy(availability);
  return (
    <section className="panel current-upstream">
      <div className="panel-head">
        <h3>{title}</h3>
        {profile && <span className={`badge ${copy.tone === "neutral" ? "" : copy.tone}`}><AvailabilityText availability={availability} className="plain" /></span>}
      </div>
      {profile ? (
        <>
          <div className="upstream-box">
            <strong>{profile.displayName}</strong>
            <span className="mono">{protocolLabel(profile)} · {profileEndpointLabel(profile.upstream)}</span>
          </div>
          <dl className="fact-list">
            <dt>{t("On upstream outage")}</dt><dd><strong>{t("Block traffic")}</strong></dd>
            <dt>{t("Type")}</dt><dd>{t(profile.upstream.kind === "local_listener" ? "Local listener" : "Remote server")}</dd>
            <dt>{t("Credential")}</dt><dd>{t(profile.hasCredential ? "Saved" : "None")}</dd>
          </dl>
        </>
      ) : (
        <p className="panel-body muted">{t("This session was opened elsewhere, so its upstream is not known here.")}</p>
      )}
      <div className="panel-foot">
        <span>{t(footnote)}</span>
        <button type="button" className="btn btn-link" onClick={onManage}>{t("Manage upstreams →")}</button>
      </div>
    </section>
  );
}

interface UpstreamPickerProps {
  profiles: SavedProfile[];
  availability: ProfileAvailabilityMap;
  selectedId: string | null;
  disabled: boolean;
  testsBusy: boolean;
  onChoose: (profileId: string) => void;
  onTestAll: () => void;
  onEdit: (profileId: string) => void;
}

export function UpstreamPicker({ profiles, availability, selectedId, disabled, testsBusy, onChoose, onTestAll, onEdit }: UpstreamPickerProps) {
  const { t } = useI18n();
  return (
    <fieldset className="upstream-picker" disabled={disabled}>
      <div className="upstream-picker-legend">
        <legend>{t("Which upstream to use")}</legend>
        <button type="button" className="btn btn-link" disabled={testsBusy} onClick={onTestAll}>{t(testsBusy ? "Testing…" : "Test all")}</button>
      </div>
      <div className="upstream-picker-grid">
        {profiles.map((profile) => {
          const state = availability[profile.profileId]?.state ?? "pending";
          const selected = profile.profileId === selectedId;
          const selectable = selected || state === "available";
          return (
            <label key={profile.profileId} className={`upstream-option${selected ? " selected" : ""}${selectable ? "" : " unavailable"}`}>
              <input
                type="radio"
                name="overview-upstream"
                checked={selected}
                disabled={!selectable}
                onChange={() => onChoose(profile.profileId)}
              />
              <span className="upstream-option-copy">
                <strong>{profile.displayName}</strong>
                <span className="mono">{protocolLabel(profile)} {profileEndpointLabel(profile.upstream)}</span>
                <span>
                  <AvailabilityText availability={availability[profile.profileId]} />
                  {state === "unavailable" && <> · <button type="button" className="btn btn-link inline" onClick={() => onEdit(profile.profileId)}>{t("Fix it")}</button></>}
                </span>
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

interface DiscoveryCardProps {
  candidates: LocalProxyCandidate[];
  scanned: boolean;
  discovering: boolean;
  onScan: () => void;
  onAdd: (candidate: LocalProxyCandidate) => void;
}

export function DiscoveryCard({ candidates, scanned, discovering, onScan, onAdd }: DiscoveryCardProps) {
  const { t, tf } = useI18n();
  return (
    <section className="panel discovery-card">
      <div className="panel-head">
        <h3>{t("Local discovery")}</h3>
        <button type="button" className="btn btn-link" disabled={discovering} onClick={onScan}>{t(discovering ? "Scanning…" : scanned ? "Scan again" : "Scan")}</button>
      </div>
      <div className="panel-body discovery-body">
        <p>{discovering
          ? t("Scanning loopback ports…")
          : !scanned
            ? t("Find proxies already listening on this computer.")
            : candidates.length === 0
              ? t("No unsaved local proxy listeners found.")
              : tf("Unsaved local proxy listeners found: {count}.", { count: candidates.length })}</p>
        {candidates.map((candidate) => (
          <div className="discovery-row" key={`${candidate.protocol}-${candidate.port}`}>
            <span>
              <strong className="mono">127.0.0.1:{candidate.port}</strong>
              <span>{candidate.protocol.toUpperCase()}{candidate.processHint ? ` · ${tf("process {name}", { name: candidate.processHint })}` : ""}</span>
            </span>
            <button type="button" className="btn btn-link" onClick={() => onAdd(candidate)}>{t("Test and add")}</button>
          </div>
        ))}
      </div>
      <div className="panel-foot"><span>{t("Only local listeners are checked; the LAN is never scanned.")}</span></div>
    </section>
  );
}
