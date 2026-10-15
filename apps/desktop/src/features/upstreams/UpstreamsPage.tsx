import { useEffect } from "react";
import { PageHeader } from "../../app/PageHeader";
import { useI18n } from "../../i18n";
import { profileMutationLocked } from "../../profile-availability";
import type { LocalProxyCandidate, ServicePhase } from "../../types";
import { Icon } from "../../ui/Icon";
import { AvailabilityText, protocolLabel } from "../overview/UpstreamCards";
import { availabilityCopy } from "./availability-copy";
import { savedProfileFor } from "./discovery-model";
import { profileEndpointLabel } from "./profile-format";
import { ProfileEditor } from "./ProfileEditor";
import type { DiscoveryApi } from "./use-discovery";
import type { ProfilesApi } from "./use-profiles";
import "./upstreams.css";

interface UpstreamsPageProps {
  phase: ServicePhase;
  activeProfileId: string | null;
  credentialStore: string;
  profilesApi: ProfilesApi;
  discovery: DiscoveryApi;
  onAddCandidate: (candidate: LocalProxyCandidate) => void;
}

export function UpstreamsPage({ phase, activeProfileId, credentialStore, profilesApi, discovery, onAddCandidate }: UpstreamsPageProps) {
  const { t, tf, language } = useI18n();
  const {
    profiles,
    profilesLoaded,
    availability,
    testsBusy,
    profileBusy,
    deleteArmedId,
    editorOpen,
    editingProfileId,
    resetEditor,
    selectProfile,
    removeProfile,
    runSavedTest,
    runAllProfileTests,
  } = profilesApi;
  const list = profiles.profiles;

  useEffect(() => {
    if (!discovery.scanned && !discovery.discovering) void discovery.runDiscovery();
  }, []);
  const scannedAt = discovery.scannedAt
    ? new Intl.DateTimeFormat(language, { hour: "2-digit", minute: "2-digit", hour12: false }).format(discovery.scannedAt)
    : null;
  return (
    <div className="page">
      <PageHeader title={t("Upstreams")} description={t("Your existing HTTP(S) / SOCKS5 proxies. TunBridge only hands system traffic to them and never provides nodes.")}>
        <button type="button" className="btn" disabled={discovery.discovering} onClick={() => void discovery.runDiscovery()}>
          <Icon name="sync" size={15} />{t(discovery.discovering ? "Scanning…" : "Discover again")}
        </button>
        <button type="button" className="btn btn-primary" disabled={profileBusy} onClick={resetEditor}>
          <Icon name="plus" size={15} />{t("Add upstream")}
        </button>
      </PageHeader>

      <div className="upstreams-grid">
        <div className="upstreams-main">
          <section className="panel">
            <div className="panel-head">
              <h3>{t("Saved")} <span className="muted">{list.length}</span></h3>
              <button type="button" className="btn btn-link" disabled={testsBusy || profileBusy || list.length === 0} onClick={() => void runAllProfileTests()}>{t(testsBusy ? "Testing…" : "Test all")}</button>
            </div>
            {!profilesLoaded ? (
              <div className="empty-panel compact">{t("Loading protected profiles…")}</div>
            ) : list.length === 0 ? (
              <div className="empty-panel compact">
                <strong>{t("No saved upstream yet")}</strong>
                <span>{t("Add a proxy that already runs on this computer, or a remote proxy you can reach.")}</span>
              </div>
            ) : (
              <table className="data-table upstream-table">
                <thead>
                  <tr>
                    <th>{t("Name / address")}</th>
                    <th>{t("Role")}</th>
                    <th>{t("Status")}</th>
                    <th className="actions">{t("Actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((profile) => {
                    const inUse = phase === "running" && profile.profileId === activeProfileId;
                    const locked = profileMutationLocked(phase, activeProfileId, profile.profileId);
                    const copy = availabilityCopy(availability[profile.profileId]);
                    const details = [
                      protocolLabel(profile),
                      profileEndpointLabel(profile.upstream),
                      profile.hasCredential ? t("credential") : null,
                    ].filter(Boolean).join(" · ");
                    return (
                      <tr key={profile.profileId} className={editorOpen && profile.profileId === editingProfileId ? "selected" : undefined}>
                        <td>
                          <strong>{profile.displayName}</strong>
                          <span className="mono">{details}</span>
                        </td>
                        <td>{inUse ? <span className="badge solid">{t("In use")}</span> : <span className="muted">—</span>}</td>
                        <td>{copy.tone === "danger"
                          ? <span className="badge danger"><AvailabilityText availability={availability[profile.profileId]} className="plain" /></span>
                          : <AvailabilityText availability={availability[profile.profileId]} />}</td>
                        <td className="actions">
                          {locked ? (
                            <span className="locked-note"><Icon name="lock" size={12} />{t("Locked while running")}</span>
                          ) : (
                            <span className="row-actions">
                              <button type="button" className="btn btn-link" disabled={profileBusy || testsBusy} onClick={() => void runSavedTest(profile.profileId)}>{t("Test")}</button>
                              <button type="button" className="btn btn-link" onClick={() => selectProfile(profile.profileId)}>{t("Edit")}</button>
                              <button type="button" className="btn btn-link danger" disabled={profileBusy} onClick={() => void removeProfile(profile.profileId)}>{t(deleteArmedId === profile.profileId ? "Confirm delete" : "Delete")}</button>
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
            <div className="panel-foot">
              <span>{tf("Credentials are stored in {store} and never shown again after saving. Stop TUN before editing the upstream in use.", { store: t(credentialStore) })}</span>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <h3>{t("Local discovery")}</h3>
                <span className="panel-meta">{t("Only local listening ports are checked; the LAN is never scanned.")}{scannedAt ? ` · ${tf("updated {time}", { time: scannedAt })}` : ""}</span>
              </div>
            </div>
            <div className="panel-body discovery-list">
              {discovery.warningCodes.length > 0 && <div className="notice amber"><Icon name="alert" size={15} /><span>{t("Scan completed with limited listener information.")}</span></div>}
              {discovery.error && <div className="notice danger"><Icon name="alert" size={15} /><span>{t(discovery.error.safeMessage)}</span></div>}
              {!discovery.scanned && !discovery.discovering && (
                <div className="discovery-empty">
                  <span>{t("Find proxies already listening on this computer.")}</span>
                  <button type="button" className="btn" onClick={() => void discovery.runDiscovery()}>{t("Scan")}</button>
                </div>
              )}
              {discovery.discovering && <div className="discovery-empty"><span>{t("Scanning loopback ports…")}</span></div>}
              {discovery.scanned && !discovery.discovering && discovery.candidates.length === 0 && (
                <div className="discovery-empty"><span>{t("No local proxy listener found. Start your proxy app, then discover again.")}</span></div>
              )}
              {!discovery.discovering && discovery.candidates.map((candidate) => {
                const saved = savedProfileFor(candidate, list);
                return (
                  <div className="discovery-item" key={`${candidate.protocol}-${candidate.port}`}>
                    <span>
                      <strong className="mono">127.0.0.1:{candidate.port}</strong>
                      <span>{candidate.protocol.toUpperCase()}{candidate.processHint ? ` · ${tf("process {name}", { name: candidate.processHint })}` : ""}</span>
                    </span>
                    {saved
                      ? <span className="muted">{tf("Saved as “{name}”", { name: saved.displayName })}</span>
                      : <button type="button" className="btn" disabled={discovery.testing} onClick={() => onAddCandidate(candidate)}>{t("Test and add")}</button>}
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        <div className="upstreams-side">
          {editorOpen && (
            <ProfileEditor
              profilesApi={profilesApi}
              credentialStore={credentialStore}
              candidateTest={discovery.candidateTest}
            />
          )}
          <section className="panel policy-card">
            <div className="panel-head"><h3>{t("When the upstream goes down")}</h3></div>
            <div className="panel-body">
              <div className="notice accent">
                <Icon name="shield-check" size={16} />
                <span><strong>{t("Block traffic, never go direct")}</strong>{t("TUN stays on and the system notifies you. Traffic resumes automatically when the upstream is back. This cannot be turned off.")}</span>
              </div>
              <p className="policy-note">{t("Need direct access? Stop TUN yourself on the overview. TunBridge never lets traffic through on its own because of a failure.")}</p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
