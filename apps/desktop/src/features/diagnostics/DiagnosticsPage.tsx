import { useState } from "react";
import { PageHeader } from "../../app/PageHeader";
import type { ExitIpApi } from "../../app/use-exit-ip";
import { useI18n } from "../../i18n";
import type { DiagnosticError, WebsiteTarget, WebsiteTestResult } from "../../types";
import { Icon } from "../../ui/Icon";
import { normalizeDiagnosticError, runWebsiteTest } from "../home/home-client";
import { locationLabel, maskIpAddress } from "../home/home-model";
import type { TunnelAppearance } from "../overview/overview-model";
import { outcomeCounts, websiteOutcome } from "./diagnostics-model";
import "./diagnostics.css";

/** The fixed targets the host tests; hosts match the URLs the host requests. */
export const websiteTargets: { id: WebsiteTarget; label: string; host: string }[] = [
  { id: "github", label: "GitHub", host: "github.com" },
  { id: "google", label: "Google", host: "www.google.com" },
  { id: "youtube", label: "YouTube", host: "www.youtube.com" },
  { id: "apple", label: "Apple", host: "www.apple.com" },
  { id: "chatgpt", label: "ChatGPT", host: "chatgpt.com" },
  { id: "claude", label: "Claude", host: "claude.ai" },
  { id: "gemini", label: "Gemini", host: "gemini.google.com" },
  { id: "netflix", label: "Netflix", host: "www.netflix.com" },
  { id: "spotify", label: "Spotify", host: "open.spotify.com" },
  { id: "tiktok", label: "TikTok", host: "www.tiktok.com" },
];

interface DiagnosticsPageProps {
  appearance: TunnelAppearance;
  routeLabel: string | null;
  exitIp: ExitIpApi;
}

export function DiagnosticsPage({ appearance, routeLabel, exitIp }: DiagnosticsPageProps) {
  const { t, tf, language } = useI18n();
  const [results, setResults] = useState<Partial<Record<WebsiteTarget, WebsiteTestResult>>>({});
  const [busy, setBusy] = useState<WebsiteTarget | "all" | null>(null);
  const [error, setError] = useState<DiagnosticError | null>(null);
  const [checkedAt, setCheckedAt] = useState<number | null>(null);
  const [ipRevealed, setIpRevealed] = useState(true);

  const run = async (id: WebsiteTarget) => {
    try {
      const result = await runWebsiteTest(id);
      setResults((current) => ({ ...current, [id]: result }));
    } catch (value) {
      setError(normalizeDiagnosticError(value));
    }
  };
  const runOne = async (id: WebsiteTarget) => {
    if (busy) return;
    setBusy(id);
    setError(null);
    await run(id);
    setCheckedAt(Date.now());
    setBusy(null);
  };
  const runAll = async () => {
    if (busy) return;
    setBusy("all");
    setError(null);
    for (const { id } of websiteTargets) {
      await run(id);
    }
    setCheckedAt(Date.now());
    setBusy(null);
  };

  const tested = Object.values(results);
  const counts = outcomeCounts(tested.filter((result): result is WebsiteTestResult => Boolean(result)));
  const ip = exitIp.info;
  const tunnelOn = appearance.kind === "running" || appearance.kind === "blocked";
  // A blocked tunnel has no exit, so the exit address is only read while running.
  const exitAvailable = appearance.kind === "running";

  return (
    <div className="page">
      <PageHeader title={t("Diagnostics")} description={t("Check whether common services are reachable through the current route. Results do not reflect region or account permissions.")}>
        <button type="button" className="btn btn-primary" disabled={busy !== null} onClick={() => void runAll()}>{t(busy === "all" ? "Checking…" : "Check all")}</button>
      </PageHeader>

      <div className="route-banner">
        <span className="muted">{t("Route under test")}</span>
        <strong>{tunnelOn
          ? routeLabel ? tf("System TUN → {upstream}", { upstream: routeLabel }) : t("System TUN")
          : t("System TUN is off; checks go directly")}</strong>
        {checkedAt && (
          <span className="route-banner-meta">
            {tf("Checked {time} · {ok} reachable · {restricted} refused · {failed} failed", {
              time: new Intl.DateTimeFormat(language, { hour: "2-digit", minute: "2-digit", hour12: false }).format(checkedAt),
              ok: counts.ok,
              restricted: counts.restricted,
              failed: counts.failed,
            })}
          </span>
        )}
      </div>

      <div className="diagnostics-grid">
        <section className="panel target-panel">
          <div className="target-grid">
            {websiteTargets.map(({ id, label, host }) => {
              const result = results[id];
              const state = busy === id || (busy === "all" && !result) ? "testing" : !result ? "pending" : websiteOutcome(result);
              return (
                <div className={`target-cell target-${state}`} key={id}>
                  <div className="target-copy">
                    <strong>{label}</strong>
                    <span className="mono">{host}</span>
                  </div>
                  {state === "ok" && <span className="badge accent">{t("Reachable")}</span>}
                  {state === "restricted" && <span className="badge amber" title={t("The site answered through the tunnel but refused the request, which is common for data-centre exit addresses.")}>{tf("Refused · HTTP {code}", { code: result?.httpStatus ?? 0 })}</span>}
                  {state === "failed" && <span className="badge danger">{t("Failed")}</span>}
                  <span className="target-latency">{state === "ok" || state === "restricted" ? `${result?.latencyMs} ms` : state === "testing" ? t("Testing…") : "—"}</span>
                  <button type="button" className="icon-close" aria-label={tf("Check {name}", { name: label })} disabled={busy !== null} onClick={() => void runOne(id)}><Icon name="sync" size={13} /></button>
                </div>
              );
            })}
          </div>
          <div className="panel-foot">
            <span>{t("Each check requests a fixed public address through the current route.")}</span>
          </div>
          {error && <div className="panel-body"><div className="notice danger" role="status"><Icon name="alert" size={15} /><span>{t(error.safeMessage)}</span></div></div>}
        </section>

        <section className="panel exit-ip-panel">
          <div className="panel-head">
            <h3>{t("Exit IP")}</h3>
            {exitAvailable && <button type="button" className="btn btn-link" disabled={exitIp.loading} onClick={exitIp.refresh}>{t(exitIp.loading ? "Checking…" : "Refresh")}</button>}
          </div>
          <div className="panel-body">
            {!exitAvailable ? (
              <p className="muted">{t("Shown while System TUN is running, so the address you see is the tunnel exit.")}</p>
            ) : ip ? (
              <dl className="detail-list">
                <dt>IP</dt>
                <dd className="mono">{ipRevealed ? ip.ip : maskIpAddress(ip.ip)} <button type="button" className="btn btn-link inline" onClick={() => setIpRevealed((value) => !value)}>{t(ipRevealed ? "Hide" : "Show")}</button></dd>
                <dt>{t("Network")}</dt><dd>{ip.organization || t("Not reported")}</dd>
                <dt>{t("Location")}</dt><dd>{locationLabel(ip.country, ip.region, ip.city) || t("Not reported")}</dd>
                <dt>{t("Timezone")}</dt><dd>{ip.timezone || t("Not reported")}</dd>
                <dt>{t("Provider")}</dt><dd>ipinfo.io</dd>
              </dl>
            ) : (
              <p className="muted">{exitIp.loading ? t("Loading IP information…") : exitIp.error ? t(exitIp.error.safeMessage) : t("IP information unavailable")}</p>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
