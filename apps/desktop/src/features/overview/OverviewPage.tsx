import { useEffect, useRef, useState } from "react";
import "./overview.css";
import type { ViewId } from "../../app/navigation";
import type { ExitIpApi } from "../../app/use-exit-ip";
import type { LifecycleApi } from "../../app/use-lifecycle";
import { useI18n } from "../../i18n";
import type { ProfileAvailability } from "../../profile-availability";
import type { DesktopStatus, LocalProxyCandidate, SavedProfile, ServicePhase, TunnelEvent } from "../../types";
import { Icon } from "../../ui/Icon";
import { maskIpAddress, shortLocation } from "../home/home-model";
import { statusNotice } from "../home/status-notice";
import { formatRate } from "../traffic/traffic-model";
import type { useTraffic } from "../traffic/use-traffic";
import { testErrorLabel } from "../upstreams/availability-copy";
import { profileEndpointLabel } from "../upstreams/profile-format";
import type { DiscoveryApi } from "../upstreams/use-discovery";
import type { ProfilesApi } from "../upstreams/use-profiles";
import { LastSessionCard, RecentEventsCard } from "../history/HistoryCards";
import { formatDuration, formatEventTime } from "../history/history-copy";
import { currentSession, lastSession, openBlock, type SessionSummary } from "../history/history-model";
import { LiveTrafficCard } from "./LiveTrafficCard";
import { appearanceTone, failedHop, faultHoldsTraffic, startBlockedReason, type TunnelAppearance } from "./overview-model";
import { RecoveryCard } from "./RecoveryCard";
import { blockedFallbackTitle, blockedTitles, lastKnownLabels, reasonLabel } from "./tunnel-copy";
import { RouteChain, TunnelCard, type Hop } from "./TunnelCard";
import { CurrentUpstreamCard, DiscoveryCard, protocolLabel, UpstreamPicker } from "./UpstreamCards";

interface OverviewPageProps {
  appearance: TunnelAppearance;
  status: DesktopStatus | undefined;
  homeProfile: SavedProfile | undefined;
  /** False when the running session belongs to another user session. */
  activeProfileKnown: boolean;
  homeAvailability: ProfileAvailability;
  /** Whether the phase's own start or stop action is unavailable right now. */
  lifecycleDisabled: boolean;
  profileSelectIsDisabled: boolean;
  chooseHomeProfile: (profileId: string) => void;
  lifecycle: LifecycleApi;
  profilesApi: ProfilesApi;
  traffic: ReturnType<typeof useTraffic>;
  exitIp: ExitIpApi;
  discovery: DiscoveryApi;
  /** The local tunnel event log, oldest first. */
  events: TunnelEvent[];
  now: number;
  unsavedCandidates: LocalProxyCandidate[];
  onAddCandidate: (candidate: LocalProxyCandidate) => void;
  onEditProfile: (profileId: string) => void;
  navigate: (view: ViewId) => void;
}

export function OverviewPage(props: OverviewPageProps) {
  const {
    appearance,
    status,
    homeProfile,
    activeProfileKnown,
    homeAvailability,
    lifecycleDisabled,
    profileSelectIsDisabled,
    chooseHomeProfile,
    lifecycle,
    profilesApi,
    traffic,
    exitIp,
    discovery,
    unsavedCandidates,
    onAddCandidate,
    onEditProfile,
    navigate,
    events,
    now,
  } = props;
  const { t, tf, language } = useI18n();
  const [ipRevealed, setIpRevealed] = useState(true);
  const tone = appearanceTone(appearance);
  const upstreamName = homeProfile && activeProfileKnown ? homeProfile.displayName : null;
  const latency = upstreamName && homeAvailability.state === "available" ? homeAvailability.latencyMs : null;
  const upstreamEndpoint = homeProfile && activeProfileKnown
    ? `${protocolLabel(homeProfile)} ${profileEndpointLabel(homeProfile.upstream)}`
    : null;
  const stopped = appearance.kind === "stopped";
  const session = currentSession(events);
  const block = openBlock(events);

  useEffect(() => {
    if (stopped && !discovery.scanned && !discovery.discovering) void discovery.runDiscovery();
  }, [stopped]);

  // Re-check the upstream once each time the tunnel starts blocking because of
  // it. This only tests the saved profile; it never changes the service.
  const recheckable = appearance.kind === "blocked" && appearance.owned && Boolean(upstreamName) && homeProfile !== undefined;
  const blockedKey = appearance.kind === "blocked" ? appearance.reason : null;
  const autoChecked = useRef<string | null>(null);
  const recheckUpstream = () => {
    if (homeProfile) void profilesApi.runSavedTest(homeProfile.profileId);
  };
  useEffect(() => {
    if (blockedKey === null) {
      autoChecked.current = null;
      return;
    }
    if (blockedKey !== "upstream_unavailable" || !recheckable || autoChecked.current === blockedKey) return;
    if (profilesApi.profileBusy || profilesApi.testsBusy) return;
    autoChecked.current = blockedKey;
    recheckUpstream();
  }, [blockedKey, recheckable, profilesApi.profileBusy, profilesApi.testsBusy]);
  const checking = homeAvailability.state === "testing" || (profilesApi.profileBusy && recheckable);

  const policyFooter = (
    <span className="tunnel-policy"><Icon name="lock" size={13} />{t("Blocks on outage, never direct")}</span>
  );

  if (appearance.kind === "running" || appearance.kind === "blocked") {
    const blocked = appearance.kind === "blocked";
    const failing = blocked ? failedHop(appearance.reason) : null;
    const lastError = homeAvailability.state === "unavailable" ? homeAvailability.errorCode : null;
    const ip = exitIp.info;
    const hops: Hop[] = blocked
      ? [
          { key: "app", label: t("Apps"), state: "warn", title: t("Traffic blocked"), detail: t("Apps retry on their own") },
          failing === "tun"
            ? { key: "tun", label: t("TUN · fault"), state: "fail", title: t(reasonLabel(appearance.reason)), detail: t("Traffic stays blocked") }
            : { key: "tun", label: t("TUN · normal"), state: "ok", title: t("TUN on"), detail: t("Capturing traffic") },
          {
            key: "upstream",
            label: failing === "upstream"
              ? `${t("Upstream")} · ${t(lastError ? testErrorLabel(lastError) : "Unreachable")}`
              : t("Upstream"),
            state: failing === "upstream" ? "fail" : "idle",
            emphasis: failing === "upstream",
            title: upstreamName ?? t(appearance.owned ? "Upstream not known" : "Upstream of another session"),
            detail: upstreamEndpoint && <span className="mono">{upstreamEndpoint}</span>,
          },
          { key: "exit", label: t("Exit"), state: "idle", title: t("None"), detail: t("Not connected directly to the internet") },
        ]
      : [
          {
            key: "app",
            label: t("Apps"),
            state: "ok",
            title: traffic.snapshot ? tf("{count} active connections", { count: traffic.snapshot.activeConnections }) : t("System traffic"),
            detail: t("All processes on this computer"),
          },
          { key: "tun", label: "TUN", state: "ok", title: t("TUN on"), detail: t("Capturing traffic") },
          {
            key: "upstream",
            label: latency === null ? t("Upstream") : tf("Upstream · {ms} ms", { ms: latency }),
            state: "ok",
            emphasis: true,
            title: upstreamName ?? t(appearance.owned ? "Upstream not known" : "Upstream of another session"),
            detail: upstreamEndpoint && <span className="mono">{upstreamEndpoint}</span>,
          },
          {
            key: "exit",
            label: t("Exit"),
            state: "ok",
            mono: Boolean(ip),
            title: ip ? (ipRevealed ? ip.ip : maskIpAddress(ip.ip)) : exitIp.loading ? t("Checking…") : "—",
            detail: ip ? (
              <>
                {shortLocation(ip) && <span className="exit-org">{shortLocation(ip)}</span>}
                <button type="button" className="btn btn-link inline" onClick={() => setIpRevealed((value) => !value)}>{t(ipRevealed ? "Hide" : "Show")}</button>
              </>
            ) : !exitIp.loading && (
              <button type="button" className="btn btn-link inline" onClick={exitIp.refresh}>{t("Detect exit IP")}</button>
            ),
          },
        ];

    return (
      <>
        <TunnelCard
          tone={tone}
          icon={blocked ? "shield-pause" : "shield-check"}
          overline={`SYSTEM TUN · ${t(blocked ? "Blocking" : "Running")}`}
          title={blocked ? t(blockedTitles[appearance.reason] ?? blockedFallbackTitle) : t("System TUN is running")}
          description={blocked
            ? t("TUN stays on and nothing goes directly. It resumes automatically once this recovers.")
            : upstreamName
              ? tf("All system traffic goes through upstream “{name}”.", { name: upstreamName })
              : t(appearance.owned
                ? "This session was not turned on from this App, so which upstream it uses is not known. Turn TUN off and on here to see it."
                : "System traffic goes through the upstream chosen by another session.")}
          actions={appearance.owned ? (
            blocked ? (
              <>
                <button type="button" className="btn btn-primary" disabled={!recheckable || checking || profilesApi.testsBusy} onClick={recheckUpstream}>
                  <Icon name="sync" size={15} />{t(checking ? "Checking upstream…" : "Re-check upstream")}
                </button>
                <button type="button" className="btn btn-link danger" disabled={lifecycleDisabled} onClick={() => void lifecycle.run("stop")}>{t("Stop TUN and restore direct access…")}</button>
              </>
            ) : (
              <>
                <button type="button" className="btn" disabled={lifecycleDisabled} onClick={() => void lifecycle.run("stop")}>
                  <Icon name="power" size={16} strokeWidth={1.9} />{t(lifecycle.busy ? "Stopping…" : "Stop TUN")}
                </button>
                <span className="tunnel-action-note">{t("Stopping restores the network; traffic then goes directly")}</span>
              </>
            )
          ) : (
            <span className="tunnel-action-note">{t("Opened by another session; view only")}</span>
          )}
          footer={<>
            {blocked && block && <strong className="tunnel-foot-strong">{tf("Blocked for {duration}", { duration: formatDuration(now - block.since, tf) })}</strong>}
            {!blocked && session && <span>{tf("Running for {duration}", { duration: `${session.exact ? "" : "≥ "}${formatDuration(now - session.startedAt, tf)}` })}</span>}
            {policyFooter}
            {blocked && block && <span className="tunnel-foot-end">{tf("Since {time}", { time: formatEventTime(block.since, language, now) })}</span>}
            {!blocked && session && (
              <span className="tunnel-foot-end">{session.exact
                ? tf("You turned it on at {time}", { time: formatEventTime(session.startedAt, language, now) })
                : tf("Running when TunBridge started at {time}", { time: formatEventTime(session.startedAt, language, now) })}</span>
            )}
          </>}
        >
          <RouteChain hops={hops} label={t("Current route")} />
        </TunnelCard>

        {blocked ? (
          <div className="overview-grid">
            <RecoveryCard
              reason={appearance.reason}
              engineRunning={status?.engineRunning ?? false}
              profile={upstreamName ? homeProfile : undefined}
              availability={homeAvailability}
              checking={checking}
              onEditProfile={onEditProfile}
              onOpenDiagnostics={() => navigate("diagnostics")}
            />
            <div className="overview-stack">
              <CurrentUpstreamCard
                title={t("Current upstream")}
                profile={upstreamName ? homeProfile : undefined}
                availability={homeAvailability}
                footnote="Stop TUN before switching upstreams"
                onManage={() => navigate("upstreams")}
              />
              <section className="panel mini-traffic">
                <div>
                  <span>{t("Live traffic")}</span>
                  <strong>{traffic.snapshot ? formatRate(traffic.snapshot.downloadBps + traffic.snapshot.uploadBps) : "—"}</strong>
                </div>
                <button type="button" className="btn btn-link" onClick={() => navigate("activity")}>{t("Open activity →")}</button>
              </section>
            </div>
          </div>
        ) : (
          <div className="overview-grid">
            {traffic.snapshot || appearance.owned ? (
              <LiveTrafficCard
                snapshot={traffic.snapshot}
                history={traffic.history}
                error={traffic.error}
                onOpenActivity={() => navigate("activity")}
              />
            ) : (
              <section className="panel">
                <div className="panel-head"><h3>{t("Live traffic")}</h3></div>
                <p className="panel-body muted">{t("Traffic is only visible to the session that opened the tunnel.")}</p>
              </section>
            )}
            <CurrentUpstreamCard
              title={t("Current upstream")}
              profile={upstreamName ? homeProfile : undefined}
              availability={homeAvailability}
              footnote="Stop TUN before switching upstreams"
              onManage={() => navigate("upstreams")}
            />
          </div>
        )}
        {!blocked && appearance.owned && (
          <div className="overview-grid single">
            <RecentEventsCard events={events} profiles={profilesApi.profiles.profiles} now={now} />
          </div>
        )}
      </>
    );
  }

  if (appearance.kind === "stopped") {
    const notice = statusNotice(status);
    const previous = lastSession(events);
    const stoppedFootnote = (summary: SessionSummary) => {
      const time = formatEventTime(summary.endedAt, language, now);
      if (summary.endKind === "recovered") return tf("{time} you restored the previous network", { time });
      if (summary.endedBy === "user") return tf("{time} stopped by you; the previous network was restored", { time });
      if (summary.endedBy === "service") return tf("{time} stopped automatically", { time });
      return tf("{time} stopped outside this App", { time });
    };
    const startHint = startBlockedReason({
      lifecycleBusy: lifecycle.busy,
      readOnly: status?.readOnly === true,
      hasProfile: homeProfile !== undefined,
      testing: profilesApi.testsBusy || profilesApi.profileBusy,
      availability: homeAvailability.state,
    });
    const profiles = profilesApi.profiles.profiles;
    return (
      <>
        <TunnelCard
          tone="neutral"
          icon="power"
          overline={`SYSTEM TUN · ${t("Stopped")}`}
          title={t("System TUN is stopped")}
          description={<>
            <p>{appearance.firstUse
              ? t("Add an upstream first: a proxy already running on this computer, or a remote proxy you can reach.")
              : t("System traffic currently goes directly without any proxy. Choose an upstream, then turn it on.")}</p>
            {notice && <p className="tunnel-auto-stop"><Icon name="alert" size={14} />{t(notice.title)} {t(notice.detail)}</p>}
          </>}
          actions={appearance.firstUse ? (
            <button type="button" className="btn btn-primary large" onClick={() => navigate("upstreams")}>
              <Icon name="plus" size={16} />{t("Add upstream")}
            </button>
          ) : (
            <>
              <button type="button" className="btn btn-primary large" disabled={lifecycleDisabled} onClick={() => void lifecycle.run("start")}>
                <Icon name="power" size={16} strokeWidth={1.9} />{t(lifecycle.busy ? "Starting…" : "Turn on TUN")}
              </button>
              {lifecycleDisabled && startHint && <span className="tunnel-action-note start-hint" role="status">{t(startHint)}</span>}
            </>
          )}
          footer={appearance.firstUse ? undefined : <>
            <span>{t("The chosen upstream is tested before TUN turns on")}</span>
            {policyFooter}
            {previous && <span className="tunnel-foot-end">{stoppedFootnote(previous)}</span>}
          </>}
        >
          {!appearance.firstUse && profiles.length > 0 && (
            <UpstreamPicker
              profiles={profiles}
              availability={profilesApi.availability}
              selectedId={homeProfile?.profileId ?? null}
              disabled={profileSelectIsDisabled}
              testsBusy={profilesApi.testsBusy || profilesApi.profileBusy}
              onChoose={chooseHomeProfile}
              onTestAll={() => void profilesApi.runAllProfileTests()}
              onEdit={onEditProfile}
            />
          )}
        </TunnelCard>
        <div className={previous || events.length > 0 ? "overview-grid" : "overview-grid single"}>
          {(previous || events.length > 0) && (
            <LastSessionCard summary={previous} events={events} profiles={profilesApi.profiles.profiles} now={now} />
          )}
          <DiscoveryCard
            candidates={unsavedCandidates}
            scanned={discovery.scanned}
            discovering={discovery.discovering}
            onScan={() => void discovery.runDiscovery()}
            onAdd={onAddCandidate}
          />
        </div>
      </>
    );
  }

  if (appearance.kind === "faulted" && !faultHoldsTraffic(appearance.reason)) {
    return (
      <>
        <TunnelCard
          tone="danger"
          icon="shield-alert"
          overline={`SYSTEM TUN · ${t("Needs cleanup")}`}
          title={t("The last TUN operation did not finish")}
          description={t("TunBridge could not finish turning System TUN on or off, so it cannot tell whether traffic is blocked or going directly. Restore the previous network to clean up, then turn TUN on again.")}
          actions={<>
            <button type="button" className="btn btn-primary" disabled={lifecycle.busy} onClick={() => void lifecycle.run("recover")}>{t("Restore network…")}</button>
            <button type="button" className="btn btn-link" disabled={lifecycleDisabled} onClick={() => void lifecycle.run("start")}>{t("Turn TUN on again")}</button>
          </>}
        />
        {events.length > 0 && (
          <div className="overview-grid single">
            <RecentEventsCard events={events} profiles={profilesApi.profiles.profiles} now={now} />
          </div>
        )}
      </>
    );
  }

  if (appearance.kind === "faulted") {
    const notice = statusNotice(status);
    return (
      <>
        <TunnelCard
          tone="danger"
          icon="shield-alert"
          overline={`SYSTEM TUN · ${t("Fault hold")}`}
          title={notice ? t(notice.title) : t("The tunnel needs attention")}
          description={t("TUN is still in place and traffic stays blocked, never direct. The previous network is restored only after you confirm.")}
          actions={<>
            <button type="button" className="btn btn-primary" disabled={lifecycleDisabled} onClick={() => void lifecycle.run("start")}>{t("Turn TUN on again")}</button>
            <button type="button" className="btn btn-link danger" disabled={lifecycle.busy} onClick={() => void lifecycle.run("recover")}>{t("Recover network…")}</button>
          </>}
          footer={policyFooter}
        />
        {events.length > 0 && (
          <div className="overview-grid single">
            <RecentEventsCard events={events} profiles={profilesApi.profiles.profiles} now={now} />
          </div>
        )}
      </>
    );
  }

  if (appearance.kind === "transition") {
    const copy = appearance.phase === "starting"
      ? { title: "Turning on System TUN…", detail: "Testing the upstream and capturing system traffic." }
      : appearance.phase === "stopping"
        ? { title: "Stopping System TUN…", detail: "Restoring routes and DNS to their state before TUN was turned on." }
        : { title: "Recovering the network…", detail: "Restoring routes and DNS to their state before TUN was turned on." };
    return (
      <TunnelCard tone="neutral" icon="sync" busy overline={`SYSTEM TUN · ${t("In progress")}`} title={t(copy.title)} description={t(copy.detail)} />
    );
  }

  if (appearance.kind === "unknown") {
    return (
      <TunnelCard
        tone="amber"
        icon="alert"
        overline={`SYSTEM TUN · ${t("Status unknown")}`}
        title={t("Cannot read the service status")}
        description={<>
          <p>{tf("Last known state: {state}. TunBridge never stops the tunnel because of this; the overview updates once the service answers again.", { state: t(lastKnownLabels[appearance.last.servicePhase]) })}</p>
          <p className="muted">{t(appearance.error.safeMessage)}</p>
        </>}
        actions={<button type="button" className="btn" onClick={() => navigate("settings")}>{t("Open service settings")}</button>}
      />
    );
  }

  if (appearance.kind === "unavailable") {
    return (
      <TunnelCard
        tone="danger"
        icon="alert"
        overline={`SYSTEM TUN · ${t("Service not ready")}`}
        title={t("The TunBridge service is not ready")}
        description={<>
          <p>{t(appearance.error.safeMessage)}</p>
          <p className="muted">{t("Install or repair the system service in Settings.")}</p>
        </>}
        actions={<button type="button" className="btn btn-primary" onClick={() => navigate("settings")}>{t("Open service settings")}</button>}
      />
    );
  }

  return <TunnelCard tone="neutral" icon="sync" busy overline="SYSTEM TUN" title={t("Checking…")} description={t("Reading the service status")} />;
}
