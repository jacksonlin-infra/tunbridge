import { useEffect, useMemo, useState } from "react";
import { invoke } from "./bridge";
import { ConfirmDialog } from "./app/ConfirmDialog";
import type { ActivityTab, NavigationTarget, ViewId } from "./app/navigation";
import { PageHeader } from "./app/PageHeader";
import { Sidebar } from "./app/Sidebar";
import { useExitIp } from "./app/use-exit-ip";
import { useRetestTriggers } from "./app/use-retest-triggers";
import { latestStatus, useDesktopStatus } from "./app/use-desktop-status";
import { useLifecycle } from "./app/use-lifecycle";
import { usePreferences } from "./app/use-preferences";
import { useTrayEvents } from "./app/use-tray-events";
import { useTunnelSelection } from "./app/use-tunnel-selection";
import { ActivityPage } from "./features/activity/ActivityPage";
import { currentSession, sessionProfileId } from "./features/history/history-model";
import { useNow, useTunnelEvents } from "./features/history/use-tunnel-events";
import { DiagnosticsPage } from "./features/diagnostics/DiagnosticsPage";
import { statusNotice } from "./features/home/status-notice";
import { tunnelAppearance } from "./features/overview/overview-model";
import { OverviewPage } from "./features/overview/OverviewPage";
import { protocolLabel } from "./features/overview/UpstreamCards";
import { SettingsPage } from "./features/settings/SettingsPage";
import { useAppUpdate } from "./features/settings/use-app-update";
import { useServiceMaintenance } from "./features/settings/use-service-maintenance";
import { useTraffic } from "./features/traffic/use-traffic";
import { unsavedCandidates } from "./features/upstreams/discovery-model";
import { profileEndpointLabel } from "./features/upstreams/profile-format";
import { UpstreamsPage } from "./features/upstreams/UpstreamsPage";
import { useDiscovery } from "./features/upstreams/use-discovery";
import { useProfiles } from "./features/upstreams/use-profiles";
import { I18nProvider, translate } from "./i18n";
import { canRequestStart, lifecycleErrorMessage } from "./lifecycle-client";
import { detectDesktopPlatform } from "./platform";
import {
  homeProfileId,
  initialDesiredProfileId,
  lifecycleToggleDisabled,
  profileIsAvailable,
  profileSelectionDisabled,
} from "./profile-availability";
import type { LocalProxyCandidate } from "./types";
import { Icon } from "./ui/Icon";

export default function App() {
  const platform = useMemo(() => detectDesktopPlatform(), []);
  const [activeView, setActiveView] = useState<ViewId>("overview");
  const [activityTab, setActivityTab] = useState<ActivityTab>("connections");
  const { language, setLanguage, themeMode, setThemeMode } = usePreferences();
  const t = (text: string) => translate(language, text);
  const { state, controller } = useDesktopStatus();

  const status = latestStatus(state);
  const phase = status?.servicePhase ?? "stopped";

  const selection = useTunnelSelection(phase, status?.callerIsOwner);
  const tunnelEvents = useTunnelEvents(`${phase}:${status?.degradedReason ?? ""}:${status?.stopReason ?? ""}`);
  // The profile the running session really uses: this App's own lease, or the
  // start this App recorded for the open session. Never the picker's choice.
  const runningProfileId = phase === "running" && status?.callerIsOwner === true
    ? selection.activeProfileId ?? sessionProfileId(tunnelEvents.events)
    : null;
  const [retestToken, setRetestToken] = useState(0);
  const [retestUnavailableToken, setRetestUnavailableToken] = useState(0);
  const currentHomeProfileId = homeProfileId(phase, selection.desiredProfileId, runningProfileId);
  const profilesApi = useProfiles({
    phase,
    activeProfileId: selection.activeProfileId,
    homeProfileId: currentHomeProfileId,
    // The upstream picker on the stopped overview needs every profile tested.
    testAllProfiles: activeView === "upstreams" || (activeView === "overview" && phase === "stopped"),
    retestToken,
    retestUnavailableToken,
  });
  const { profiles, profilesLoaded, availability: profileAvailability } = profilesApi;
  const profileOperationBusy = profilesApi.profileBusy || profilesApi.testsBusy;

  useEffect(() => {
    if (!profilesLoaded) return;
    selection.setDesiredProfileId((current) => initialDesiredProfileId(
      profiles.profiles,
      current ?? localStorage.getItem("tunbridge.desiredProfileId"),
    ));
  }, [profilesLoaded, profiles]);

  const homeProfile = profiles.profiles.find(
    (profile) => profile.profileId === currentHomeProfileId,
  );
  const homeAvailability = currentHomeProfileId
    ? profileAvailability[currentHomeProfileId] ?? { state: "pending" as const }
    : { state: "pending" as const };

  const appearance = tunnelAppearance(state, profilesLoaded ? profiles.profiles.length > 0 : null);
  const tunnelOn = appearance.kind === "running" || appearance.kind === "blocked";
  const now = useNow(tunnelOn || activeView === "overview");
  const session = tunnelOn ? currentSession(tunnelEvents.events) : null;

  const lifecycle = useLifecycle({
    controller,
    phase,
    homeProfile,
    storeRevision: profiles.storeRevision,
    profileOperationBusy,
    blocked: phase === "running" && Boolean(status?.degradedReason),
    onStarted: (profileId) => {
      selection.setActiveProfileId(profileId);
      tunnelEvents.refresh();
    },
  });
  const maintenance = useServiceMaintenance({ controller, phase, lifecycleBusy: lifecycle.busy });
  const appUpdateApi = useAppUpdate();
  useRetestTriggers(() => setRetestToken((value) => value + 1), () => setRetestUnavailableToken((value) => value + 1), {
    appearanceKind: appearance.kind,
    installerBusy: maintenance.installerBusy,
    periodic: appearance.kind === "stopped" && (activeView === "overview" || activeView === "upstreams"),
  });
  const discovery = useDiscovery();

  const profileSelectIsDisabled = profileSelectionDisabled(
    phase,
    lifecycle.busy,
    profiles.profiles.length,
  );
  const canObserveTraffic = phase === "running" && status?.callerIsOwner === true;
  const canObserveLogs = canObserveTraffic
    && status?.capabilities.includes("observe_mihomo_logs") === true;
  const traffic = useTraffic(canObserveTraffic);

  useTrayEvents({
    navigate: (target: NavigationTarget) => {
      setActiveView(target.view);
      if (target.activityTab) setActivityTab(target.activityTab);
    },
    exitFailed: () => maintenance.setSettingsError("The System TUN could not be stopped, so TunBridge remains open."),
    exitConfirm: () => lifecycle.setConfirmDialog("exit"),
  });

  const exitIp = useExitIp(appearance.kind === "running");
  const canStart = Boolean(
    homeProfile
      && profileIsAvailable(profileAvailability, homeProfile.profileId)
      && canRequestStart(phase)
      && status?.readOnly === false,
  );
  const canStop = phase === "running" && status?.callerIsOwner === true;
  const toggleDisabled = lifecycleToggleDisabled(
    phase,
    canStart,
    canStop,
    lifecycle.busy,
    profileOperationBusy,
  );
  // Another user session's tunnel never reveals which of our profiles it uses,
  // and a session this App did not start has no known profile.
  const activeProfileKnown = phase !== "running" || runningProfileId !== null;
  const activeUpstream = activeProfileKnown ? homeProfile : undefined;

  const chooseHomeProfile = (profileId: string) => {
    if (profileSelectIsDisabled || !profileIsAvailable(profileAvailability, profileId)) return;
    selection.setDesiredProfileId(profileId);
  };

  /** Opens a new profile prefilled from a discovered listener and tests it. */
  const addCandidate = (candidate: LocalProxyCandidate) => {
    profilesApi.resetEditor();
    profilesApi.updateFields({
      name: candidate.processHint ? `${candidate.processHint} proxy` : "Local proxy",
      upstreamKind: "local_listener",
      port: String(candidate.port),
      protocol: candidate.protocol,
    });
    setActiveView("upstreams");
    void discovery.testCandidate(candidate);
  };

  const editProfile = (profileId: string) => {
    profilesApi.selectProfile(profileId);
    setActiveView("upstreams");
  };

  const notice = activeView !== "overview" ? statusNotice(status) : null;
  const lifecycleError = lifecycle.error;

  return (
    <I18nProvider language={language}>
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        onNavigate={setActiveView}
        appearance={appearance}
        counts={{
          ...(profilesLoaded ? { upstreams: profiles.profiles.length } : {}),
          ...(canObserveTraffic && traffic.snapshot ? { activity: traffic.snapshot.activeConnections } : {}),
        }}
        updatePending={appUpdateApi.pending}
        traffic={traffic.snapshot}
        versionLine={maintenance.systemInfo ? `${maintenance.systemInfo.appVersion} · ${platform.displayName}` : platform.displayName}
        session={session ? { elapsed: Math.max(0, now - session.startedAt), exact: session.exact } : null}
        exitIp={exitIp.info}
      />

      <main className="workspace">
        {(notice || lifecycleError) && (
          <div className="page-alerts">
            {notice && (
              <div className={notice.tone === "error" ? "notice danger" : "notice amber"} role="status">
                <Icon name="alert" size={15} />
                <span><strong>{t(notice.title)}</strong>{t(notice.detail)}</span>
              </div>
            )}
            {lifecycleError && (
              <div className="notice danger" role="status">
                <Icon name="alert" size={15} />
                <span><strong>{t(lifecycleErrorMessage(lifecycleError))}</strong>{lifecycleError.serviceCode ?? lifecycleError.code}</span>
              </div>
            )}
          </div>
        )}

        {activeView === "overview" && (
          <div className="page">
            <PageHeader title={t("Overview")}>
              {status && <span className="page-header-meta">{t("Service verified")}</span>}
              <button type="button" className="help-button" aria-label={t("Help")} title={t("TunBridge routes only through a proxy already running on this PC.")}>?</button>
            </PageHeader>
            <OverviewPage
              appearance={appearance}
              status={status}
              homeProfile={homeProfile}
              activeProfileKnown={activeProfileKnown}
              homeAvailability={homeAvailability}
              lifecycleDisabled={toggleDisabled}
              profileSelectIsDisabled={profileSelectIsDisabled}
              chooseHomeProfile={chooseHomeProfile}
              lifecycle={lifecycle}
              profilesApi={profilesApi}
              traffic={traffic}
              exitIp={exitIp}
              discovery={discovery}
              unsavedCandidates={unsavedCandidates(discovery.candidates, profiles.profiles)}
              onAddCandidate={addCandidate}
              onEditProfile={editProfile}
              navigate={setActiveView}
              events={tunnelEvents.events}
              now={now}
            />
          </div>
        )}

        {activeView === "upstreams" && (
          <UpstreamsPage
            phase={phase}
            activeProfileId={selection.activeProfileId}
            credentialStore={platform.credentialStore}
            profilesApi={profilesApi}
            discovery={discovery}
            onAddCandidate={addCandidate}
          />
        )}

        {activeView === "activity" && (
          <ActivityPage
            tab={activityTab}
            onTabChange={setActivityTab}
            canObserveTraffic={canObserveTraffic}
            canObserveLogs={canObserveLogs}
            traffic={traffic.snapshot}
            upstreamName={activeUpstream?.displayName ?? null}
          />
        )}

        {activeView === "diagnostics" && (
          <DiagnosticsPage
            appearance={appearance}
            routeLabel={activeUpstream
              ? `${activeUpstream.displayName} (${protocolLabel(activeUpstream)} ${profileEndpointLabel(activeUpstream.upstream)})`
              : null}
            exitIp={exitIp}
          />
        )}

        {activeView === "settings" && (
          <SettingsPage
            platform={platform}
            status={status}
            phase={phase}
            language={language}
            setLanguage={setLanguage}
            themeMode={themeMode}
            setThemeMode={setThemeMode}
            appUpdateApi={appUpdateApi}
            maintenance={maintenance}
            lifecycle={lifecycle}
          />
        )}
      </main>
      {lifecycle.confirmDialog && (
        <ConfirmDialog
          kind={lifecycle.confirmDialog}
          onCancel={() => lifecycle.setConfirmDialog(null)}
          onExit={(stopTunnel) => {
            lifecycle.setConfirmDialog(null);
            void invoke("confirm_exit", { input: { stopTunnel } }).catch(() => undefined);
          }}
          onConfirmRecovery={(operation) => {
            lifecycle.setConfirmDialog(null);
            void lifecycle.run(operation, true);
          }}
          onConfirmStop={() => {
            lifecycle.setConfirmDialog(null);
            void lifecycle.run("stop", true);
          }}
          upstreamUnreachable={status?.degradedReason === "upstream_unavailable"}
          faultUnconfirmed={status?.servicePhase === "faulted" && !status.stopReason}
        />
      )}
    </div>
    </I18nProvider>
  );
}
