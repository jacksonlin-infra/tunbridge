import type { ReactNode } from "react";
import { PageHeader } from "../../app/PageHeader";
import type { ThemeMode } from "../../app/use-preferences";
import type { LifecycleApi } from "../../app/use-lifecycle";
import { useI18n, type Language } from "../../i18n";
import type { DesktopPlatform } from "../../platform";
import type { DesktopStatus, ServicePhase } from "../../types";
import { Icon } from "../../ui/Icon";
import { Select } from "../../ui/Select";
import { coreVersionLabel } from "../home/home-model";
import type { AppUpdateApi } from "./use-app-update";
import type { ServiceMaintenanceApi } from "./use-service-maintenance";
import "./settings.css";

interface SettingsPageProps {
  platform: DesktopPlatform;
  status: DesktopStatus | undefined;
  phase: ServicePhase;
  language: Language;
  setLanguage: (language: Language) => void;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  appUpdateApi: AppUpdateApi;
  maintenance: ServiceMaintenanceApi;
  lifecycle: LifecycleApi;
}

function Row({ title, detail, children }: { title: ReactNode; detail?: ReactNode; children?: ReactNode }) {
  return (
    <div className="settings-row">
      <div className="settings-row-copy">
        <strong>{title}</strong>
        {detail && <span>{detail}</span>}
      </div>
      {children && <div className="settings-row-control">{children}</div>}
    </div>
  );
}

export function SettingsPage({
  platform,
  status,
  phase,
  language,
  setLanguage,
  themeMode,
  setThemeMode,
  appUpdateApi,
  maintenance,
  lifecycle,
}: SettingsPageProps) {
  const { t, tf } = useI18n();
  const {
    systemInfo,
    autoLaunchBusy,
    toggleAutoLaunch,
    installerBusy,
    installerError,
    installerNotice,
    runInstaller,
    coreUpdate,
    coreUpdateBusy,
    checkCoreUpdate,
    runCoreUpgrade,
    settingsError,
  } = maintenance;
  const { appUpdate, busy: appUpdateBusy, error: appUpdateError, autoCheck, lastCheck, isIgnored } = appUpdateApi;
  const appVersion = systemInfo?.appVersion ?? appUpdate?.currentVersion ?? null;
  const coreVersion = coreVersionLabel(systemInfo?.coreVersion);
  const dateTime = (value: number) => new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(value);
  const serviceLine = [
    status?.serviceVersion,
    systemInfo?.architecture,
    status && appVersion ? t(status.serviceVersion === appVersion ? "same version as the app" : "differs from the app version") : null,
  ].filter(Boolean).join(" · ");

  return (
    <div className="page">
      <PageHeader title={t("Settings")} description={t("Interface preferences, startup and quit behavior, and system service maintenance.")} />
      {(settingsError || installerError || installerNotice) && (
        <div className="settings-messages">
          {installerError && <div className="notice danger" role="status"><Icon name="alert" size={15} /><span><strong>{t(installerError.safeMessage)}</strong>{installerError.retryable ? t("Check administrator approval and try again.") : installerError.code}</span></div>}
          {settingsError && <div className="notice danger" role="status"><Icon name="alert" size={15} /><span>{t(settingsError)}</span></div>}
          {installerNotice && <div className="notice accent" role="status"><Icon name="check" size={15} /><span>{t(installerNotice)}</span></div>}
        </div>
      )}
      <div className="settings-grid">
        <div className="settings-column">
          <section className="panel">
            <div className="panel-head"><h3>{t("Startup and quit")}</h3></div>
            <Row title={t("Launch at sign-in")} detail={tf("Starts in the background; open the window from the {icon}.", { icon: t(platform.statusIconLabel === "Menu Bar Icon" ? "menu bar icon" : "tray icon") })}>
              <button type="button" role="switch" className="switch" aria-label={t("Launch at sign-in")} aria-checked={systemInfo?.autoLaunch ?? false} disabled={autoLaunchBusy || !systemInfo} onClick={toggleAutoLaunch}><span /></button>
            </Row>
            <Row title={t("Closing the window")} detail={t("TunBridge keeps running in the background. Quitting while TUN is on always asks first.")} />
          </section>

          <section className="panel">
            <div className="panel-head"><h3>{t("Appearance")}</h3></div>
            <div className="settings-row appearance-row">
              <div className="appearance-field">
                <strong id="settings-theme-label">{t("Theme")}</strong>
                <Select<ThemeMode> ariaLabelledBy="settings-theme-label" value={themeMode} onChange={setThemeMode} options={[
                  { value: "system", label: t("Follow system") },
                  { value: "light", label: t("Light") },
                  { value: "dark", label: t("Dark") },
                ]} />
              </div>
              <div className="appearance-field">
                <strong id="settings-language-label">{t("Language")}</strong>
                <Select<Language> ariaLabelledBy="settings-language-label" value={language} onChange={setLanguage} options={[
                  { value: "zh-CN", label: "简体中文" },
                  { value: "en", label: "English" },
                  { value: "zh-TW", label: "繁體中文" },
                  { value: "ja", label: "日本語" },
                ]} />
              </div>
            </div>
          </section>
        </div>

        <div className="settings-column">
          <section className="panel">
            <div className="panel-head">
              <h3>{t("System service")}</h3>
              <span className={status ? "badge accent" : "badge danger"}>{t(status ? "Verified" : "Unavailable")}</span>
            </div>
            <Row title={t(platform.serviceName)} detail={status ? <span className="mono">{serviceLine}</span> : t("The service is not installed or not responding.")}>
              <button type="button" className="btn" disabled={installerBusy || lifecycle.busy || phase === "running"} onClick={() => void runInstaller("install")}>
                {t(installerBusy ? "Working…" : status ? "Verify / repair" : "Install service")}
              </button>
            </Row>
            {platform.id === "windows" ? (
              <Row title={t("Uninstall system service")} detail={t("Remove TunBridge from Windows Installed apps so the service and application are removed together.")} />
            ) : platform.id === "macos" ? (
              // The macOS helper has no removal transaction yet; the App must not offer one.
              <Row title={t("Uninstall system service")} detail={t("Not available in the macOS app yet.")} />
            ) : (
              <Row title={t("Uninstall system service")} detail={t("Stop TUN first.")}>
                <button type="button" className="btn btn-danger" disabled={installerBusy || lifecycle.busy || !status || phase !== "stopped"} onClick={() => void runInstaller("uninstall")}>{t("Uninstall…")}</button>
              </Row>
            )}
            {phase === "faulted" && (
              <Row title={t("Recover network")} detail={t("Removes the tunnel that is holding traffic. Traffic then goes directly until you turn TUN on again.")}>
                <button type="button" className="btn btn-danger" disabled={lifecycle.busy} onClick={() => void lifecycle.run("recover")}>{t("Recover network…")}</button>
              </Row>
            )}
            {phase === "running" && <p className="settings-footnote">{t("Stop TUN before verifying or repairing the service.")}</p>}
          </section>

          <section className="panel">
            <div className="panel-head"><h3>{t("Updates")}</h3></div>
            <Row
              title={appVersion ? `TunBridge ${appVersion}` : "TunBridge"}
              detail={appUpdate
                ? `${t(appUpdate.updateAvailable ? (isIgnored ? "Version ignored" : "App update available") : "App is up to date")}${appUpdate.updateAvailable ? ` · ${appUpdate.latestVersion}` : ""}${lastCheck ? ` · ${tf("checked {time}", { time: dateTime(lastCheck) })}` : ""}`
                : lastCheck ? tf("Last checked {time}", { time: dateTime(lastCheck) }) : t("Not checked yet")}
            >
              <button type="button" className="btn" disabled={appUpdateBusy} onClick={() => void appUpdateApi.check(true)}>{t(appUpdateBusy ? "Checking…" : "Check for updates")}</button>
            </Row>
            {appUpdate?.updateAvailable && !isIgnored && (
              <div className="settings-row update-actions">
                <span className="muted">{appUpdate.packageKind.toUpperCase()} · {appUpdate.minimumOs}</span>
                <span>
                  <button type="button" className="btn btn-link" onClick={() => appUpdateApi.ignore(appUpdate.latestVersion)}>{t("Ignore this version")}</button>
                  <button type="button" className="btn btn-primary" onClick={appUpdateApi.openReleases}>{t("View download")}</button>
                </span>
              </div>
            )}
            {isIgnored && (
              <div className="settings-row update-actions">
                <span />
                <button type="button" className="btn btn-link" onClick={() => appUpdateApi.ignore(null)}>{t("Show this version again")}</button>
              </div>
            )}
            {appUpdateError && <p className="settings-footnote danger">{t(appUpdateError)}</p>}
            <Row title={t("Check for updates automatically")}>
              <button type="button" role="switch" className="switch" aria-label={t("Check for updates automatically")} aria-checked={autoCheck} onClick={appUpdateApi.toggleAutoCheck}><span /></button>
            </Row>
            {platform.supportsCoreUpdate ? (
              <>
                <Row
                  title={coreVersion ? `${t("Mihomo core")} ${coreVersion}` : t("Mihomo core")}
                  detail={coreUpdate
                    ? coreUpdate.updateAvailable ? `${t("Update available")} · ${coreUpdate.currentVersion} → ${coreUpdate.latestVersion}` : t("Core is up to date")
                    : t("Check the official Mihomo release channel, then use the verified installer to upgrade.")}
                >
                  {coreUpdate?.updateAvailable
                    ? <button type="button" className="btn btn-primary" disabled={coreUpdateBusy} onClick={() => void runCoreUpgrade()}>{t(coreUpdateBusy ? "Upgrading…" : "Upgrade core")}</button>
                    : <button type="button" className="btn" disabled={coreUpdateBusy} onClick={checkCoreUpdate}>{t(coreUpdateBusy ? "Checking…" : "Check online")}</button>}
                </Row>
                {coreUpdate?.updateAvailable && phase === "running" && <p className="settings-footnote">{t("System TUN will be stopped safely before the core is upgraded.")}</p>}
              </>
            ) : (
              <Row title={coreVersion ? `${t("Mihomo core")} ${coreVersion}` : t("Mihomo core")} detail={t("Updated together with the app on macOS.")}>
                <span className="badge">{t("Bundled with app")}</span>
              </Row>
            )}
          </section>

          <section className="panel">
            <div className="panel-head"><h3>{t("Your data stays on this device")}</h3></div>
            <p className="panel-body settings-privacy">
              {tf("Profiles are stored for the current user and credentials go to {store}. TunBridge never provides proxy nodes, imports subscriptions, or decrypts traffic.", { store: t(platform.credentialStore) })}
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}
