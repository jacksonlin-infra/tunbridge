import { useEffect, useState } from "react";
import {
  installProduct,
  normalizeInstallerError,
  uninstallProduct,
} from "../../installer-client";
import type { StatusController } from "../../status-controller";
import type {
  CoreUpdateInformation,
  InstallerError,
  ServicePhase,
  SystemInformation,
} from "../../types";
import {
  installCoreUpdate,
  loadCoreUpdateInformation,
  loadSystemInformation,
  normalizeDiagnosticError,
  setAutoLaunch,
} from "../home/home-client";

interface MaintenanceOptions {
  controller: StatusController;
  phase: ServicePhase;
  lifecycleBusy: boolean;
}

/** Service install/verify/uninstall, the Mihomo core update, and auto launch. */
export function useServiceMaintenance({ controller, phase, lifecycleBusy }: MaintenanceOptions) {
  const [systemInfo, setSystemInfo] = useState<SystemInformation | null>(null);
  const [autoLaunchBusy, setAutoLaunchBusy] = useState(false);
  const [installerBusy, setInstallerBusy] = useState(false);
  const [installerError, setInstallerError] = useState<InstallerError | null>(null);
  const [installerNotice, setInstallerNotice] = useState<string | null>(null);
  const [coreUpdate, setCoreUpdate] = useState<CoreUpdateInformation | null>(null);
  const [coreUpdateBusy, setCoreUpdateBusy] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  useEffect(() => {
    void loadSystemInformation().then(setSystemInfo).catch(() => undefined);
  }, []);

  const runInstaller = async (operation: "install" | "uninstall") => {
    if (installerBusy || lifecycleBusy) return;
    setInstallerBusy(true);
    setInstallerError(null);
    setInstallerNotice(null);
    try {
      if (operation === "install") {
        await installProduct();
        setInstallerNotice("Service installation completed.");
      } else {
        await uninstallProduct();
        setInstallerNotice("Service removal completed.");
      }
      controller.invalidate();
      await controller.refresh();
    } catch (error) {
      setInstallerError(normalizeInstallerError(error));
      await controller.refresh();
    } finally {
      setInstallerBusy(false);
    }
  };

  const checkCoreUpdate = () => {
    setCoreUpdateBusy(true);
    setSettingsError(null);
    void loadCoreUpdateInformation()
      .then(setCoreUpdate)
      .catch((error) => setSettingsError(normalizeDiagnosticError(error).safeMessage))
      .finally(() => setCoreUpdateBusy(false));
  };

  const runCoreUpgrade = async () => {
    if (coreUpdateBusy) return;
    setCoreUpdateBusy(true);
    setSettingsError(null);
    setInstallerNotice(null);
    try {
      const result = await installCoreUpdate();
      setCoreUpdate(result);
      setInstallerNotice(
        phase === "running"
          ? "Mihomo core update completed. System TUN was restored automatically."
          : "Mihomo core update completed.",
      );
      controller.invalidate();
      const [systemInformation] = await Promise.allSettled([
        loadSystemInformation(),
        controller.refresh(),
      ]);
      if (systemInformation.status === "fulfilled") {
        setSystemInfo(systemInformation.value);
      }
    } catch (error) {
      setSettingsError(normalizeDiagnosticError(error).safeMessage);
    } finally {
      setCoreUpdateBusy(false);
    }
  };

  const toggleAutoLaunch = () => {
    const enabled = !(systemInfo?.autoLaunch ?? false);
    setAutoLaunchBusy(true);
    setSettingsError(null);
    void setAutoLaunch(enabled)
      .then((value) => setSystemInfo((current) => current ? { ...current, autoLaunch: value } : current))
      .catch((error) => setSettingsError(normalizeDiagnosticError(error).safeMessage))
      .finally(() => setAutoLaunchBusy(false));
  };

  return {
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
    setSettingsError,
  };
}

export type ServiceMaintenanceApi = ReturnType<typeof useServiceMaintenance>;
