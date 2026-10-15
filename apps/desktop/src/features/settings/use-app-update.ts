import { useEffect, useState } from "react";
import type { AppUpdateInformation } from "../../types";
import {
  loadAppUpdateInformation,
  normalizeAppUpdateError,
  openAppReleasesPage,
} from "./app-update-client";
import {
  APP_UPDATE_AUTO_CHECK_DELAY_MS,
  autoCheckEnabled,
  ignoredVersion,
  lastCheckAt,
  recordCheck,
  setAutoCheckEnabled,
  setIgnoredVersion,
  shouldAutoCheck,
} from "./app-update-policy";

export function useAppUpdate() {
  const [appUpdate, setAppUpdate] = useState<AppUpdateInformation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autoCheck, setAutoCheck] = useState(() => autoCheckEnabled(localStorage));
  const [lastCheck, setLastCheck] = useState<number | null>(() => lastCheckAt(localStorage));
  const [ignored, setIgnored] = useState<string | null>(() => ignoredVersion(localStorage));

  const check = async (showError: boolean) => {
    if (busy) return;
    setBusy(true);
    if (showError) setError(null);
    try {
      const information = await loadAppUpdateInformation();
      const checkedAt = Date.now();
      setAppUpdate(information);
      recordCheck(localStorage, checkedAt);
      setLastCheck(checkedAt);
    } catch (checkError) {
      if (showError) setError(normalizeAppUpdateError(checkError).safeMessage);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!shouldAutoCheck(localStorage, Date.now())) return;
    const timer = window.setTimeout(
      () => void check(false),
      APP_UPDATE_AUTO_CHECK_DELAY_MS,
    );
    return () => window.clearTimeout(timer);
  }, []);

  const isIgnored = Boolean(appUpdate?.updateAvailable && ignored === appUpdate.latestVersion);

  return {
    appUpdate,
    busy,
    error,
    autoCheck,
    lastCheck,
    isIgnored,
    /** An update the user has not dismissed. */
    pending: Boolean(appUpdate?.updateAvailable && !isIgnored),
    check,
    toggleAutoCheck: () => {
      const enabled = !autoCheck;
      setAutoCheckEnabled(localStorage, enabled);
      setAutoCheck(enabled);
    },
    openReleases: () => {
      setError(null);
      void openAppReleasesPage().catch((openError) => setError(normalizeAppUpdateError(openError).safeMessage));
    },
    ignore: (version: string | null) => {
      setIgnoredVersion(localStorage, version);
      setIgnored(version);
    },
  };
}

export type AppUpdateApi = ReturnType<typeof useAppUpdate>;
