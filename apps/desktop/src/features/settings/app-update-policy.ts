export const APP_UPDATE_AUTO_CHECK_KEY = "tunbridge.app-update.auto-check";
export const APP_UPDATE_LAST_CHECK_KEY = "tunbridge.app-update.last-check";
export const APP_UPDATE_IGNORED_VERSION_KEY = "tunbridge.app-update.ignored-version";
export const APP_UPDATE_AUTO_CHECK_DELAY_MS = 30_000;
export const APP_UPDATE_AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1_000;

export function autoCheckEnabled(storage: Storage): boolean {
  return storage.getItem(APP_UPDATE_AUTO_CHECK_KEY) !== "false";
}

export function setAutoCheckEnabled(storage: Storage, enabled: boolean): void {
  storage.setItem(APP_UPDATE_AUTO_CHECK_KEY, String(enabled));
}

export function lastCheckAt(storage: Storage): number | null {
  const value = Number(storage.getItem(APP_UPDATE_LAST_CHECK_KEY));
  return Number.isFinite(value) && value > 0 ? value : null;
}

export function recordCheck(storage: Storage, checkedAt: number): void {
  storage.setItem(APP_UPDATE_LAST_CHECK_KEY, String(checkedAt));
}

export function shouldAutoCheck(storage: Storage, now: number): boolean {
  if (!autoCheckEnabled(storage)) return false;
  const previous = lastCheckAt(storage);
  return previous === null || now - previous >= APP_UPDATE_AUTO_CHECK_INTERVAL_MS;
}

export function ignoredVersion(storage: Storage): string | null {
  const value = storage.getItem(APP_UPDATE_IGNORED_VERSION_KEY);
  return value && value.length <= 64 ? value : null;
}

export function setIgnoredVersion(storage: Storage, version: string | null): void {
  if (version === null) storage.removeItem(APP_UPDATE_IGNORED_VERSION_KEY);
  else storage.setItem(APP_UPDATE_IGNORED_VERSION_KEY, version);
}
