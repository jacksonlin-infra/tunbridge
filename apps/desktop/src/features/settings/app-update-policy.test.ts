import { describe, expect, it } from "vitest";
import {
  APP_UPDATE_AUTO_CHECK_INTERVAL_MS,
  autoCheckEnabled,
  ignoredVersion,
  recordCheck,
  setAutoCheckEnabled,
  setIgnoredVersion,
  shouldAutoCheck,
} from "./app-update-policy";

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
}

describe("app update policy", () => {
  it("checks by default and then waits twenty-four hours", () => {
    const storage = memoryStorage();
    expect(autoCheckEnabled(storage)).toBe(true);
    expect(shouldAutoCheck(storage, 1_000)).toBe(true);
    recordCheck(storage, 1_000);
    expect(shouldAutoCheck(storage, 1_000 + APP_UPDATE_AUTO_CHECK_INTERVAL_MS - 1)).toBe(false);
    expect(shouldAutoCheck(storage, 1_000 + APP_UPDATE_AUTO_CHECK_INTERVAL_MS)).toBe(true);
  });

  it("persists the opt-out and ignored version independently", () => {
    const storage = memoryStorage();
    setAutoCheckEnabled(storage, false);
    setIgnoredVersion(storage, "0.3.0");
    expect(autoCheckEnabled(storage)).toBe(false);
    expect(ignoredVersion(storage)).toBe("0.3.0");
    setIgnoredVersion(storage, null);
    expect(ignoredVersion(storage)).toBeNull();
  });
});
