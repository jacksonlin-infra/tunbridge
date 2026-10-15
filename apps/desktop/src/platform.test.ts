import { describe, expect, it } from "vitest";
import { detectDesktopPlatform } from "./platform";

describe("desktop platform copy", () => {
  it.each([
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows", "Windows Credential Manager"],
    ["Mozilla/5.0 (X11; Linux x86_64)", "linux", "Secret Service"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_6)", "macos", "macOS Keychain"],
  ] as const)("maps %s to platform-specific protected storage", (userAgent, id, credentialStore) => {
    const platform = detectDesktopPlatform(userAgent);
    expect(platform.id).toBe(id);
    expect(platform.credentialStore).toBe(credentialStore);
  });

  it("keeps Windows as the compatibility fallback for unknown WebViews", () => {
    expect(detectDesktopPlatform("unknown").id).toBe("windows");
  });

  it.each([
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", true],
    ["Mozilla/5.0 (X11; Linux x86_64)", true],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_6)", false],
  ] as const)("only exposes online core updates on supported platforms", (userAgent, supported) => {
    expect(detectDesktopPlatform(userAgent).supportsCoreUpdate).toBe(supported);
  });
});
