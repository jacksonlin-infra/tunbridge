export type DesktopPlatformId = "windows" | "linux" | "macos";

export interface DesktopPlatform {
  id: DesktopPlatformId;
  displayName: string;
  serviceName: "TunBridge Service" | "TunBridge Helper";
  credentialStore: "Windows Credential Manager" | "Secret Service" | "macOS Keychain";
  statusIconLabel: "Tray Icon" | "Menu Bar Icon";
  supportsCoreUpdate: boolean;
}

const platforms: Record<DesktopPlatformId, DesktopPlatform> = {
  windows: {
    id: "windows",
    displayName: "Windows",
    serviceName: "TunBridge Service",
    credentialStore: "Windows Credential Manager",
    statusIconLabel: "Tray Icon",
    supportsCoreUpdate: true,
  },
  linux: {
    id: "linux",
    displayName: "Linux",
    serviceName: "TunBridge Service",
    credentialStore: "Secret Service",
    statusIconLabel: "Tray Icon",
    supportsCoreUpdate: true,
  },
  macos: {
    id: "macos",
    displayName: "macOS",
    serviceName: "TunBridge Helper",
    credentialStore: "macOS Keychain",
    statusIconLabel: "Menu Bar Icon",
    supportsCoreUpdate: false,
  },
};

export function detectDesktopPlatform(
  userAgent = globalThis.navigator?.userAgent ?? "",
): DesktopPlatform {
  const normalized = userAgent.toLowerCase();
  if (normalized.includes("macintosh") || normalized.includes("mac os")) {
    return platforms.macos;
  }
  if (normalized.includes("linux")) {
    return platforms.linux;
  }
  return platforms.windows;
}
