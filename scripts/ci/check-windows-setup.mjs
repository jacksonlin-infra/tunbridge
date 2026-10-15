import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const source = await readFile(
  resolve(repositoryRoot, "platforms/windows/packaging/TunBridgeSetup.nsi"),
  "utf8",
);
const desktopBuild = await readFile(
  resolve(repositoryRoot, "platforms/windows/packaging/build-desktop-app.ps1"),
  "utf8",
);
const setupManifest = await readFile(
  resolve(repositoryRoot, "crates/tunbridge-setup/Cargo.toml"),
  "utf8",
);

const requiredFiles = [
  "tunbridge-desktop.exe",
  "tunbridge-setup.exe",
  "tunbridge-service.exe",
  "tunbridge.exe",
  "mihomo.exe",
  "engines.lock.json",
  "product-package.json",
];
for (const file of requiredFiles) {
  const escaped = file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = source.match(new RegExp(`File \\"/oname=${escaped}\\"`, "g")) ?? [];
  if (matches.length !== 1) throw new Error(`Windows Setup must embed ${file} exactly once`);
}
for (const command of [
  'tunbridge-setup.exe" install',
  'tunbridge-setup.exe" uninstall',
]) {
  if (!source.includes(command)) throw new Error(`Windows Setup is missing ${command}`);
}
if (!source.includes('RequestExecutionLevel admin')) {
  throw new Error("Windows Setup must use the existing elevated setup transaction");
}
if (!source.includes('$PROGRAMFILES64\\TunBridge Installer')) {
  throw new Error("The outer uninstaller must stay outside the strict product generation");
}
if (!source.includes('QuietUninstallString')) {
  throw new Error("Windows Setup must register a standard silent uninstall entry");
}
if (!desktopBuild.includes('"tunbridge-desktop-$productVersion"')) {
  throw new Error("Windows internal package directory must be tunbridge-desktop-<version>");
}
if (desktopBuild.includes("tunbridge-mvp-")) {
  throw new Error("Windows packaging must not use the retired MVP directory name");
}
if (!desktopBuild.includes("--features tunbridge-service/production-mihomo-logs-v4")) {
  throw new Error("Windows product binaries must use the protocol-v4 service contract");
}
if (!desktopBuild.includes("-C target-feature=+crt-static")) {
  throw new Error("Windows product binaries must statically link the MSVC runtime");
}
if (!desktopBuild.includes("check-crt-dependencies.ps1")) {
  throw new Error("Windows packaging must reject dynamic Visual C++ runtime dependencies");
}
for (const productContract of [
  "service_feature = 'production-mihomo-logs-v4'",
  "service_protocol_version = 4",
  "'remote_upstream'",
  "'observe_mihomo_logs'",
]) {
  if (!desktopBuild.includes(productContract)) {
    throw new Error(`Windows product manifest is missing ${productContract}`);
  }
}
if (!setupManifest.includes('features = ["production-mihomo-logs-v4"]')) {
  throw new Error("Windows setup must probe the protocol-v4 service contract");
}

console.log(`windows_setup_static=ok payloads=${requiredFiles.length}`);
