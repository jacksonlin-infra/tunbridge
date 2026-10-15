import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(process.cwd(), "../..");
const read = (path) => readFile(resolve(repositoryRoot, path), "utf8");

const tauri = JSON.parse(await read("apps/desktop/src-tauri/tauri.conf.json"));
if (tauri.bundle?.macOS?.minimumSystemVersion !== "12.0") {
  throw new Error("Tauri bundle minimumSystemVersion must be exactly 12.0");
}

const cargoConfig = await read(".cargo/config.toml");
if (
  !/MACOSX_DEPLOYMENT_TARGET\s*=\s*\{\s*value\s*=\s*"12\.0",\s*force\s*=\s*true\s*\}/.test(
    cargoConfig,
  )
) {
  throw new Error("Cargo must force MACOSX_DEPLOYMENT_TARGET=12.0");
}

const workflow = await read(".github/workflows/cross-platform-desktop.yml");
if (!/MACOSX_DEPLOYMENT_TARGET:\s*"12\.0"/.test(workflow)) {
  throw new Error("cross-platform CI must set MACOSX_DEPLOYMENT_TARGET=12.0");
}

const desktopManifest = await read("apps/desktop/src-tauri/Cargo.toml");
for (const dependency of [
  "tunbridge-platform-macos",
  "tunbridge-service-macos",
  "tunbridge-setup-macos",
]) {
  if (!desktopManifest.includes(`${dependency} =`)) {
    throw new Error(`Desktop is missing explicit ${dependency} wiring`);
  }
}

const mainCapability = JSON.parse(
  await read("apps/desktop/src-tauri/capabilities/main.json"),
);
if (!mainCapability.permissions?.includes("core:event:allow-listen")) {
  throw new Error("Desktop tray navigation requires event listen permission");
}
if (
  mainCapability.permissions.includes("core:event:allow-emit") ||
  mainCapability.permissions.includes("core:event:default")
) {
  throw new Error("WebView must not receive broader event permissions");
}

const rustToolchain = await read("rust-toolchain.toml");
if (!/channel\s*=\s*"1\.96\.1"/.test(rustToolchain)) {
  throw new Error("Rust toolchain must remain pinned to 1.96.1");
}

const engineLock = JSON.parse(await read("platforms/macos/engine.lock.json"));
const expectedEngineTargets = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
const reviewedEngineTargets = {
  "aarch64-apple-darwin": {
    asset: "mihomo-darwin-arm64-v1.19.30.gz",
    downloadUrl:
      "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-darwin-arm64-v1.19.30.gz",
    archiveSize: 16805556,
    archiveSha256: "2c7f3a7904fa1cee291e124123e630e7b1ebd13765dd9bf26c0a28432004d9f4",
    binarySize: 45643538,
    binarySha256: "e80c6334b4e3aae53dfbc86cddd4434cec1565a61d4483931fac2ae12fec6d30",
    minimumSystemVersion: "11.0",
  },
  "x86_64-apple-darwin": {
    asset: "mihomo-darwin-amd64-compatible-v1.19.30.gz",
    downloadUrl:
      "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-darwin-amd64-compatible-v1.19.30.gz",
    archiveSize: 18300486,
    archiveSha256: "6e75de0732e8afabe413ff7c235e8f16226ce136672371c60787cbf9607402c5",
    binarySize: 49677184,
    binarySha256: "30895e01ba17cc4293f9fa192c0601e91fcb812acb72a03a0286b8ffef72dadc",
    minimumSystemVersion: "10.13",
  },
};
if (
  engineLock.schemaVersion !== 1 ||
  engineLock.version !== "v1.19.30" ||
  engineLock.releaseUrl !==
    "https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30" ||
  engineLock.sourceUrl !==
    "https://github.com/MetaCubeX/mihomo/tree/v1.19.30" ||
  engineLock.license !== "GPL-3.0" ||
  engineLock.licenseUrl !==
    "https://github.com/MetaCubeX/mihomo/blob/v1.19.30/LICENSE" ||
  JSON.stringify(Object.keys(engineLock.targets ?? {}).sort()) !==
    JSON.stringify(expectedEngineTargets)
) {
  throw new Error("macOS engine lock must pin the reviewed dual-architecture release");
}
for (const target of expectedEngineTargets) {
  const entry = engineLock.targets[target];
  if (
    !entry ||
    !Number.isSafeInteger(entry.archiveSize) ||
    !Number.isSafeInteger(entry.binarySize) ||
    !/^[0-9a-f]{64}$/.test(entry.archiveSha256 ?? "") ||
    !/^[0-9a-f]{64}$/.test(entry.binarySha256 ?? "") ||
    !entry.downloadUrl?.startsWith(
      "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/",
    ) ||
    entry.downloadUrl.includes("/latest/") ||
    Number(entry.minimumSystemVersion) > 12
  ) {
    throw new Error(`invalid macOS engine lock entry for ${target}`);
  }
  for (const [key, expectedValue] of Object.entries(reviewedEngineTargets[target])) {
    if (entry[key] !== expectedValue) {
      throw new Error(`macOS engine lock ${target}.${key} changed without review`);
    }
  }
}

console.log(
  "macos_compat=ok deployment_target=12.0 validation_floor=12.7.6 command_scaffold=explicit",
);
