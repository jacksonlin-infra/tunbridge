import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const read = (path) => readFile(resolve(repositoryRoot, path), "utf8");

const cargo = await read("Cargo.toml");
const cargoVersion = cargo.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1];
if (!cargoVersion) throw new Error("workspace product version is missing");

const packageJson = JSON.parse(await read("apps/desktop/package.json"));
const packageLock = JSON.parse(await read("apps/desktop/package-lock.json"));
const tauri = JSON.parse(await read("apps/desktop/src-tauri/tauri.conf.json"));
const linuxTauri = JSON.parse(await read("apps/desktop/src-tauri/tauri.linux.conf.json"));
const engineLock = JSON.parse(await read("engines.lock.json"));
const linuxEngineManifest = JSON.parse(
  await read("platforms/linux/packaging/deb/engine-manifest.json"),
);
const macosEngineLock = JSON.parse(await read("platforms/macos/engine.lock.json"));
const linuxEngineFetch = await read("scripts/fetch-linux-mihomo.sh");
const linuxDebLayout = JSON.parse(
  await read("platforms/linux/packaging/deb/linux-service-layout.json"),
);
const linuxArchLayout = JSON.parse(
  await read("platforms/linux/packaging/arch/linux-service-layout.json"),
);

const versions = {
  workspace: cargoVersion,
  package: packageJson.version,
  packageLock: packageLock.version,
  packageLockRoot: packageLock.packages?.[""]?.version,
  tauri: tauri.version,
  engineProduct: engineLock.product_version,
};
for (const [source, version] of Object.entries(versions)) {
  if (version !== cargoVersion) {
    throw new Error(`${source} version ${version ?? "<missing>"} does not match ${cargoVersion}`);
  }
}
if (Object.hasOwn(linuxTauri, "version")) {
  throw new Error("Linux Tauri config must inherit the shared product version");
}

const windowsEngineVersion = engineLock.engine?.version;
const linuxFetchEngineVersion = linuxEngineFetch.match(/^version=(v[^\s]+)$/m)?.[1];
const linuxFetchAsset = linuxEngineFetch.match(/^asset=([^\s]+)$/m)?.[1];
const linuxFetchBinarySize = Number(
  linuxEngineFetch.match(/^expected_binary_size=([0-9]+)$/m)?.[1],
);
const linuxFetchBinarySha256 = linuxEngineFetch.match(
  /^expected_binary_sha256=([0-9a-f]{64})$/m,
)?.[1];
const engineVersions = {
  windows: windowsEngineVersion,
  linuxManifest: linuxEngineManifest.version,
  linuxFetch: linuxFetchEngineVersion,
  macos: macosEngineLock.version,
};
for (const [source, version] of Object.entries(engineVersions)) {
  if (version !== windowsEngineVersion) {
    throw new Error(
      `${source} Mihomo version ${version ?? "<missing>"} does not match ${windowsEngineVersion}`,
    );
  }
}
if (
  linuxEngineManifest.assetName !== linuxFetchAsset ||
  linuxEngineManifest.binarySize !== linuxFetchBinarySize ||
  linuxEngineManifest.binarySha256 !== linuxFetchBinarySha256
) {
  throw new Error("Linux Mihomo fetch metadata does not match the package manifest");
}
for (const [source, layout] of Object.entries({
  linuxDebLayout,
  linuxArchLayout,
})) {
  if (
    layout.engine_size !== linuxEngineManifest.binarySize ||
    layout.engine_sha256 !== linuxEngineManifest.binarySha256
  ) {
    throw new Error(`${source} Mihomo metadata does not match the package manifest`);
  }
}

for (const path of [
  "scripts/build-linux-desktop-deb.sh",
  "scripts/verify-linux-desktop-deb.sh",
  "scripts/build-linux-desktop-omarchy.sh",
  "scripts/verify-linux-desktop-omarchy.sh",
  "scripts/build-macos-desktop-candidate.sh",
]) {
  const source = await read(path);
  if (source.includes("0.2.12") || source.includes("<string>0.2.13</string>")) {
    throw new Error(`${path} still contains a platform-specific product version`);
  }
}

console.log(
  `version_sync=ok version=${cargoVersion} mihomo=${windowsEngineVersion}`,
);
