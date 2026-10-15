import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const releasePrefix =
  "https://github.com/jacksonlin-infra/tunbridge/releases/download";

async function productVersion() {
  const cargo = await readFile(resolve(repositoryRoot, "Cargo.toml"), "utf8");
  const version = cargo.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1];
  if (!version) throw new Error("workspace product version is missing");
  return version;
}

async function sha256(path) {
  const hash = createHash("sha256");
  await new Promise((resolvePromise, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", resolvePromise);
    stream.on("error", reject);
  });
  return hash.digest("hex");
}

async function target(version, path, packageKind, minimumOs) {
  const assetName = basename(path);
  if (!/^[A-Za-z0-9._-]+$/.test(assetName) || !assetName.includes(version)) {
    throw new Error(`release asset name must contain version ${version}: ${assetName}`);
  }
  return {
    packageKind,
    minimumOs,
    url: `${releasePrefix}/tunbridge-desktop-v${version}/${assetName}`,
    sha256: await sha256(path),
  };
}

export async function buildManifest(options) {
  const version = await productVersion();
  for (const required of ["windows", "macosArm64", "linux", "omarchy"]) {
    if (!options[required]) throw new Error(`missing required ${required} release asset`);
  }
  const targets = {
    "windows-x86_64": await target(version, options.windows, "nsis", "Windows 11"),
    "darwin-aarch64": await target(version, options.macosArm64, "dmg", "macOS 12.0"),
    "linux-x86_64-deb": await target(
      version,
      options.linux,
      "deb",
      "Ubuntu 24.04 / 26.04",
    ),
    "linux-x86_64-pacman": await target(
      version,
      options.omarchy,
      "pacman",
      "Omarchy 4 / Arch Linux x86_64",
    ),
  };
  if (options.macosX86_64) {
    targets["darwin-x86_64"] = await target(
      version,
      options.macosX86_64,
      "dmg",
      "macOS 12.0",
    );
  }
  return {
    schemaVersion: 1,
    version,
    channel: "stable",
    publishedAt: options.publishedAt ?? new Date().toISOString(),
    targets,
  };
}

function parseArguments(argumentsList) {
  const options = {};
  for (let index = 0; index < argumentsList.length; index += 2) {
    const key = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!key?.startsWith("--") || !value) throw new Error(`invalid argument ${key ?? ""}`);
    const field = {
      "--output": "output",
      "--windows": "windows",
      "--macos-arm64": "macosArm64",
      "--macos-x86_64": "macosX86_64",
      "--linux": "linux",
      "--omarchy": "omarchy",
      "--published-at": "publishedAt",
    }[key];
    if (!field || options[field]) throw new Error(`unknown or duplicate argument ${key}`);
    options[field] = resolve(value);
    if (field === "publishedAt") options[field] = value;
  }
  if (!options.output) throw new Error("missing required --output path");
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = parseArguments(process.argv.slice(2));
  const manifest = await buildManifest(options);
  await writeFile(options.output, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`update_manifest=ok version=${manifest.version} output=${options.output}`);
}
