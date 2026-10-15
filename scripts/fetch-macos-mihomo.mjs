#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createGunzip } from "node:zlib";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const modulePath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(modulePath), "..");
const lockPath = resolve(repositoryRoot, "platforms/macos/engine.lock.json");
const supportedTargets = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
const targetKeys = [
  "archiveSha256",
  "archiveSize",
  "asset",
  "binarySha256",
  "binarySize",
  "downloadUrl",
  "minimumSystemVersion",
];

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const observed = Object.keys(value).sort();
  if (JSON.stringify(observed) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${label} has unexpected keys: ${observed.join(",")}`);
  }
}

function validSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

async function loadLock() {
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  exactKeys(
    lock,
    [
      "license",
      "licenseUrl",
      "releaseUrl",
      "schemaVersion",
      "sourceUrl",
      "targets",
      "version",
    ],
    "lock",
  );
  if (
    lock.schemaVersion !== 1 ||
    lock.version !== "v1.19.30" ||
    lock.releaseUrl !==
      "https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30" ||
    lock.sourceUrl !== "https://github.com/MetaCubeX/mihomo/tree/v1.19.30" ||
    lock.license !== "GPL-3.0" ||
    lock.licenseUrl !==
      "https://github.com/MetaCubeX/mihomo/blob/v1.19.30/LICENSE"
  ) {
    throw new Error("macOS engine release identity is not the reviewed v1.19.30 release");
  }
  exactKeys(lock.targets, supportedTargets, "targets");
  for (const target of supportedTargets) {
    const entry = lock.targets[target];
    exactKeys(entry, targetKeys, target);
    if (
      typeof entry.asset !== "string" ||
      !/^mihomo-darwin-[a-z0-9-]+-v1\.19\.30\.gz$/.test(entry.asset) ||
      entry.downloadUrl !==
        `https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/${entry.asset}` ||
      !Number.isSafeInteger(entry.archiveSize) ||
      entry.archiveSize <= 0 ||
      !Number.isSafeInteger(entry.binarySize) ||
      entry.binarySize <= 0 ||
      entry.binarySize > 128 * 1024 * 1024 ||
      !validSha256(entry.archiveSha256) ||
      !validSha256(entry.binarySha256) ||
      !/^\d+\.\d+$/.test(entry.minimumSystemVersion) ||
      Number(entry.minimumSystemVersion) > 12
    ) {
      throw new Error(`invalid locked metadata for ${target}`);
    }
  }
  return lock;
}

async function digest(path) {
  const hash = createHash("sha256");
  const input = createReadStream(path);
  for await (const chunk of input) hash.update(chunk);
  return hash.digest("hex");
}

async function matches(path, size, sha256) {
  try {
    const metadata = await stat(path);
    return metadata.isFile() && metadata.size === size && (await digest(path)) === sha256;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

export function exactByteCount(expectedSize) {
  let observedSize = 0;
  return new Transform({
    transform(chunk, _encoding, callback) {
      observedSize += chunk.length;
      if (observedSize > expectedSize) {
        callback(new Error("download exceeded locked archive size"));
      } else {
        callback(null, chunk);
      }
    },
    flush(callback) {
      if (observedSize !== expectedSize) {
        callback(new Error("download did not match locked archive size"));
      } else {
        callback();
      }
    },
  });
}

async function download(url, output, expectedSize) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok || !response.body) {
    throw new Error(`download failed with HTTP ${response.status}`);
  }
  await pipeline(
    response.body,
    exactByteCount(expectedSize),
    createWriteStream(output, { flags: "wx", mode: 0o600 }),
  );
}

async function fetchTarget(lock, target) {
  if (!supportedTargets.includes(target)) throw new Error(`unsupported target: ${target}`);
  const entry = lock.targets[target];
  const outputDirectory = resolve(repositoryRoot, "target/macos-engine", target);
  const archivePath = resolve(outputDirectory, entry.asset);
  const binaryPath = resolve(outputDirectory, "mihomo");
  const temporaryArchive = `${archivePath}.download-${process.pid}`;
  const temporaryBinary = `${binaryPath}.inflate-${process.pid}`;
  await mkdir(outputDirectory, { recursive: true });

  if (!(await matches(archivePath, entry.archiveSize, entry.archiveSha256))) {
    await rm(archivePath, { force: true });
    await rm(temporaryArchive, { force: true });
    try {
      await download(entry.downloadUrl, temporaryArchive, entry.archiveSize);
      if (!(await matches(temporaryArchive, entry.archiveSize, entry.archiveSha256))) {
        throw new Error(`archive integrity mismatch for ${target}`);
      }
      await rename(temporaryArchive, archivePath);
    } finally {
      await rm(temporaryArchive, { force: true });
    }
  }

  if (!(await matches(binaryPath, entry.binarySize, entry.binarySha256))) {
    await rm(binaryPath, { force: true });
    await rm(temporaryBinary, { force: true });
    try {
      await pipeline(
        createReadStream(archivePath),
        createGunzip(),
        createWriteStream(temporaryBinary, { flags: "wx", mode: 0o700 }),
      );
      if (!(await matches(temporaryBinary, entry.binarySize, entry.binarySha256))) {
        throw new Error(`binary integrity mismatch for ${target}`);
      }
      await chmod(temporaryBinary, 0o755);
      await rename(temporaryBinary, binaryPath);
    } finally {
      await rm(temporaryBinary, { force: true });
    }
  }
  console.log(binaryPath);
}

async function writeRuntimeManifest(lock, target, binaryPath, outputPath) {
  if (!supportedTargets.includes(target)) throw new Error(`unsupported target: ${target}`);
  const metadata = await stat(binaryPath);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > 128 * 1024 * 1024) {
    throw new Error("signed engine payload is not a bounded regular file");
  }
  const manifest = {
    schemaVersion: 1,
    version: lock.version,
    targetTriple: target,
    binarySize: metadata.size,
    binarySha256: await digest(binaryPath),
  };
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o644,
  });
}

async function main() {
  const [command = "validate-lock", ...args] = process.argv.slice(2);
  const lock = await loadLock();
  if (command === "validate-lock") {
    console.log(`macos_engine_lock=ok version=${lock.version} targets=${supportedTargets.length}`);
  } else if (command === "fetch") {
    await fetchTarget(lock, args[0]);
  } else if (command === "manifest" && args.length === 3) {
    await writeRuntimeManifest(lock, args[0], resolve(args[1]), resolve(args[2]));
  } else {
    throw new Error(
      "usage: fetch-macos-mihomo.mjs validate-lock | fetch <target> | manifest <target> <binary> <output>",
    );
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
