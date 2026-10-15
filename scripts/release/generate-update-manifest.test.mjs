import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildManifest } from "./generate-update-manifest.mjs";

test("one manifest binds all public platform assets to the workspace version", async () => {
  const cargo = await readFile(new URL("../../Cargo.toml", import.meta.url), "utf8");
  const version = cargo.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1];
  assert.ok(version);
  const root = await mkdtemp(join(tmpdir(), "tunbridge-update-manifest-"));
  const files = {
    windows: join(root, `TunBridge-${version}-windows-x86_64-setup.exe`),
    macosArm64: join(root, `TunBridge-${version}-arm64.dmg`),
    linux: join(root, `TunBridge_${version}_amd64.deb`),
    omarchy: join(root, `tunbridge-desktop-${version}-1-x86_64.pkg.tar.zst`),
  };
  await Promise.all(Object.values(files).map((path) => writeFile(path, path)));
  const manifest = await buildManifest({
    ...files,
    publishedAt: "2026-08-20T10:00:00Z",
  });

  assert.equal(manifest.version, version);
  assert.deepEqual(Object.keys(manifest.targets), [
    "windows-x86_64",
    "darwin-aarch64",
    "linux-x86_64-deb",
    "linux-x86_64-pacman",
  ]);
  for (const entry of Object.values(manifest.targets)) {
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
    assert.ok(entry.url.startsWith(
      `https://github.com/jacksonlin-infra/tunbridge/releases/download/tunbridge-desktop-v${version}/`,
    ));
  }
});
