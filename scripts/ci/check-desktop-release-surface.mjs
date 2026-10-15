import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(process.cwd(), "dist");
const forbidden = [
  "TUNBRIDGE_DEV_MOCK_SENTINEL_V1",
  "VITE_TUNBRIDGE_DEV_MOCK",
  "mock-connection-github",
  "mock-profile-local",
  "0.2.0-dev-mock",
];

const files = [];
const visit = async (path) => {
  for (const entry of await readdir(path)) {
    const child = resolve(path, entry);
    if ((await stat(child)).isDirectory()) {
      await visit(child);
    } else {
      files.push(child);
    }
  }
};

await visit(root);
let releaseHtml = "";
let releaseCss = "";
for (const file of files) {
  const contents = await readFile(file, "utf8");
  if (file.endsWith(".html")) releaseHtml += contents;
  if (file.endsWith(".css")) releaseCss += contents;
  for (const marker of forbidden) {
    if (contents.includes(marker)) {
      throw new Error(`release surface contains dev mock marker ${marker} in ${file}`);
    }
  }
}

if (!/<meta\s+name="color-scheme"\s+content="light dark"\s*\/?>/.test(releaseHtml)) {
  throw new Error("release surface must allow light and dark native controls");
}
if (!/:root\{[^}]*color-scheme:light/.test(releaseCss)) {
  throw new Error("release surface must default native controls to the light theme");
}
if (!/:root\[data-theme=dark\]\{[^}]*color-scheme:dark/.test(releaseCss)) {
  throw new Error("release surface must switch native controls with the dark theme");
}

console.log(`release_surface=ok files=${files.length}`);
