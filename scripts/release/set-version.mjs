import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  throw new Error("usage: node scripts/release/set-version.mjs <semver>");
}

const repositoryRoot = resolve(import.meta.dirname, "../..");
const path = (value) => resolve(repositoryRoot, value);
const updateJson = async (file, mutate) => {
  const value = JSON.parse(await readFile(path(file), "utf8"));
  mutate(value);
  await writeFile(path(file), `${JSON.stringify(value, null, 2)}\n`);
};

const cargoPath = path("Cargo.toml");
const cargo = await readFile(cargoPath, "utf8");
const updatedCargo = cargo.replace(
  /(\[workspace\.package\][\s\S]*?^version\s*=\s*")[^"]+("\s*$)/m,
  (_match, prefix, suffix) => `${prefix}${version}${suffix}`,
);
if (updatedCargo === cargo) throw new Error("workspace product version was not updated");
await writeFile(cargoPath, updatedCargo);

await updateJson("apps/desktop/package.json", (value) => { value.version = version; });
await updateJson("apps/desktop/package-lock.json", (value) => {
  value.version = version;
  value.packages[""].version = version;
});
await updateJson("apps/desktop/src-tauri/tauri.conf.json", (value) => { value.version = version; });
await updateJson("engines.lock.json", (value) => { value.product_version = version; });

console.log(`product_version_updated=${version}`);
