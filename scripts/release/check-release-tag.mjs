import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const cargo = await readFile(resolve(repositoryRoot, "Cargo.toml"), "utf8");
const version = cargo.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version) throw new Error("workspace product version is missing");

const explicitTag = process.argv[2];
const ciTag = process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined;
const tag = explicitTag ?? ciTag;
const expectedTag = `tunbridge-desktop-v${version}`;
if (tag && tag !== expectedTag) {
  throw new Error(`release tag ${tag} does not match unified product version ${expectedTag}`);
}

console.log(`release_tag=ok version=${version}${tag ? ` tag=${tag}` : " tag=not-applicable"}`);
