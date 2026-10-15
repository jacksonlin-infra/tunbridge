import { describe, expect, it } from "vitest";

// The release WebView may only call commands that a permission allows and the
// main capability grants; the browser dev mock does not enforce this, so a
// missing entry fails silently in the App. Keep every invoked command covered.
const sources = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.ts", "!./dev-mock.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});
const permissionsToml = Object.values(import.meta.glob<string>("../src-tauri/permissions/*.toml", {
  query: "?raw",
  import: "default",
  eager: true,
})).join("\n");
const capability = JSON.parse(Object.values(import.meta.glob<string>("../src-tauri/capabilities/main.json", {
  query: "?raw",
  import: "default",
  eager: true,
}))[0]) as { permissions: string[] };

const permissionFor = (command: string): string | undefined => {
  for (const block of permissionsToml.split("[[permission]]")) {
    const identifier = block.match(/identifier\s*=\s*"([^"]+)"/)?.[1];
    const allowed = [...(block.match(/commands\.allow\s*=\s*\[([^\]]*)\]/)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    if (identifier && allowed.includes(command)) return identifier;
  }
  return undefined;
};

describe("WebView command permissions", () => {
  it("grants every command the UI invokes", () => {
    const commands = new Set(Object.values(sources).flatMap((source) =>
      [...source.matchAll(/\binvoke(?:<[^>]*>)?\(\s*"([a-z_]+)"/g)].map((match) => match[1])));
    expect(commands.size).toBeGreaterThan(20);
    const missing = [...commands].filter((command) => {
      const permission = permissionFor(command);
      return !permission || !capability.permissions.includes(permission);
    });
    expect(missing).toEqual([]);
  });
});
