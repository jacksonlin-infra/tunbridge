import { describe, expect, it } from "vitest";
import { navItems } from "./app/navigation";
import { routeBadge, routeFilters } from "./features/activity/route-model";
import {
  blockedFallbackTitle,
  blockedTitles,
  lastKnownLabels,
  reasonLabel,
  tunnelSummary,
} from "./features/overview/tunnel-copy";
import { eventReasonLabel, eventTitle } from "./features/history/history-copy";
import { lifecycleServiceMessageKeys } from "./lifecycle-client";
import { startBlockedReason } from "./features/overview/overview-model";
import { availabilityCopy, testErrorLabel } from "./features/upstreams/availability-copy";
import { hasTranslation, translate, translateFormat } from "./i18n";
import { detectDesktopPlatform } from "./platform";
import { v2Catalog } from "./i18n-v2";
import type { WatchdogReason } from "./types";

const sources = Object.entries(
  import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.ts", "!./i18n.tsx", "!./i18n-v2.ts"], {
    query: "?raw",
    import: "default",
    eager: true,
  }),
);

/** The first argument of every `t(...)` / `tf(...)` call, as source text. */
const firstArguments = (source: string): string[] => {
  const result: string[] = [];
  for (const match of source.matchAll(/(?<![\w.])tf?\(/g)) {
    let depth = 1;
    let index = match.index + match[0].length;
    const start = index;
    let quote: string | null = null;
    for (; index < source.length && depth > 0; index += 1) {
      const char = source[index];
      if (quote) {
        if (char === "\\") index += 1;
        else if (char === quote) quote = null;
        continue;
      }
      if (char === '"' || char === "'" || char === "`") quote = char;
      else if (char === "(" || char === "{" || char === "[") depth += 1;
      else if (char === ")" || char === "}" || char === "]") depth -= 1;
      else if (char === "," && depth === 1) break;
    }
    result.push(source.slice(start, index));
  }
  return result;
};

const literalKeys = (argument: string): string[] =>
  [...argument
    // Literals compared against a value are conditions, not copy.
    .replace(/[!=]==\s*"(?:[^"\\]|\\.)*"/g, "")
    .replace(/"(?:[^"\\]|\\.)*"\s*[!=]==/g, "")
    .matchAll(/"((?:[^"\\]|\\.)*)"/g)]
    .map((match) => JSON.parse(`"${match[1]}"`) as string);

const reasons: (WatchdogReason | null)[] = [
  "engine_exited", "upstream_unavailable", "controller_unavailable", "adapter_missing",
  "runtime_identity_mismatch", "lease_expired", "connection_storm", null,
];

describe("translations", () => {
  it("covers every literal passed to t() and tf()", () => {
    const found = sources.flatMap(([file, source]) =>
      firstArguments(source).flatMap(literalKeys).map((key) => ({ file, key })));
    // Guards the scanner itself: the UI passes hundreds of literal keys.
    expect(new Set(found.map(({ key }) => key)).size).toBeGreaterThan(300);
    expect(found.some(({ key }) => key === "Stop TUN and restore direct access…")).toBe(true);
    const missing = found
      .filter(({ key }) => !hasTranslation(key))
      .map(({ file, key }) => `${file}: ${key}`);
    expect(missing).toEqual([]);
  });

  it("covers copy chosen at runtime", () => {
    const platforms = ["Windows NT 10.0", "X11; Linux x86_64", "Macintosh; Intel Mac OS X 12_7"].map(detectDesktopPlatform);
    const keys = [
      ...platforms.flatMap((platform) => [platform.credentialStore, platform.serviceName, platform.statusIconLabel]),
      ...navItems.map((item) => item.label),
      ...reasons.map((reason) => eventReasonLabel(reason ?? undefined)).filter((key): key is string => key !== null),
      ...(["app_started", "started", "stopped", "blocked", "resumed", "faulted", "recovered", "start_failed"] as const).flatMap((kind) =>
        (["user", "service", "observed"] as const).flatMap((actor) =>
          [undefined, "upstream_unavailable", "engine_exited"].map((reason) =>
            eventTitle({ atUnixMs: 1, kind, actor, reason: reason as WatchdogReason | undefined }).title))),
      ...[
        { readOnly: true }, { hasProfile: false }, { testing: true },
        { availability: "pending" as const }, { availability: "unavailable" as const },
      ].map((patch) => startBlockedReason({
        lifecycleBusy: false, readOnly: false, hasProfile: true, testing: false, availability: "available", ...patch,
      })).filter((key): key is string => key !== null),
      ...reasons.map(reasonLabel),
      ...lifecycleServiceMessageKeys,
      ...Object.values(lastKnownLabels),
      ...Object.values(blockedTitles),
      blockedFallbackTitle,
      ...Object.values(routeBadge).map((badge) => badge.label),
      ...routeFilters.map((filter) => filter.label),
      ...["connect_failed", "authentication_failed", "protocol_mismatch", "upstream_timeout",
        "test_target_unavailable", "invalid_response", "credential_unavailable", null].map(testErrorLabel),
      ...[undefined, { state: "testing" as const }, { state: "available" as const, latencyMs: 12 },
        { state: "available" as const, latencyMs: null }].map((value) => availabilityCopy(value).label),
      ...[
        { kind: "checking" as const },
        { kind: "transition" as const, phase: "starting" as const },
        { kind: "transition" as const, phase: "stopping" as const },
        { kind: "transition" as const, phase: "recovering" as const },
        { kind: "faulted" as const, reason: null, owned: true },
        { kind: "faulted" as const, reason: "engine_exited" as const, owned: true },
        { kind: "running" as const, owned: true },
        { kind: "running" as const, owned: false },
        { kind: "stopped" as const, firstUse: false, autoStopReason: null },
      ].flatMap((appearance) => Object.values(tunnelSummary(appearance))),
    ];
    expect(keys.filter((key) => !hasTranslation(key))).toEqual([]);
  });

  it("keeps placeholders identical in every language", () => {
    const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
    const mismatched = Object.entries(v2Catalog).flatMap(([key, localized]) =>
      Object.entries(localized)
        .filter(([, text]) => !text.trim() || placeholders(text).join() !== placeholders(key).join())
        .map(([language]) => `${language}: ${key}`));
    expect(mismatched).toEqual([]);
  });

  it("formats placeholders after translating", () => {
    expect(translateFormat("zh-CN", "Upstream · {ms} ms", { ms: 12 })).toBe("上游 · 12 ms");
    expect(translateFormat("en", "Upstream · {ms} ms", { ms: 12 })).toBe("Upstream · 12 ms");
    expect(translate("ja", "Overview")).toBe("概要");
    expect(translate("zh-TW", "Not a catalog key")).toBe("Not a catalog key");
  });
});
