import { describe, expect, it } from "vitest";
import type { MihomoLogPage } from "../../types";
import { emptyLogBuffer, filterLogs, mergeLogPage } from "./logs-model";

const page = (generation: string, sequences: number[], oldestSequence = 1): MihomoLogPage => ({
  schemaVersion: 1,
  engineGeneration: generation,
  oldestSequence,
  nextSequence: Math.max(oldestSequence, ...sequences, 0) + 1,
  items: sequences.map((sequence) => ({
    sequence,
    observedAtUnixMs: sequence * 1_000,
    level: sequence % 2 ? "info" : "error",
    message: `message-${sequence}`,
    truncated: false,
  })),
});

describe("Mihomo log model", () => {
  it("merges cursor pages without duplicates", () => {
    const first = mergeLogPage(emptyLogBuffer(), page("a", [1, 2]));
    const second = mergeLogPage(first, page("a", [2, 3]));
    expect(second.cursor).toBe(3);
    expect(second.items.map((item) => item.sequence)).toEqual([1, 2, 3]);
  });

  it("resets on generation changes and reports service-side eviction", () => {
    const first = mergeLogPage(emptyLogBuffer(), page("a", [1, 2]));
    const dropped = mergeLogPage(first, page("a", [8], 8));
    expect(dropped.dropped).toBe(true);
    expect(dropped.items.map((item) => item.sequence)).toEqual([8]);
    expect(mergeLogPage(dropped, page("a", [9], 8)).dropped).toBe(true);
    const restarted = mergeLogPage(dropped, page("b", [1]));
    expect(restarted.dropped).toBe(false);
    expect(restarted.items.map((item) => item.sequence)).toEqual([1]);
  });

  it("reports entries evicted before the first visible page", () => {
    const first = mergeLogPage(emptyLogBuffer(), page("a", [50], 50));
    expect(first.dropped).toBe(true);
  });

  it("filters by level and query and reverses without mutating", () => {
    const source = page("a", [1, 2, 3]).items;
    expect(filterLogs(source, "info", "MESSAGE", "desc").map((item) => item.sequence))
      .toEqual([3, 1]);
    expect(source.map((item) => item.sequence)).toEqual([1, 2, 3]);
  });
});
