import { describe, expect, it } from "vitest";
import type { TrafficSnapshot } from "../../types";
import { appendTrafficPoint, formatBytes, formatRate, splitRate } from "./traffic-model";

const snapshot = (
  generation: string,
  sequence: number,
  uploadBps: number,
): TrafficSnapshot => ({
  schemaVersion: 1,
  engineGeneration: generation,
  sequence,
  sampledAtUnixMs: sequence * 1_000,
  intervalMs: 1_000,
  uploadBps,
  downloadBps: uploadBps * 2,
  uploadTotal: uploadBps,
  downloadTotal: uploadBps * 2,
  activeConnections: 1,
  memoryBytes: 64,
  stale: false,
});

describe("traffic model", () => {
  it("keeps a bounded history and resets for a new engine generation", () => {
    let points = appendTrafficPoint([], snapshot("a", 1, 1), 2);
    points = appendTrafficPoint(points, snapshot("a", 2, 2), 2);
    points = appendTrafficPoint(points, snapshot("a", 3, 3), 2);
    expect(points.map((point) => point.sequence)).toEqual([2, 3]);
    points = appendTrafficPoint(points, snapshot("b", 1, 4), 2);
    expect(points).toHaveLength(1);
    expect(points[0].engineGeneration).toBe("b");
  });

  it("rejects duplicate or out-of-order samples by rebuilding the baseline", () => {
    const points = appendTrafficPoint(
      [appendTrafficPoint([], snapshot("a", 2, 2))[0]],
      snapshot("a", 2, 9),
    );
    expect(points).toHaveLength(1);
    expect(points[0].uploadBps).toBe(9);
  });

  it("formats byte and rate units consistently", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.50 KB");
    expect(formatBytes(10 * 1024 * 1024)).toBe("10.0 MB");
    expect(formatRate(1024)).toBe("1.00 KB/s");
  });
});

describe("split rate", () => {
  it("separates the number from the unit", () => {
    expect(splitRate(0)).toEqual({ value: "0", unit: "B/s" });
    expect(splitRate(2_600_000)).toEqual({ value: "2.48", unit: "MB/s" });
  });
});
