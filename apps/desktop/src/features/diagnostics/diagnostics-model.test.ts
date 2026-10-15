import { describe, expect, it } from "vitest";
import type { WebsiteTarget, WebsiteTestResult } from "../../types";
import { outcomeCounts, websiteOutcome } from "./diagnostics-model";

const result = (reachable: boolean, httpStatus: number, target: WebsiteTarget = "github"): WebsiteTestResult => ({
  schemaVersion: 1, target, reachable, latencyMs: 10, httpStatus,
});

describe("website outcomes", () => {
  it("separates refused responses from missing ones", () => {
    expect(websiteOutcome(result(true, 204))).toBe("ok");
    expect(websiteOutcome(result(false, 403))).toBe("restricted");
    expect(websiteOutcome(result(false, 502))).toBe("restricted");
    expect(websiteOutcome(result(false, 0))).toBe("failed");
  });

  it("counts each outcome", () => {
    expect(outcomeCounts([result(true, 200), result(false, 403), result(false, 0), result(true, 204)]))
      .toEqual({ ok: 2, restricted: 1, failed: 1 });
  });
});
