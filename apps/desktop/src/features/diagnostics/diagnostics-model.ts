import type { WebsiteTestResult } from "../../types";

/**
 * A site that answers with an HTTP error still proves the route works: the
 * request went through the tunnel and the site refused it (often a 403 for
 * data-centre exit addresses). Only a missing response is a real failure.
 */
export type WebsiteOutcome = "ok" | "restricted" | "failed";

export const websiteOutcome = (result: WebsiteTestResult): WebsiteOutcome =>
  result.reachable ? "ok" : result.httpStatus >= 400 ? "restricted" : "failed";

export const outcomeCounts = (results: WebsiteTestResult[]): Record<WebsiteOutcome, number> => {
  const counts = { ok: 0, restricted: 0, failed: 0 };
  for (const result of results) counts[websiteOutcome(result)] += 1;
  return counts;
};
