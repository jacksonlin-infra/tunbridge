import { describe, expect, it } from "vitest";
import type { ConnectionView } from "../../types";
import {
  connectionRuleLabel,
  filterAndSortConnections,
} from "./connections-model";

const connection = (
  id: string,
  host: string,
  downloadBps: number,
  overrides: Partial<ConnectionView> = {},
): ConnectionView => ({
  id,
  host,
  network: "tcp",
  connectionType: "TUN",
  source: "198.18.0.1:5000",
  destination: "1.1.1.1:443",
  chains: ["Proxy", "Hong Kong"],
  rule: "DomainSuffix",
  rulePayload: "example.com",
  uploadTotal: 10,
  downloadTotal: 20,
  uploadBps: 5,
  downloadBps,
  startedAt: "2026-07-25T12:00:00Z",
  ...overrides,
});

describe("connection view model", () => {
  it("filters across host, process, rule, endpoint, and chain", () => {
    const rows = [
      connection("a", "api.example.com", 3, { processName: "browser.exe" }),
      connection("b", "updates.test", 8, { chains: ["DIRECT"] }),
    ];
    expect(filterAndSortConnections(rows, "browser", "speed").map((row) => row.id))
      .toEqual(["a"]);
    expect(filterAndSortConnections(rows, "direct", "speed").map((row) => row.id))
      .toEqual(["b"]);
  });

  it("sorts by live throughput descending without mutating input", () => {
    const rows = [connection("a", "a.test", 3), connection("b", "b.test", 9)];
    expect(filterAndSortConnections(rows, "", "speed").map((row) => row.id))
      .toEqual(["b", "a"]);
    expect(rows.map((row) => row.id)).toEqual(["a", "b"]);
  });

  it("formats rule and chain fallbacks", () => {
    const row = connection("a", "a.test", 0);
    expect(connectionRuleLabel(row)).toBe("DomainSuffix(example.com)");
  });
});
