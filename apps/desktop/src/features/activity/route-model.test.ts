import { describe, expect, it } from "vitest";
import type { ConnectionView } from "../../types";
import {
  connectionRoute,
  destinationAddress,
  destinationPort,
  durationLabel,
  matchesRouteFilter,
  routeCounts,
} from "./route-model";

const connection = (chains: string[]): ConnectionView => ({
  id: chains.join("-") || "none",
  host: "example.com",
  network: "tcp",
  connectionType: "TUN",
  source: "198.18.0.1:50000",
  destination: "203.0.113.4:443",
  chains,
  rule: "Match",
  uploadTotal: 0,
  downloadTotal: 0,
  uploadBps: 0,
  downloadBps: 0,
  startedAt: "2026-10-11T10:00:00Z",
});

describe("connection routes", () => {
  it("classifies the chain names every platform renders", () => {
    expect(connectionRoute(["upstream"])).toBe("upstream");
    expect(connectionRoute(["DIRECT"])).toBe("direct");
    expect(connectionRoute(["direct-default"])).toBe("direct");
    expect(connectionRoute(["TunBridge", "DIRECT"])).toBe("direct");
    expect(connectionRoute(["REJECT"])).toBe("rejected");
    expect(connectionRoute([])).toBe("unknown");
    expect(connectionRoute(["something-else"])).toBe("unknown");
  });

  it("filters and counts by route", () => {
    const items = [connection(["upstream"]), connection(["DIRECT"]), connection(["REJECT"])];
    expect(items.filter((item) => matchesRouteFilter(item, "upstream"))).toHaveLength(1);
    expect(items.filter((item) => matchesRouteFilter(item, "all"))).toHaveLength(3);
    expect(routeCounts(items)).toEqual({ all: 3, upstream: 1, direct: 1 });
  });

  it("splits destinations and formats durations", () => {
    expect(destinationPort("203.0.113.4:443")).toBe("443");
    expect(destinationAddress("203.0.113.4:443")).toBe("203.0.113.4");
    expect(destinationAddress("[2001:db8::1]:443")).toBe("2001:db8::1");
    expect(destinationPort("example")).toBeNull();
    expect(durationLabel(9_000)).toBe("0:09");
    expect(durationLabel(252_000)).toBe("4:12");
    expect(durationLabel(3_725_000)).toBe("1:02:05");
  });
});
