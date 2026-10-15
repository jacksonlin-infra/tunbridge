import { describe, expect, it } from "vitest";
import { navItems, trayDestination } from "./navigation";

describe("navigation", () => {
  it("has the five v2 pages", () => {
    expect(navItems.map((item) => item.id)).toEqual([
      "overview",
      "upstreams",
      "activity",
      "diagnostics",
      "settings",
    ]);
  });

  it("maps every pre-v2 tray destination to a v2 page", () => {
    expect(trayDestination("overview")).toEqual({ view: "overview" });
    expect(trayDestination("home")).toEqual({ view: "overview" });
    expect(trayDestination("proxies")).toEqual({ view: "upstreams" });
    expect(trayDestination("profiles")).toEqual({ view: "upstreams" });
    expect(trayDestination("connections")).toEqual({ view: "activity", activityTab: "connections" });
    expect(trayDestination("logs")).toEqual({ view: "activity", activityTab: "logs" });
    expect(trayDestination("test")).toEqual({ view: "diagnostics" });
    expect(trayDestination("settings")).toEqual({ view: "settings" });
  });

  it("ignores unknown or inherited destinations", () => {
    expect(trayDestination(null)).toBeNull();
    expect(trayDestination("exceptions")).toBeNull();
    expect(trayDestination("constructor")).toBeNull();
    expect(trayDestination("toString")).toBeNull();
  });
});
