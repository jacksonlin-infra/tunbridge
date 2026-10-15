import { describe, expect, it } from "vitest";
import { coreVersionLabel, locationLabel, maskIpAddress, shortLocation, uptimeLabel } from "./home-model";

describe("home information model", () => {
  it("masks public addresses before display", () => {
    expect(maskIpAddress("203.0.113.42")).toBe("203.0.•••.•••");
    expect(maskIpAddress("2001:db8::1")).toBe("2001:db8:••••");
    expect(maskIpAddress("invalid")).toBe("••••");
  });

  it("formats bounded locations and uptime", () => {
    expect(locationLabel("Turkey", "Istanbul", "Fatih")).toBe(
      "Fatih, Istanbul, Turkey",
    );
    expect(uptimeLabel(3_661_000)).toBe("01:01:01");
  });
});

describe("core version label", () => {
  it("only shows real versions", () => {
    expect(coreVersionLabel("1.19.30")).toBe("v1.19.30");
    expect(coreVersionLabel("v1.19.30")).toBe("v1.19.30");
    expect(coreVersionLabel("Not installed")).toBeNull();
    expect(coreVersionLabel("unknown")).toBeNull();
    expect(coreVersionLabel(undefined)).toBeNull();
  });
});

describe("short location", () => {
  it("prefers city, falls back to region, and drops empty parts", () => {
    expect(shortLocation({ city: "Los Angeles", region: "California", country: "US" })).toBe("Los Angeles, US");
    expect(shortLocation({ city: "", region: "Hong Kong", country: "HK" })).toBe("Hong Kong, HK");
    expect(shortLocation({ city: "", region: "", country: "" })).toBe("");
  });
});
