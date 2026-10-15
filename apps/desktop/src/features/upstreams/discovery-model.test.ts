import { describe, expect, it } from "vitest";
import type { SavedProfile } from "../../types";
import { savedProfileFor, unsavedCandidates } from "./discovery-model";

const local: SavedProfile = {
  profileId: "local",
  displayName: "Local proxy",
  hasCredential: false,
  upstream: { kind: "local_listener", port: 7890, protocol: "socks5" },
};

describe("discovery model", () => {
  it("matches a candidate to the saved profile with the same port and protocol", () => {
    expect(savedProfileFor({ port: 7890, protocol: "socks5" }, [local])).toBe(local);
    expect(savedProfileFor({ port: 7890, protocol: "http" }, [local])).toBeUndefined();
  });

  it("keeps only listeners that are not saved yet", () => {
    expect(unsavedCandidates([
      { port: 7890, protocol: "socks5" },
      { port: 7891, protocol: "http", processHint: "proxy-client" },
    ], [local])).toEqual([{ port: 7891, protocol: "http", processHint: "proxy-client" }]);
  });
});
