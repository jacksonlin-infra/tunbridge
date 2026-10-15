import { describe, expect, it } from "vitest";
import {
  automaticProfileTestIds,
  availabilityAfterTestError,
  homeProfileId,
  initialDesiredProfileId,
  lifecycleToggleDisabled,
  profileIsAvailable,
  profileMutationLocked,
  profileSelectionDisabled,
  reconcileAvailability,
  testFailureMayBeMomentary,
} from "./profile-availability";
import type { SavedProfile } from "./types";

const profiles: SavedProfile[] = [
  {
    profileId: "profile-a",
    displayName: "A",
    upstream: { kind: "local_listener", port: 7890, protocol: "socks5" },
    hasCredential: false,
  },
  {
    profileId: "profile-b",
    displayName: "B",
    upstream: {
      kind: "remote_server",
      endpoint: { host: "192.168.1.30", port: 7897, ipPreference: "ipv4_prefer" },
      protocolConfig: {
        protocol: "socks5",
        tls: false,
        sni: null,
        udp: true,
        certificatePolicy: "strict",
      },
    },
    hasCredential: false,
  },
];

describe("profile availability and selection", () => {
  it("keeps editor selection independent from the desired and active profile", () => {
    expect(homeProfileId("stopped", "profile-a", null)).toBe("profile-a");
    expect(homeProfileId("running", "profile-b", "profile-a")).toBe("profile-a");
    expect(homeProfileId("running", "profile-b", null)).toBe("profile-b");
  });

  it("restores a persisted desired profile only while it still exists", () => {
    expect(initialDesiredProfileId(profiles, "profile-b")).toBe("profile-b");
    expect(initialDesiredProfileId(profiles, "deleted")).toBe("profile-a");
    expect(initialDesiredProfileId([], "profile-a")).toBeNull();
  });

  it("preserves results for existing profiles and starts new profiles pending", () => {
    const result = reconcileAvailability(profiles, {
      "profile-a": { state: "available", latencyMs: 20 },
      deleted: { state: "unavailable", errorCode: "connect_failed" },
    });
    expect(result).toEqual({
      "profile-a": { state: "available", latencyMs: 20 },
      "profile-b": { state: "pending" },
    });
    expect(profileIsAvailable(result, "profile-a")).toBe(true);
    expect(profileIsAvailable(result, "profile-b")).toBe(false);
  });

  it("locks upstream selection while System TUN is active", () => {
    expect(profileSelectionDisabled("running", false, 2)).toBe(true);
    expect(profileSelectionDisabled("stopped", true, 2)).toBe(true);
    expect(profileSelectionDisabled("stopped", false, 0)).toBe(true);
    expect(profileSelectionDisabled("stopped", false, 2)).toBe(false);
  });

  it("locks only the active saved profile while allowing creation and other profiles", () => {
    expect(profileMutationLocked("running", "profile-a", "profile-a")).toBe(true);
    expect(profileMutationLocked("running", "profile-a", "profile-b")).toBe(false);
    expect(profileMutationLocked("running", "profile-a", null)).toBe(false);
    expect(profileMutationLocked("stopped", "profile-a", "profile-a")).toBe(false);
    expect(profileMutationLocked("running", null, "profile-a")).toBe(true);
  });

  it("tests only the home profile during overview startup", () => {
    expect(automaticProfileTestIds(profiles, "profile-a", false)).toEqual(["profile-a"]);
    expect(automaticProfileTestIds(profiles, "deleted", false)).toEqual([]);
  });

  it("tests every profile when the profiles view requests a full refresh", () => {
    expect(automaticProfileTestIds(profiles, "profile-a", true)).toEqual([
      "profile-a",
      "profile-b",
    ]);
  });

  it("blocks start while a profile test owns the desktop operation slot", () => {
    expect(lifecycleToggleDisabled("stopped", true, false, false, true)).toBe(true);
    expect(lifecycleToggleDisabled("stopped", true, false, false, false)).toBe(false);
    expect(lifecycleToggleDisabled("running", false, true, false, true)).toBe(false);
  });
});

describe("availability after a failed test call", () => {
  it("keeps a busy slot as untested and other errors as unavailable", () => {
    expect(availabilityAfterTestError("busy", 5)).toEqual({ state: "pending" });
    expect(availabilityAfterTestError("credential_unavailable", 5))
      .toEqual({ state: "unavailable", errorCode: "credential_unavailable", checkedAt: 5 });
  });
});

describe("automatic test confirmation", () => {
  it("re-checks only failures that can clear by themselves", () => {
    expect(testFailureMayBeMomentary("connect_failed")).toBe(true);
    expect(testFailureMayBeMomentary("upstream_timeout")).toBe(true);
    expect(testFailureMayBeMomentary("test_target_unavailable")).toBe(true);
    expect(testFailureMayBeMomentary("authentication_failed")).toBe(false);
    expect(testFailureMayBeMomentary("protocol_mismatch")).toBe(false);
    expect(testFailureMayBeMomentary(null)).toBe(false);
  });
});
