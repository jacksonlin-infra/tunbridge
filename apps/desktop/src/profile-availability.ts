import type { SavedProfile, ServicePhase } from "./types";

export type ProfileAvailability =
  | { state: "pending" }
  | { state: "testing" }
  | { state: "available"; latencyMs: number | null; checkedAt?: number }
  | { state: "unavailable"; errorCode: string | null; checkedAt?: number };

export type ProfileAvailabilityMap = Record<string, ProfileAvailability>;

export const profileIsAvailable = (
  availability: ProfileAvailabilityMap,
  profileId: string,
): boolean => availability[profileId]?.state === "available";

export const profileSelectionDisabled = (
  phase: ServicePhase,
  lifecycleBusy: boolean,
  profileCount: number,
): boolean => phase === "running" || lifecycleBusy || profileCount === 0;

export const lifecycleToggleDisabled = (
  phase: ServicePhase,
  canStart: boolean,
  canStop: boolean,
  lifecycleBusy: boolean,
  profileOperationBusy: boolean,
): boolean => lifecycleBusy || (
  phase === "running"
    ? !canStop
    : profileOperationBusy || !canStart
);

export const profileMutationLocked = (
  phase: ServicePhase,
  activeProfileId: string | null,
  targetProfileId: string | null,
): boolean => phase === "running"
  && targetProfileId !== null
  && (activeProfileId === null || targetProfileId === activeProfileId);

export const initialDesiredProfileId = (
  profiles: SavedProfile[],
  persistedProfileId: string | null,
): string | null => {
  if (persistedProfileId && profiles.some((profile) => profile.profileId === persistedProfileId)) {
    return persistedProfileId;
  }
  return profiles[0]?.profileId ?? null;
};

export const homeProfileId = (
  phase: ServicePhase,
  desiredProfileId: string | null,
  activeProfileId: string | null,
): string | null => phase === "running"
  ? activeProfileId ?? desiredProfileId
  : desiredProfileId;

export const reconcileAvailability = (
  profiles: SavedProfile[],
  previous: ProfileAvailabilityMap,
): ProfileAvailabilityMap => Object.fromEntries(
  profiles.map((profile) => [
    profile.profileId,
    previous[profile.profileId] ?? { state: "pending" },
  ]),
);

export const automaticProfileTestIds = (
  profiles: SavedProfile[],
  homeProfileId: string | null,
  testAllProfiles: boolean,
): string[] => {
  if (testAllProfiles) {
    return profiles.map((profile) => profile.profileId);
  }
  return homeProfileId && profiles.some((profile) => profile.profileId === homeProfileId)
    ? [homeProfileId]
    : [];
};

/**
 * What a failed test call means for availability. "busy" only says another
 * desktop operation (such as the service installer) held the slot: the
 * upstream was not tested, so it stays pending and is tested again later.
 */
export const availabilityAfterTestError = (code: string, checkedAt: number): ProfileAvailability =>
  code === "busy" ? { state: "pending" } : { state: "unavailable", errorCode: code, checkedAt };

/**
 * Waits before an automatic test confirms a failure. Automatic tests run right
 * after the tunnel stops or the App opens, while the proxy client may still be
 * re-establishing its own connections. One confirmation keeps a real outage
 * visible within seconds.
 */
export const AUTOMATIC_TEST_CONFIRM_DELAYS_MS = [3_000];

/** Failures that may clear by themselves; a wrong password or protocol does not. */
export const testFailureMayBeMomentary = (errorCode: string | null): boolean =>
  errorCode === "connect_failed"
  || errorCode === "upstream_timeout"
  || errorCode === "test_target_unavailable";
