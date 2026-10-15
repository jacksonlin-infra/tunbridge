import type { LocalProxyCandidate, SavedProfile } from "../../types";

/** The saved profile that already uses a discovered local listener, if any. */
export const savedProfileFor = (
  candidate: LocalProxyCandidate,
  profiles: SavedProfile[],
): SavedProfile | undefined =>
  profiles.find((profile) =>
    profile.upstream.kind === "local_listener"
    && profile.upstream.port === candidate.port
    && profile.upstream.protocol === candidate.protocol);

export const unsavedCandidates = (
  candidates: LocalProxyCandidate[],
  profiles: SavedProfile[],
): LocalProxyCandidate[] =>
  candidates.filter((candidate) => !savedProfileFor(candidate, profiles));
