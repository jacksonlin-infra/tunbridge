import { invoke } from "./bridge";
import type {
  ProfileError,
  ProfileErrorCode,
  ProfileList,
  ProfileUpstream,
  ProxyTestResponse,
} from "./types";

const messages: Record<ProfileErrorCode, string> = {
  invalid_input: "The profile input is invalid.",
  busy: "Another desktop operation is already active.",
  active_profile_locked: "The active profile cannot be edited or deleted while System TUN is running.",
  stale_revision: "The profile list changed. Refresh and try again.",
  not_found: "The selected profile was not found.",
  limit_reached: "The profile limit has been reached.",
  storage_untrusted: "The profile storage security check failed.",
  credential_unavailable: "The saved credential is unavailable or invalid.",
  transaction_unknown: "The profile transaction could not be safely reconciled.",
  internal_error: "The profile operation failed safely.",
};

const codes = new Set<ProfileErrorCode>(Object.keys(messages) as ProfileErrorCode[]);

export const normalizeProfileError = (value: unknown): ProfileError => {
  const candidate = value as { code?: unknown } | null;
  const code = candidate && typeof candidate.code === "string" && codes.has(candidate.code as ProfileErrorCode)
    ? (candidate.code as ProfileErrorCode)
    : "internal_error";
  return { code, safeMessage: messages[code] };
};

export const listProfiles = (): Promise<ProfileList> => invoke<ProfileList>("list_profiles");

export const createProfile = (input: {
  expectedStoreRevision: number;
  displayName: string;
  upstream: ProfileUpstream;
  credential: null | { username: string; password: string };
}): Promise<ProfileList> => invoke<ProfileList>("create_profile", { input });

export const updateProfile = (input: {
  expectedStoreRevision: number;
  profileId: string;
  displayName: string;
  upstream: ProfileUpstream;
  credentialAction:
    | { action: "keep" }
    | { action: "remove" }
    | { action: "replace"; username: string; password: string };
}): Promise<ProfileList> => invoke<ProfileList>("update_profile", { input });

export const deleteProfile = (input: {
  expectedStoreRevision: number;
  profileId: string;
}): Promise<ProfileList> => invoke<ProfileList>("delete_profile", { input });

export const testSavedProfile = (input: {
  expectedStoreRevision: number;
  profileId: string;
}): Promise<ProxyTestResponse> => invoke<ProxyTestResponse>("test_saved_profile", { input });
