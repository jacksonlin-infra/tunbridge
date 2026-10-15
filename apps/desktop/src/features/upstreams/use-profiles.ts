import { useEffect, useRef, useState } from "react";
import {
  createProfile,
  deleteProfile,
  listProfiles,
  normalizeProfileError,
  testSavedProfile,
  updateProfile,
} from "../../profile-client";
import {
  AUTOMATIC_TEST_CONFIRM_DELAYS_MS,
  automaticProfileTestIds,
  availabilityAfterTestError,
  testFailureMayBeMomentary,
  profileMutationLocked,
  reconcileAvailability,
  type ProfileAvailabilityMap,
} from "../../profile-availability";
import type {
  CertificatePolicy,
  ProfileError,
  ProfileList,
  ProfileUpstream,
  ProxyProtocol,
  ProxyTestResponse,
  SavedProfile,
  ServicePhase,
} from "../../types";
import { profileProtocolOf } from "./profile-format";

export type CredentialMode = "none" | "keep" | "replace" | "remove";

export interface ProfileEditorFields {
  name: string;
  upstreamKind: ProfileUpstream["kind"];
  host: string;
  port: string;
  protocol: ProxyProtocol;
  tls: boolean;
  sni: string;
  certificatePolicy: CertificatePolicy;
  udp: boolean;
  credentialMode: CredentialMode;
  username: string;
  password: string;
}

export const emptyEditorFields = (): ProfileEditorFields => ({
  name: "",
  upstreamKind: "local_listener",
  host: "",
  port: "7078",
  protocol: "socks5",
  tls: false,
  sni: "",
  certificatePolicy: "strict",
  udp: true,
  credentialMode: "none",
  username: "",
  password: "",
});

/** Editor fields for an existing profile; credentials are never loaded. */
export const editorFieldsFrom = (profile: SavedProfile): ProfileEditorFields => {
  const upstream = profile.upstream;
  const base = {
    ...emptyEditorFields(),
    name: profile.displayName,
    upstreamKind: upstream.kind,
    protocol: profileProtocolOf(upstream),
    credentialMode: "keep" as const,
  };
  if (upstream.kind === "local_listener") {
    return { ...base, port: String(upstream.port), udp: upstream.protocol === "socks5" };
  }
  return {
    ...base,
    host: upstream.endpoint.host,
    port: String(upstream.endpoint.port),
    tls: upstream.protocolConfig.tls,
    sni: upstream.protocolConfig.sni ?? "",
    certificatePolicy: upstream.protocolConfig.certificatePolicy,
    udp: upstream.protocolConfig.protocol === "socks5" && upstream.protocolConfig.udp,
  };
};

export const upstreamFromFields = (fields: ProfileEditorFields): ProfileUpstream => {
  const port = Number(fields.port);
  if (fields.upstreamKind === "local_listener") {
    return { kind: "local_listener", port, protocol: fields.protocol };
  }
  const sni = fields.tls && fields.sni.trim() ? fields.sni.trim() : null;
  const certificatePolicy = fields.tls ? fields.certificatePolicy : "strict";
  return {
    kind: "remote_server",
    endpoint: { host: fields.host.trim(), port, ipPreference: "ipv4_prefer" },
    protocolConfig: fields.protocol === "http"
      ? { protocol: "http", tls: fields.tls, sni, certificatePolicy }
      : { protocol: "socks5", tls: fields.tls, sni, udp: fields.udp, certificatePolicy },
  };
};

interface ProfilesOptions {
  phase: ServicePhase;
  activeProfileId: string | null;
  homeProfileId: string | null;
  /** True while the page that lists every profile is open. */
  testAllProfiles: boolean;
  /** Changing this forgets the last automatic results so they are tested again. */
  retestToken: number;
  /** Changing this tests only the upstreams that are not currently available. */
  retestUnavailableToken: number;
}

export function useProfiles({
  phase,
  activeProfileId,
  homeProfileId,
  testAllProfiles,
  retestToken,
  retestUnavailableToken,
}: ProfilesOptions) {
  const [profiles, setProfiles] = useState<ProfileList>({
    schemaVersion: 2,
    storeRevision: 0,
    profiles: [],
  });
  const [profilesLoaded, setProfilesLoaded] = useState(false);
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileError, setProfileError] = useState<ProfileError | null>(null);
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [fields, setFields] = useState<ProfileEditorFields>(emptyEditorFields);
  const [profileTestResult, setProfileTestResult] = useState<ProxyTestResponse | null>(null);
  const [deleteArmedId, setDeleteArmedId] = useState<string | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [availability, setAvailability] = useState<ProfileAvailabilityMap>({});
  const [testsBusy, setTestsBusy] = useState(false);
  const selectionTouched = useRef(false);
  const lastAutoTestRevision = useRef<number | null>(null);
  const previousTestAll = useRef(false);
  const previousRetestToken = useRef(retestToken);
  const previousUnavailableToken = useRef(retestUnavailableToken);
  const unavailableRetestPending = useRef(false);

  const editingProfile = profiles.profiles.find(
    (profile) => profile.profileId === editingProfileId,
  );
  const editingLocked = profileMutationLocked(
    phase,
    activeProfileId,
    editingProfile?.profileId ?? null,
  );

  const updateFields = (patch: Partial<ProfileEditorFields>) =>
    setFields((current) => ({ ...current, ...patch }));

  useEffect(() => {
    let active = true;
    void listProfiles()
      .then((value) => {
        if (active) setProfiles(value);
      })
      .catch((error) => {
        if (active) setProfileError(normalizeProfileError(error));
      })
      .finally(() => {
        if (active) setProfilesLoaded(true);
      });
    return () => {
      active = false;
      updateFields({ username: "", password: "" });
    };
  }, []);

  useEffect(() => {
    if (!profilesLoaded || selectionTouched.current) return;
    selectionTouched.current = true;
    if (profiles.profiles.length === 0) return;
    const profile = profiles.profiles[0];
    setEditingProfileId(profile.profileId);
    setFields(editorFieldsFrom(profile));
  }, [profilesLoaded, profiles]);

  useEffect(() => {
    if (!profilesLoaded) return;
    setAvailability((current) => reconcileAvailability(profiles.profiles, current));
  }, [profilesLoaded, profiles]);

  const resetEditor = () => {
    selectionTouched.current = true;
    setEditorOpen(true);
    setEditingProfileId(null);
    setFields(emptyEditorFields());
    setProfileTestResult(null);
    setDeleteArmedId(null);
  };

  const selectProfile = (profileId: string) => {
    const profile = profiles.profiles.find((entry) => entry.profileId === profileId);
    if (!profile) return;
    selectionTouched.current = true;
    setEditorOpen(true);
    setEditingProfileId(profile.profileId);
    setFields(editorFieldsFrom(profile));
    setProfileError(null);
    setProfileTestResult(null);
    setDeleteArmedId(null);
  };

  const selectProfileFrom = (list: ProfileList, profileId: string) => {
    const profile = list.profiles.find((entry) => entry.profileId === profileId);
    if (!profile) return resetEditor();
    selectionTouched.current = true;
    setEditingProfileId(profile.profileId);
    setFields((current) => ({
      ...editorFieldsFrom(profile),
      username: current.username,
      password: current.password,
    }));
    setDeleteArmedId(null);
  };

  const recordTest = (profileId: string, result: ProxyTestResponse) =>
    setAvailability((current) => ({
      ...current,
      [profileId]: result.ok
        ? { state: "available", latencyMs: result.latencyMs, checkedAt: Date.now() }
        : { state: "unavailable", errorCode: result.errorCode, checkedAt: Date.now() },
    }));

  const saveProfile = async (testAfterSave = false) => {
    if (profileBusy || (editingProfile && editingLocked)) return;
    const upstream = upstreamFromFields(fields);
    setProfileBusy(true);
    setProfileError(null);
    setProfileTestResult(null);
    try {
      let next: ProfileList;
      let savedProfileId: string | null = null;
      if (editingProfile) {
        const credentialAction = fields.credentialMode === "replace"
          ? { action: "replace" as const, username: fields.username, password: fields.password }
          : fields.credentialMode === "remove"
            ? { action: "remove" as const }
            : { action: "keep" as const };
        next = await updateProfile({
          expectedStoreRevision: profiles.storeRevision,
          profileId: editingProfile.profileId,
          displayName: fields.name,
          upstream,
          credentialAction,
        });
        setProfiles(next);
        selectProfileFrom(next, editingProfile.profileId);
        savedProfileId = editingProfile.profileId;
      } else {
        const previous = new Set(profiles.profiles.map((profile) => profile.profileId));
        next = await createProfile({
          expectedStoreRevision: profiles.storeRevision,
          displayName: fields.name,
          upstream,
          credential: fields.credentialMode === "replace"
            ? { username: fields.username, password: fields.password }
            : null,
        });
        setProfiles(next);
        const created = next.profiles.find((profile) => !previous.has(profile.profileId));
        if (created) {
          selectProfileFrom(next, created.profileId);
          savedProfileId = created.profileId;
        }
      }
      if (testAfterSave && savedProfileId) {
        const result = await testSavedProfile({
          expectedStoreRevision: next.storeRevision,
          profileId: savedProfileId,
        });
        setProfileTestResult(result);
        recordTest(savedProfileId, result);
      }
    } catch (error) {
      setProfileError(normalizeProfileError(error));
    } finally {
      updateFields({ username: "", password: "" });
      setProfileBusy(false);
    }
  };

  /** First call arms the delete for that profile; a second call deletes it. */
  const removeProfile = async (profileId = editingProfile?.profileId) => {
    if (!profileId || profileBusy || profileMutationLocked(phase, activeProfileId, profileId)) return;
    if (deleteArmedId !== profileId) {
      setDeleteArmedId(profileId);
      return;
    }
    setProfileBusy(true);
    setProfileError(null);
    try {
      const next = await deleteProfile({
        expectedStoreRevision: profiles.storeRevision,
        profileId,
      });
      setProfiles(next);
      if (profileId === editingProfileId) {
        resetEditor();
        setEditorOpen(false);
      }
      setDeleteArmedId(null);
    } catch (error) {
      setProfileError(normalizeProfileError(error));
    } finally {
      setProfileBusy(false);
    }
  };

  const runSavedTest = async (profileId = editingProfile?.profileId) => {
    if (!profileId || profileBusy || testsBusy) return;
    setProfileBusy(true);
    setProfileError(null);
    setProfileTestResult(null);
    try {
      const result = await testSavedProfile({
        expectedStoreRevision: profiles.storeRevision,
        profileId,
      });
      setProfileTestResult(result);
      recordTest(profileId, result);
    } catch (error) {
      const normalized = normalizeProfileError(error);
      setProfileError(normalized);
      setAvailability((current) => ({
        ...current,
        [profileId]: availabilityAfterTestError(normalized.code, Date.now()),
      }));
    } finally {
      setProfileBusy(false);
    }
  };

  /** Automatic runs confirm a possibly momentary failure before showing it. */
  const runProfileTests = async (profileIds: string[], automatic = false) => {
    if (profileBusy || testsBusy || profileIds.length === 0) return;
    setTestsBusy(true);
    setProfileError(null);
    const revision = profiles.storeRevision;
    let interrupted = false;
    for (const profileId of profileIds) {
      setAvailability((current) => ({
        ...current,
        [profileId]: { state: "testing" },
      }));
      try {
        const test = () => testSavedProfile({ expectedStoreRevision: revision, profileId });
        let result = await test();
        for (const delay of automatic ? AUTOMATIC_TEST_CONFIRM_DELAYS_MS : []) {
          if (result.ok || !testFailureMayBeMomentary(result.errorCode)) break;
          await new Promise((resolve) => window.setTimeout(resolve, delay));
          result = await test();
        }
        recordTest(profileId, result);
      } catch (error) {
        const next = availabilityAfterTestError(normalizeProfileError(error).code, Date.now());
        if (next.state === "pending") interrupted = true;
        setAvailability((current) => ({ ...current, [profileId]: next }));
      }
    }
    // A test that could not run (another operation held the slot) is retried
    // on the next trigger instead of being remembered as done.
    if (!interrupted) lastAutoTestRevision.current = revision;
    setTestsBusy(false);
  };

  const runAllProfileTests = async () => runProfileTests(
    profiles.profiles.map((profile) => profile.profileId),
  );

  useEffect(() => {
    const entered = testAllProfiles && !previousTestAll.current;
    previousTestAll.current = testAllProfiles;
    if (entered) lastAutoTestRevision.current = null;
    if (previousRetestToken.current !== retestToken) {
      previousRetestToken.current = retestToken;
      lastAutoTestRevision.current = null;
    }
    if (
      !profilesLoaded
      || profiles.profiles.length === 0
      || profileBusy
      || testsBusy
      || lastAutoTestRevision.current === profiles.storeRevision
    ) return;
    const profileIds = automaticProfileTestIds(profiles.profiles, homeProfileId, testAllProfiles);
    if (profileIds.length > 0) void runProfileTests(profileIds, true);
  }, [
    retestToken,
    testAllProfiles,
    homeProfileId,
    profileBusy,
    testsBusy,
    profilesLoaded,
    profiles.profiles,
    profiles.storeRevision,
  ]);

  useEffect(() => {
    if (previousUnavailableToken.current !== retestUnavailableToken) {
      previousUnavailableToken.current = retestUnavailableToken;
      unavailableRetestPending.current = true;
    }
    // A request that arrives while another test runs waits for it to finish.
    if (!unavailableRetestPending.current || !profilesLoaded || profileBusy || testsBusy) return;
    unavailableRetestPending.current = false;
    const profileIds = profiles.profiles
      .filter((profile) => {
        const state = availability[profile.profileId]?.state;
        return state !== "available" && state !== "testing";
      })
      .map((profile) => profile.profileId);
    if (profileIds.length > 0) void runProfileTests(profileIds, true);
  }, [retestUnavailableToken, profilesLoaded, profileBusy, testsBusy]);

  return {
    profiles,
    profilesLoaded,
    profileBusy,
    profileError,
    setProfileError,
    editingProfile,
    editingProfileId,
    editingLocked,
    fields,
    updateFields,
    profileTestResult,
    deleteArmedId,
    editorOpen,
    closeEditor: () => {
      setEditorOpen(false);
      setDeleteArmedId(null);
      updateFields({ username: "", password: "" });
    },
    availability,
    testsBusy,
    resetEditor,
    selectProfile,
    saveProfile,
    removeProfile,
    runSavedTest,
    runAllProfileTests,
  };
}

export type ProfilesApi = ReturnType<typeof useProfiles>;
