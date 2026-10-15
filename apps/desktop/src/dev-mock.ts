import type { InvokeArgs } from "@tauri-apps/api/core";
import type {
  AppUpdateInformation,
  CloseConnectionsResult,
  ConnectionPage,
  ConnectionState,
  ConnectionView,
  CoreUpdateInformation,
  DesktopStatus,
  DiscoveryResponse,
  IpInformation,
  MihomoLogEntry,
  MihomoLogPage,
  ProfileList,
  ProfileUpstream,
  ProxyProtocol,
  ProxyTestResponse,
  SavedProfile,
  SystemInformation,
  TrafficSnapshot,
  TunnelEvent,
  WebsiteTarget,
  WebsiteTestResult,
} from "./types";
import { detectDesktopPlatform } from "./platform";

export const DEV_MOCK_SENTINEL = "TUNBRIDGE_DEV_MOCK_SENTINEL_V1";

const MOCK_SCENARIOS = [
  "ready",
  "service-error",
  "faulted",
  "empty",
  "degraded",
  "auto-stopped",
  "stopped",
  "starting",
  "foreign",
  "stale",
  "engine-restarting",
  "start-failed",
  "outside-app",
] as const;

type MockScenario = (typeof MOCK_SCENARIOS)[number];

interface MockState {
  installed: boolean;
  statusReads: number;
  running: boolean;
  activeProfileId: string | null;
  autoLaunch: boolean;
  coreUpdated: boolean;
  sequence: number;
  storeRevision: number;
  profiles: SavedProfile[];
  connections: ConnectionView[];
  logs: MihomoLogEntry[];
  events: TunnelEvent[];
}

const minutesAgo = (minutes: number): string =>
  new Date(Date.now() - minutes * 60_000 - 12_000).toISOString();

const initialConnections = (): ConnectionView[] => [
  {
    id: "mock-connection-github",
    host: "github.com",
    network: "tcp",
    connectionType: "TUN",
    source: "198.18.0.1:52144",
    destination: "140.82.112.4:443",
    processName: "browser",
    chains: ["upstream"],
    rule: "DomainSuffix",
    rulePayload: "github.com",
    uploadTotal: 48_200,
    downloadTotal: 512_800,
    uploadBps: 8_400,
    downloadBps: 96_400,
    startedAt: minutesAgo(4),
  },
  {
    id: "mock-connection-api",
    host: "api.example.com",
    network: "tcp",
    connectionType: "TUN",
    source: "198.18.0.1:52145",
    destination: "203.0.113.80:443",
    processName: "developer-tool",
    chains: ["upstream"],
    rule: "Match",
    uploadTotal: 12_800,
    downloadTotal: 84_200,
    uploadBps: 2_100,
    downloadBps: 14_600,
    startedAt: minutesAgo(12),
  },
  {
    id: "mock-connection-lan",
    host: "192.168.1.20:445",
    network: "tcp",
    connectionType: "TUN",
    source: "198.18.0.1:52146",
    destination: "192.168.1.20:445",
    processName: "file-browser",
    chains: ["DIRECT"],
    rule: "IPCIDR",
    rulePayload: "192.168.0.0/16",
    uploadTotal: 8_200,
    downloadTotal: 42_000,
    uploadBps: 0,
    downloadBps: 0,
    startedAt: minutesAgo(22),
  },
];

const PROFILE_LOCAL = "mock-profile-local";

/** A plausible local history for each scenario, oldest first. */
const initialEvents = (): TunnelEvent[] => {
  const ago = (minutes: number) => Date.now() - minutes * 60_000;
  const yesterday: TunnelEvent[] = [
    { atUnixMs: ago(1_500), kind: "app_started", actor: "observed", phase: "stopped" },
    { atUnixMs: ago(1_490), kind: "started", actor: "user", profileId: PROFILE_LOCAL },
    { atUnixMs: ago(1_400), kind: "stopped", actor: "user", downloadTotal: 120_000_000, uploadTotal: 9_000_000 },
  ];
  const session: TunnelEvent[] = [
    { atUnixMs: ago(200), kind: "app_started", actor: "observed", phase: "stopped" },
    { atUnixMs: ago(134), kind: "started", actor: "user", profileId: PROFILE_LOCAL },
    { atUnixMs: ago(76), kind: "blocked", actor: "service", reason: "upstream_unavailable" },
    { atUnixMs: ago(72), kind: "resumed", actor: "service", reason: "upstream_unavailable" },
  ];
  switch (scenario()) {
    case "degraded":
      return [...yesterday, ...session, { atUnixMs: Date.now() - 222_000, kind: "blocked", actor: "service", reason: "upstream_unavailable" }];
    case "stopped":
    case "auto-stopped":
      return [...yesterday, ...session, { atUnixMs: ago(12), kind: "stopped", actor: "user", downloadTotal: 509_607_936, uploadTotal: 26_004_684 }];
    case "outside-app":
      return [...yesterday, { atUnixMs: ago(40), kind: "app_started", actor: "observed", phase: "stopped" }, { atUnixMs: ago(30), kind: "started", actor: "observed" }];
    case "start-failed":
      return [...yesterday, { atUnixMs: ago(3), kind: "start_failed", actor: "user", profileId: PROFILE_LOCAL }];
    case "empty":
    case "service-error":
      return [];
    default:
      return [...yesterday, ...session];
  }
};

const initialState = (): MockState => ({
  installed: true,
  statusReads: 0,
  running: !["stopped", "empty", "auto-stopped", "start-failed"].includes(scenario()),
  activeProfileId: scenario() === "outside-app" ? null : "mock-profile-local",
  autoLaunch: false,
  coreUpdated: false,
  sequence: 1,
  storeRevision: 1,
  profiles: [
    {
      profileId: "mock-profile-local",
      displayName: "Local development proxy",
      upstream: { kind: "local_listener", port: 7890, protocol: "socks5" },
      hasCredential: false,
    },
    {
      profileId: "mock-profile-remote",
      displayName: "Office remote proxy",
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
    {
      profileId: "mock-profile-offline",
      displayName: "Offline proxy",
      upstream: { kind: "local_listener", port: 1080, protocol: "socks5" },
      hasCredential: false,
    },
  ],
  connections: initialConnections(),
  logs: [],
  events: initialEvents(),
});

let scenarioOverride: MockScenario | null = null;

const scenario = (): MockScenario => {
  if (scenarioOverride) return scenarioOverride;
  const value = new URLSearchParams(globalThis.location?.search ?? "").get("tunbridgeMock");
  return (MOCK_SCENARIOS as readonly string[]).includes(value ?? "") ? value as MockScenario : "ready";
};

// Created on first use so the release bundle can drop this module entirely.
let state!: MockState;
let stateReady = false;

const value = <T>(result: T): Promise<T> =>
  new Promise((resolve) => globalThis.setTimeout(() => resolve(result), 20));

const reject = (error: unknown): Promise<never> =>
  new Promise((_, rejectPromise) =>
    globalThis.setTimeout(() => rejectPromise(error), 20),
  );

const argumentsRecord = (args?: InvokeArgs): Record<string, unknown> => {
  if (
    !args
    || Array.isArray(args)
    || args instanceof ArrayBuffer
    || ArrayBuffer.isView(args)
  ) {
    return {};
  }
  return args;
};

const input = (args?: InvokeArgs): Record<string, unknown> =>
  (argumentsRecord(args).input as Record<string, unknown> | undefined) ?? {};

const profileList = (): ProfileList => ({
  schemaVersion: 2,
  storeRevision: state.storeRevision,
  profiles: scenario() === "empty" ? [] : state.profiles.map((profile) => ({ ...profile })),
});

const status = (): DesktopStatus => ({
  schemaVersion: 3,
  servicePhase: scenario() === "faulted" || scenario() === "start-failed"
    ? "faulted"
    : scenario() === "starting" ? "starting" : state.running ? "running" : "stopped",
  engineRunning: state.running && scenario() !== "faulted" && scenario() !== "engine-restarting",
  callerIsOwner: state.running && scenario() !== "foreign",
  serviceVersion: "0.2.0-dev-mock",
  readOnly: false,
  capabilities: [
    "status", "start", "stop", "recover", "lease", "observe_local_traffic",
    "close_owned_connections", "remote_upstream", "observe_mihomo_logs",
  ],
  stopReason: scenario() === "faulted"
    ? "runtime_identity_mismatch"
    : scenario() === "auto-stopped" && !state.running ? "lease_expired" : null,
  degradedReason: !state.running
    ? null
    : scenario() === "degraded"
      ? "upstream_unavailable"
      : scenario() === "engine-restarting" ? "engine_exited" : null,
});

const testResponse = (protocol: ProxyProtocol): ProxyTestResponse => ({
  schemaVersion: 1,
  ok: true,
  httpCode: 204,
  latencyMs: 38,
  udpSupported: protocol === "socks5",
  errorCode: null,
});

const trafficSnapshot = (): TrafficSnapshot => {
  state.sequence += 1;
  return {
    schemaVersion: 1,
    engineGeneration: "mock-engine-generation",
    sequence: state.sequence,
    sampledAtUnixMs: Date.now(),
    intervalMs: 1_000,
    uploadBps: 24_000 + state.sequence * 250,
    downloadBps: 180_000 + state.sequence * 1_000,
    uploadTotal: 1_280_000 + state.sequence * 24_000,
    downloadTotal: 18_400_000 + state.sequence * 180_000,
    activeConnections: state.connections.length,
    memoryBytes: 42_000_000,
    stale: false,
  };
};

const connectionPage = (args?: InvokeArgs): ConnectionPage => {
  const request = input(args);
  const requestedState = request.state === "closed" ? "closed" : "active";
  const offset = typeof request.offset === "number" ? request.offset : 0;
  const limit = typeof request.limit === "number" ? request.limit : 25;
  const items = requestedState === "active" ? state.connections : [];
  return {
    schemaVersion: 1,
    engineGeneration: "mock-engine-generation",
    sequence: state.sequence,
    state: requestedState as ConnectionState,
    offset,
    limit,
    total: items.length,
    items: items.slice(offset, offset + limit).map((item) => ({ ...item })),
  };
};

const mihomoLogPage = (args?: InvokeArgs): MihomoLogPage => {
  const request = input(args);
  const afterSequence = typeof request.afterSequence === "number" ? request.afterSequence : 0;
  const next = (state.logs.at(-1)?.sequence ?? 0) + 1;
  const samples: Array<Pick<MihomoLogEntry, "level" | "message">> = [
    { level: "info", message: "[TCP] 198.18.0.1:52144 --> github.com:443 match DomainSuffix using Trusted local proxy" },
    { level: "debug", message: "health check completed for trusted local upstream" },
    { level: "warning", message: "connection retry scheduled after a bounded timeout" },
    { level: "error", message: "sample development-only dial failure" },
  ];
  const sample = samples[(next - 1) % samples.length];
  state.logs.push({
    sequence: next,
    observedAtUnixMs: Date.now(),
    level: sample.level,
    message: sample.message,
    truncated: false,
  });
  state.logs = state.logs.slice(-1_000);
  const oldestSequence = state.logs[0]?.sequence ?? next;
  return {
    schemaVersion: 1,
    engineGeneration: "mock-engine-generation",
    oldestSequence,
    nextSequence: (state.logs.at(-1)?.sequence ?? 0) + 1,
    items: state.logs.filter((entry) => entry.sequence > afterSequence).slice(0, 25),
  };
};

const updateProfile = (args?: InvokeArgs): ProfileList => {
  const request = input(args);
  const profileId = String(request.profileId ?? "");
  const existing = state.profiles.find((profile) => profile.profileId === profileId);
  if (!existing) throw { code: "not_found" };
  existing.displayName = String(request.displayName ?? existing.displayName);
  if (request.upstream) existing.upstream = request.upstream as ProfileUpstream;
  const credentialAction = request.credentialAction as { action?: string } | undefined;
  if (credentialAction?.action === "remove") existing.hasCredential = false;
  if (credentialAction?.action === "replace") existing.hasCredential = true;
  state.storeRevision += 1;
  return profileList();
};

export async function mockInvoke<T>(command: string, args?: InvokeArgs): Promise<T> {
  void DEV_MOCK_SENTINEL;
  if (!stateReady) {
    state = initialState();
    stateReady = true;
  }
  switch (command) {
    case "take_pending_tray_navigation":
      return value(null as T);
    case "get_tunnel_events":
      return value({ schemaVersion: 1, events: state.events.slice(-100) } as T);
    case "get_status":
      state.statusReads += 1;
      if (!state.installed || scenario() === "service-error" || (scenario() === "stale" && state.statusReads > 1)) {
        return reject({
          code: "service_unavailable",
          safeMessage: "The TunBridge service is unavailable.",
          retryable: true,
        });
      }
      return value(status() as T);
    case "discover_upstreams":
      return value({
        schemaVersion: 1,
        candidates: [
          { port: 7890, protocol: "socks5", processHint: "Local proxy" },
          { port: 8080, protocol: "http", processHint: "Development proxy" },
        ],
        warningCodes: [],
      } satisfies DiscoveryResponse as T);
    case "test_upstream":
      return value(testResponse(input(args).protocol === "http" ? "http" : "socks5") as T);
    case "list_profiles":
      return value(profileList() as T);
    case "create_profile": {
      const request = input(args);
      state.storeRevision += 1;
      state.profiles.push({
        profileId: `mock-profile-${state.storeRevision}`,
        displayName: String(request.displayName ?? "Mock profile"),
        upstream: (request.upstream as ProfileUpstream | undefined)
          ?? { kind: "local_listener", port: 7890, protocol: "socks5" },
        hasCredential: request.credential !== null,
      });
      return value(profileList() as T);
    }
    case "update_profile":
      return value(updateProfile(args) as T);
    case "delete_profile": {
      const request = input(args);
      state.profiles = state.profiles.filter(
        (profile) => profile.profileId !== String(request.profileId ?? ""),
      );
      state.storeRevision += 1;
      return value(profileList() as T);
    }
    case "test_saved_profile": {
      if (
        String(input(args).profileId ?? "").includes("offline")
        || (scenario() === "degraded" && state.running && input(args).profileId === state.activeProfileId)
      ) {
        return value({
          schemaVersion: 1,
          ok: false,
          httpCode: null,
          latencyMs: null,
          udpSupported: false,
          errorCode: "connect_failed",
        } satisfies ProxyTestResponse as T);
      }
      const profile = state.profiles.find(
        (candidate) => candidate.profileId === String(input(args).profileId ?? ""),
      );
      const protocol = profile?.upstream.kind === "local_listener"
        ? profile.upstream.protocol
        : profile?.upstream.protocolConfig.protocol;
      return value(testResponse(protocol ?? "socks5") as T);
    }
    case "start_saved_profile":
      state.events.push({ atUnixMs: Date.now(), kind: "started", actor: "user", profileId: PROFILE_LOCAL });
      state.running = true;
      state.activeProfileId = String(input(args).profileId ?? state.profiles[0]?.profileId ?? "") || null;
      return value(undefined as T);
    case "get_active_profile_id":
      return value((state.running ? state.activeProfileId : null) as T);
    case "stop_tunnel":
      state.events.push({ atUnixMs: Date.now(), kind: "stopped", actor: "user", downloadTotal: 18_400_000, uploadTotal: 1_280_000 });
      state.running = false;
      state.activeProfileId = null;
      return value(undefined as T);
    case "recover_tunnel":
      state.running = false;
      state.activeProfileId = null;
      return value(undefined as T);
    case "confirm_exit":
      // The browser mock has no process to quit; only a stop changes state.
      if (input(args).stopTunnel === true) {
        state.running = false;
        state.activeProfileId = null;
      }
      return value(undefined as T);
    case "get_traffic_snapshot":
      return state.running
        ? value(trafficSnapshot() as T)
        : reject({ code: "not_running", retryable: false });
    case "get_connections_page":
      return value(connectionPage(args) as T);
    case "get_mihomo_logs_page":
      return state.running
        ? value(mihomoLogPage(args) as T)
        : reject({ code: "not_running", retryable: false });
    case "close_connection": {
      const connectionId = String(input(args).connectionId ?? "");
      const previous = state.connections.length;
      state.connections = state.connections.filter(
        (connection) => connection.id !== connectionId,
      );
      return value({
        schemaVersion: 1,
        closed: previous - state.connections.length,
      } satisfies CloseConnectionsResult as T);
    }
    case "close_all_connections": {
      const closed = state.connections.length;
      state.connections = [];
      return value({ schemaVersion: 1, closed } satisfies CloseConnectionsResult as T);
    }
    case "test_website": {
      const target = String(input(args).target ?? "github") as WebsiteTarget;
      // Sites that refuse data-centre exits answer 403 through a working tunnel.
      const refused = target === "claude" || target === "chatgpt";
      return value({
        schemaVersion: 1,
        target,
        reachable: !refused,
        latencyMs: refused ? 380 : 42,
        httpStatus: refused ? 403 : 204,
      } satisfies WebsiteTestResult as T);
    }
    case "get_ip_information":
      return value({
        schemaVersion: 1,
        ip: "203.0.113.24",
        country: "Singapore",
        countryCode: "SG",
        region: "Singapore",
        city: "Singapore",
        timezone: "Asia/Singapore",
        asn: 64496,
        organization: "Documentation network",
        provider: "ipinfo.io",
      } satisfies IpInformation as T);
    case "get_system_information": {
      const platform = detectDesktopPlatform();
      return value({
        schemaVersion: 1,
        osName: platform.displayName,
        displayVersion: platform.id === "macos" ? "Monterey 12.7.6 compatibility" : "Development",
        buildNumber: "dev-mock",
        architecture: platform.id === "macos" ? "arm64" : "x86_64",
        autoLaunch: state.autoLaunch,
        appVersion: "0.2.13",
        coreVersion: state.coreUpdated ? "1.20.0" : "1.19.0",
      } satisfies SystemInformation as T);
    }
    case "set_auto_launch":
      state.autoLaunch = argumentsRecord(args).enabled === true;
      return value(state.autoLaunch as T);
    case "get_app_update_information":
      return value({
        schemaVersion: 1,
        currentVersion: "0.2.13",
        latestVersion: "0.3.0",
        updateAvailable: true,
        publishedAt: "2026-08-20T10:00:00Z",
        target: `${detectDesktopPlatform().id}-development`,
        packageKind: detectDesktopPlatform().id === "windows"
          ? "nsis"
          : detectDesktopPlatform().id === "macos" ? "dmg" : "deb",
        minimumOs: detectDesktopPlatform().id === "windows"
          ? "Windows 11"
          : detectDesktopPlatform().id === "macos" ? "macOS 12.0" : "Ubuntu 24.04 / 26.04",
        assetName: "TunBridge-0.3.0-development",
      } satisfies AppUpdateInformation as T);
    case "open_app_releases_page":
      return value(undefined as T);
    case "get_core_update_information":
      return value({
        schemaVersion: 1,
        currentVersion: state.coreUpdated ? "1.20.0" : "1.19.0",
        latestVersion: "1.20.0",
        updateAvailable: !state.coreUpdated,
      } satisfies CoreUpdateInformation as T);
    case "install_core_update":
      state.coreUpdated = true;
      return value({
        schemaVersion: 1,
        currentVersion: "1.20.0",
        latestVersion: "1.20.0",
        updateAvailable: false,
      } satisfies CoreUpdateInformation as T);
    case "install_product":
      state.installed = true;
      return value(undefined as T);
    case "uninstall_product":
      state.installed = false;
      state.running = false;
      state.activeProfileId = null;
      return value(undefined as T);
    default:
      return reject(new Error(`Unsupported dev mock command: ${command}`));
  }
}

export function resetDevMockForTest(nextScenario: MockScenario = "ready"): void {
  scenarioOverride = nextScenario;
  state = initialState();
  stateReady = true;
}

type MockHandler = (event: { event: string; id: number; payload: unknown }) => void;
let mockListeners: Map<string, Set<MockHandler>> | undefined;

/**
 * Registers a native-event listener in the browser mock. The first call also
 * exposes `__tunbridgeMockEmit(event, payload)` so tray and quit events can be
 * exercised from the console; it is never reached in a release build.
 */
export function mockListen(event: string, handler: MockHandler): () => void {
  const target = globalThis as typeof globalThis & {
    __tunbridgeMockEmit?: (name: string, payload?: unknown) => void;
  };
  const registry = mockListeners ??= new Map();
  target.__tunbridgeMockEmit ??= (name, payload = null) => {
    for (const listener of registry.get(name) ?? []) listener({ event: name, id: 0, payload });
  };
  const listeners = registry.get(event) ?? new Set<MockHandler>();
  listeners.add(handler);
  registry.set(event, listeners);
  return () => listeners.delete(handler);
}
