export const SERVICE_PHASES = [
  "stopped",
  "starting",
  "running",
  "stopping",
  "recovering",
  "faulted",
] as const;

export type ServicePhase = (typeof SERVICE_PHASES)[number];

export type ServiceCapability =
  | "status"
  | "start"
  | "stop"
  | "recover"
  | "lease"
  | "observe_local_traffic"
  | "close_owned_connections"
  | "remote_upstream"
  | "observe_mihomo_logs";

export interface TrafficSnapshot {
  schemaVersion: 1;
  engineGeneration: string;
  sequence: number;
  sampledAtUnixMs: number;
  intervalMs: number;
  uploadBps: number;
  downloadBps: number;
  uploadTotal: number;
  downloadTotal: number;
  activeConnections: number;
  memoryBytes: number;
  stale: boolean;
}

export type ConnectionState = "active" | "closed";

export interface ConnectionView {
  id: string;
  host: string;
  network: string;
  connectionType: string;
  source: string;
  destination: string;
  processName?: string;
  chains: string[];
  rule: string;
  rulePayload?: string;
  uploadTotal: number;
  downloadTotal: number;
  uploadBps: number;
  downloadBps: number;
  startedAt: string;
  closedAtUnixMs?: number;
}

export interface ConnectionPage {
  schemaVersion: 1;
  engineGeneration: string;
  sequence: number;
  state: ConnectionState;
  offset: number;
  limit: number;
  total: number;
  items: ConnectionView[];
}

export type MihomoLogLevel = "debug" | "info" | "warning" | "error";

export interface MihomoLogEntry {
  sequence: number;
  observedAtUnixMs: number;
  level: MihomoLogLevel;
  message: string;
  truncated: boolean;
}

export interface MihomoLogPage {
  schemaVersion: 1;
  engineGeneration: string;
  oldestSequence: number;
  nextSequence: number;
  items: MihomoLogEntry[];
}

export type TrafficErrorCode =
  | "service_unavailable"
  | "service_identity_failed"
  | "service_protocol_error"
  | "not_running"
  | "not_owner"
  | "traffic_unavailable"
  | "connection_not_found";

export interface TrafficError {
  code: TrafficErrorCode;
  safeMessage: string;
  retryable: boolean;
}

export interface CloseConnectionsResult {
  schemaVersion: 1;
  closed: number;
}

export type WebsiteTarget =
  | "apple"
  | "github"
  | "google"
  | "youtube"
  | "chatgpt"
  | "claude"
  | "gemini"
  | "netflix"
  | "spotify"
  | "tiktok";

export interface WebsiteTestResult {
  schemaVersion: 1;
  target: WebsiteTarget;
  reachable: boolean;
  latencyMs: number;
  httpStatus: number;
}

export interface IpInformation {
  schemaVersion: 1;
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  timezone: string;
  asn: number;
  organization: string;
  provider: "ipinfo.io";
}

export interface SystemInformation {
  schemaVersion: 1;
  osName: string;
  displayVersion: string;
  buildNumber: string;
  architecture: string;
  autoLaunch: boolean;
  appVersion: string;
  coreVersion: string;
}

export interface CoreUpdateInformation {
  schemaVersion: 1;
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
}

export interface AppUpdateInformation {
  schemaVersion: 1;
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  publishedAt: string;
  target: string;
  packageKind: "nsis" | "dmg" | "deb" | "pacman";
  minimumOs: string;
  assetName: string;
}

export type AppUpdateErrorCode =
  | "busy"
  | "update_unavailable"
  | "invalid_response"
  | "unsupported_target"
  | "release_page_unavailable"
  | "worker_failed";

export interface AppUpdateError {
  code: AppUpdateErrorCode;
  safeMessage: string;
  retryable: boolean;
}

export type DiagnosticErrorCode =
  | "network_unavailable"
  | "provider_unavailable"
  | "invalid_response"
  | "system_info_unavailable"
  | "core_update_unavailable"
  | "core_update_identity_failed"
  | "core_update_failed";

export interface DiagnosticError {
  code: DiagnosticErrorCode;
  safeMessage: string;
  retryable: boolean;
}

export type WatchdogReason =
  | "engine_exited"
  | "upstream_unavailable"
  | "controller_unavailable"
  | "adapter_missing"
  | "runtime_identity_mismatch"
  | "lease_expired"
  | "connection_storm";

export interface DesktopStatus {
  schemaVersion: 3;
  servicePhase: ServicePhase;
  engineRunning: boolean;
  callerIsOwner: boolean;
  serviceVersion: string;
  readOnly: boolean;
  capabilities: ServiceCapability[];
  /** Why the service stopped or faulted the session on its own. */
  stopReason: WatchdogReason | null;
  /** Why a running session fails closed while its upstream is unusable. */
  degradedReason: WatchdogReason | null;
}

export type DesktopErrorCode =
  | "service_unavailable"
  | "service_identity_failed"
  | "service_protocol_error"
  | "service_rejected";

export interface DesktopError {
  code: DesktopErrorCode;
  safeMessage: string;
  retryable: boolean;
}

export type StatusViewState =
  | { kind: "boot" }
  | { kind: "loading"; previous?: DesktopStatus }
  | { kind: "ready"; status: DesktopStatus; refreshedAt: number }
  | {
      kind: "failure";
      error: DesktopError;
      previous?: DesktopStatus;
      failedAt: number;
    };

export type ProxyProtocol = "socks5" | "http";

export interface LocalProxyCandidate {
  port: number;
  protocol: ProxyProtocol;
  processHint?: string;
}

export type DiscoveryWarningCode =
  | "listener_enumeration_unavailable"
  | "listener_limit_reached"
  | "discovery_deadline_reached";

export interface DiscoveryResponse {
  schemaVersion: 1;
  candidates: LocalProxyCandidate[];
  warningCodes: DiscoveryWarningCode[];
}

export type ProxyErrorCode =
  | "invalid_input"
  | "busy"
  | "connect_failed"
  | "authentication_failed"
  | "protocol_mismatch"
  | "upstream_timeout"
  | "test_target_unavailable"
  | "invalid_response";

export interface ProxyError {
  code: ProxyErrorCode;
  safeMessage: string;
}

export interface ProxyTestInput {
  port: number;
  protocol: ProxyProtocol;
  username?: string;
  password?: string;
}

export interface ProxyTestResponse {
  schemaVersion: 1;
  ok: boolean;
  httpCode: number | null;
  latencyMs: number | null;
  udpSupported: boolean;
  errorCode: ProxyErrorCode | null;
}

export type IpPreference = "ipv4" | "ipv6" | "ipv4_prefer" | "ipv6_prefer";
export type CertificatePolicy = "strict" | "insecure";

export interface RemoteEndpoint {
  host: string;
  port: number;
  ipPreference: IpPreference;
}

export type RemoteProtocolConfig =
  | {
      protocol: "http";
      tls: boolean;
      sni: string | null;
      certificatePolicy: CertificatePolicy;
    }
  | {
      protocol: "socks5";
      tls: boolean;
      sni: string | null;
      udp: boolean;
      certificatePolicy: CertificatePolicy;
    };

export type ProfileUpstream =
  | { kind: "local_listener"; port: number; protocol: ProxyProtocol }
  | {
      kind: "remote_server";
      endpoint: RemoteEndpoint;
      protocolConfig: RemoteProtocolConfig;
    };

export interface SavedProfile {
  profileId: string;
  displayName: string;
  upstream: ProfileUpstream;
  hasCredential: boolean;
}

export interface ProfileList {
  schemaVersion: 2;
  storeRevision: number;
  profiles: SavedProfile[];
}

export type ProfileErrorCode =
  | "invalid_input"
  | "busy"
  | "active_profile_locked"
  | "stale_revision"
  | "not_found"
  | "limit_reached"
  | "storage_untrusted"
  | "credential_unavailable"
  | "transaction_unknown"
  | "internal_error";

export interface ProfileError {
  code: ProfileErrorCode;
  safeMessage: string;
}

export type LifecycleErrorCode =
  | "busy"
  | "profile_unavailable"
  | "upstream_identity_unavailable"
  | "service_unavailable"
  | "service_identity_failed"
  | "service_protocol_error"
  | "service_rejected"
  | "lease_unavailable"
  | "worker_failed";

export interface LifecycleError {
  code: LifecycleErrorCode;
  safeMessage: string;
  retryable: boolean;
  serviceCode?: string;
  serviceMessage?: string;
}

export type InstallerErrorCode =
  | "busy"
  | "installer_unavailable"
  | "installer_identity_failed"
  | "elevation_cancelled"
  | "installer_timeout"
  | "installer_failed"
  | "worker_failed";

export interface InstallerError {
  code: InstallerErrorCode;
  safeMessage: string;
  retryable: boolean;
}

export type TunnelEventKind =
  | "app_started"
  | "started"
  | "stopped"
  | "blocked"
  | "resumed"
  | "faulted"
  | "recovered"
  | "start_failed";

/** Who caused a tunnel event: the user in this App, the service, or nobody seen (noticed later). */
export type TunnelEventActor = "user" | "service" | "observed";

export interface TunnelEvent {
  atUnixMs: number;
  kind: TunnelEventKind;
  actor: TunnelEventActor;
  reason?: WatchdogReason;
  phase?: ServicePhase | "unavailable";
  profileId?: string;
  downloadTotal?: number;
  uploadTotal?: number;
}

export interface TunnelEventPage {
  schemaVersion: 1;
  events: TunnelEvent[];
}
