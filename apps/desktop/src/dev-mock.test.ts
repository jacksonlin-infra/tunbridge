import { describe, expect, it } from "vitest";
import { mockInvoke, resetDevMockForTest } from "./dev-mock";

const commands: Array<[string, Record<string, unknown> | undefined]> = [
  ["get_status", undefined],
  ["take_pending_tray_navigation", undefined],
  ["get_traffic_snapshot", undefined],
  ["get_connections_page", { input: { state: "active", offset: 0, limit: 25 } }],
  ["close_connection", { input: { connectionId: "mock-connection-github" } }],
  ["close_all_connections", undefined],
  ["test_website", { input: { target: "github" } }],
  ["get_ip_information", undefined],
  ["get_system_information", undefined],
  ["set_auto_launch", { enabled: true }],
  ["get_app_update_information", undefined],
  ["open_app_releases_page", undefined],
  ["get_core_update_information", undefined],
  ["install_core_update", undefined],
  ["discover_upstreams", undefined],
  ["test_upstream", { input: { port: 7890, protocol: "socks5" } }],
  ["list_profiles", undefined],
  [
    "create_profile",
    {
      input: {
        expectedStoreRevision: 1,
        displayName: "Test profile",
        upstream: { kind: "local_listener", port: 8080, protocol: "http" },
        credential: null,
      },
    },
  ],
  [
    "update_profile",
    {
      input: {
        expectedStoreRevision: 1,
        profileId: "mock-profile-local",
        displayName: "Updated profile",
        upstream: { kind: "local_listener", port: 7890, protocol: "socks5" },
        credentialAction: { action: "keep" },
      },
    },
  ],
  [
    "delete_profile",
    {
      input: {
        expectedStoreRevision: 1,
        profileId: "mock-profile-local",
      },
    },
  ],
  [
    "test_saved_profile",
    {
      input: {
        expectedStoreRevision: 1,
        profileId: "mock-profile-local",
      },
    },
  ],
  [
    "start_saved_profile",
    {
      input: {
        expectedStoreRevision: 1,
        profileId: "mock-profile-local",
      },
    },
  ],
  ["get_active_profile_id", undefined],
  ["stop_tunnel", undefined],
  ["recover_tunnel", undefined],
  ["install_product", undefined],
  ["uninstall_product", undefined],
];

describe("dev-only command backend", () => {
  it("covers the complete 27-command surface", async () => {
    expect(commands).toHaveLength(27);
    for (const [command, args] of commands) {
      resetDevMockForTest();
      await expect(mockInvoke(command, args)).resolves.not.toThrow();
    }
  });

  it("supports lifecycle state transitions", async () => {
    resetDevMockForTest();
    await mockInvoke("stop_tunnel");
    await expect(mockInvoke<{ servicePhase: string }>("get_status")).resolves.toMatchObject({
      servicePhase: "stopped",
    });
    await mockInvoke("start_saved_profile");
    await expect(mockInvoke<{ servicePhase: string }>("get_status")).resolves.toMatchObject({
      servicePhase: "running",
    });
  });

  it("provides explicit service error and fault scenarios", async () => {
    resetDevMockForTest("service-error");
    await expect(mockInvoke("get_status")).rejects.toMatchObject({
      code: "service_unavailable",
      retryable: true,
    });
    resetDevMockForTest("faulted");
    await expect(mockInvoke<{ servicePhase: string }>("get_status")).resolves.toMatchObject({
      servicePhase: "faulted",
    });
  });
});
