import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("../../bridge", () => ({ invoke }));

import {
  loadAppUpdateInformation,
  normalizeAppUpdateError,
  openAppReleasesPage,
} from "./app-update-client";

describe("app update client", () => {
  beforeEach(() => invoke.mockReset());

  it("uses the two fixed backend commands without accepting a URL", async () => {
    invoke.mockResolvedValue(undefined);
    await loadAppUpdateInformation();
    await openAppReleasesPage();
    expect(invoke).toHaveBeenNthCalledWith(1, "get_app_update_information");
    expect(invoke).toHaveBeenNthCalledWith(2, "open_app_releases_page");
  });

  it("normalizes unknown backend failures", () => {
    expect(normalizeAppUpdateError(new Error("private path"))).toEqual({
      code: "invalid_response",
      safeMessage: "The TunBridge release channel returned an invalid response.",
      retryable: true,
    });
  });
});
