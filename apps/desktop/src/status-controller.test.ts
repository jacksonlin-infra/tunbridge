import { describe, expect, it, vi } from "vitest";
import { StatusController } from "./status-controller";
import type { DesktopStatus, StatusViewState } from "./types";

const status: DesktopStatus = {
  schemaVersion: 3,
  servicePhase: "stopped",
  engineRunning: false,
  callerIsOwner: false,
  serviceVersion: "0.1.0",
  readOnly: false,
  capabilities: ["status", "start", "stop", "recover", "lease"],
  stopReason: null,
  degradedReason: null,
};

describe("StatusController", () => {
  it("publishes loading then a fresh read-only status", async () => {
    const states: StatusViewState[] = [];
    const controller = new StatusController(
      async () => status,
      (state) => states.push(state),
      () => 42,
    );

    expect(await controller.refresh()).toBe(true);
    expect(states).toEqual([
      { kind: "loading" },
      { kind: "ready", status, refreshedAt: 42 },
    ]);
  });

  it("rejects overlapping and hidden refreshes without queueing", async () => {
    let resolve: ((value: DesktopStatus) => void) | undefined;
    const load = vi.fn(
      () =>
        new Promise<DesktopStatus>((done) => {
          resolve = done;
        }),
    );
    const controller = new StatusController(load, () => undefined);

    const first = controller.refresh();
    expect(await controller.refresh()).toBe(false);
    expect(load).toHaveBeenCalledTimes(1);
    resolve?.(status);
    await first;

    controller.setVisible(false);
    expect(await controller.refresh()).toBe(false);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("keeps the last good status as explicitly stale on failure", async () => {
    const states: StatusViewState[] = [];
    const load = vi
      .fn<() => Promise<DesktopStatus>>()
      .mockResolvedValueOnce(status)
      .mockRejectedValueOnce({
        code: "service_unavailable",
        safeMessage: "The TunBridge service is unavailable.",
        retryable: true,
      });
    const controller = new StatusController(load, (state) => states.push(state), () => 7);

    await controller.refresh();
    await controller.refresh();

    expect(states.at(-1)).toEqual({
      kind: "failure",
      error: {
        code: "service_unavailable",
        safeMessage: "The TunBridge service is unavailable.",
        retryable: true,
      },
      previous: status,
      failedAt: 7,
    });
  });

  it("drops the last verified status when the service installation changes", async () => {
    const states: StatusViewState[] = [];
    const load = vi
      .fn<() => Promise<DesktopStatus>>()
      .mockResolvedValueOnce(status)
      .mockRejectedValueOnce({
        code: "service_unavailable",
        safeMessage: "The TunBridge service is unavailable.",
        retryable: true,
      });
    const controller = new StatusController(load, (state) => states.push(state), () => 9);

    await controller.refresh();
    controller.invalidate();
    await controller.refresh();

    expect(states.slice(-3)).toEqual([
      { kind: "boot" },
      { kind: "loading" },
      {
        kind: "failure",
        error: {
          code: "service_unavailable",
          safeMessage: "The TunBridge service is unavailable.",
          retryable: true,
        },
        failedAt: 9,
      },
    ]);
  });

  it("ignores a status response that started before installation was invalidated", async () => {
    let resolveOld: ((value: DesktopStatus) => void) | undefined;
    const states: StatusViewState[] = [];
    const load = vi
      .fn<() => Promise<DesktopStatus>>()
      .mockImplementationOnce(
        () =>
          new Promise<DesktopStatus>((resolve) => {
            resolveOld = resolve;
          }),
      )
      .mockRejectedValueOnce({
        code: "service_unavailable",
        safeMessage: "The TunBridge service is unavailable.",
        retryable: true,
      });
    const controller = new StatusController(load, (state) => states.push(state), () => 11);

    const oldRefresh = controller.refresh();
    controller.invalidate();
    expect(await controller.refresh()).toBe(true);
    resolveOld?.(status);
    expect(await oldRefresh).toBe(false);

    expect(states.at(-1)).toEqual({
      kind: "failure",
      error: {
        code: "service_unavailable",
        safeMessage: "The TunBridge service is unavailable.",
        retryable: true,
      },
      failedAt: 11,
    });
  });

  it("maps arbitrary rejected values to a fixed protocol error", async () => {
    const states: StatusViewState[] = [];
    const controller = new StatusController(
      async () => {
        throw new Error("C:\\secret\\pipe details");
      },
      (state) => states.push(state),
    );

    await controller.refresh();
    const failure = states.at(-1);
    expect(failure?.kind).toBe("failure");
    if (failure?.kind === "failure") {
      expect(failure.error).toEqual({
        code: "service_protocol_error",
        safeMessage: "The TunBridge service returned an invalid response.",
        retryable: false,
      });
    }
  });

  it("normalizes accepted error codes instead of trusting backend text", async () => {
    const states: StatusViewState[] = [];
    const controller = new StatusController(
      async () => {
        throw {
          code: "service_identity_failed",
          safeMessage: "C:\\secret\\identity details",
          retryable: false,
        };
      },
      (state) => states.push(state),
    );

    await controller.refresh();
    const failure = states.at(-1);
    expect(failure?.kind).toBe("failure");
    if (failure?.kind === "failure") {
      expect(failure.error.safeMessage).toBe(
        "The TunBridge service identity could not be verified.",
      );
    }
  });
});
