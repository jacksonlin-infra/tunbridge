import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { installProduct, normalizeInstallerError, uninstallProduct } from "./installer-client";

describe("installer client", () => {
  it("uses only closed no-input commands", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await installProduct();
    await uninstallProduct();
    expect(invoke).toHaveBeenNthCalledWith(1, "install_product");
    expect(invoke).toHaveBeenNthCalledWith(2, "uninstall_product");
  });

  it("normalizes untrusted failures to fixed text", () => {
    expect(normalizeInstallerError({ code: "installer_failed", message: "C:\\secret" })).toEqual({
      code: "installer_failed",
      safeMessage: "The TunBridge installer did not complete.",
      retryable: false,
    });
    expect(normalizeInstallerError("raw path").safeMessage).not.toContain("path");
  });
});
