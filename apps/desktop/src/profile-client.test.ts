import { describe, expect, it } from "vitest";
import { normalizeProfileError } from "./profile-client";

describe("profile error boundary", () => {
  it("maps accepted codes to local fixed text", () => {
    expect(normalizeProfileError({ code: "stale_revision", safeMessage: "C:\\private" })).toEqual({
      code: "stale_revision",
      safeMessage: "The profile list changed. Refresh and try again.",
    });
    expect(normalizeProfileError({ code: "active_profile_locked" })).toEqual({
      code: "active_profile_locked",
      safeMessage: "The active profile cannot be edited or deleted while System TUN is running.",
    });
  });

  it("maps arbitrary values to a fixed internal error", () => {
    for (const value of [new Error("secret"), { code: "delete_all" }, "C:\\private"]) {
      expect(normalizeProfileError(value)).toEqual({
        code: "internal_error",
        safeMessage: "The profile operation failed safely.",
      });
    }
  });
});
