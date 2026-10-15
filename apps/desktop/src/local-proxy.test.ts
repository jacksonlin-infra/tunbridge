import { describe, expect, it } from "vitest";
import { normalizeProxyError } from "./local-proxy";

describe("local proxy error boundary", () => {
  it("maps every accepted code to local fixed text", () => {
    expect(normalizeProxyError({ code: "busy", safeMessage: "C:\\private" })).toEqual({
      code: "busy",
      safeMessage: "Another local proxy operation is already active.",
    });
  });

  it("maps arbitrary values and unknown codes to a fixed invalid response", () => {
    for (const value of [new Error("C:\\private"), { code: "shell_failed" }, "secret"]) {
      expect(normalizeProxyError(value)).toEqual({
        code: "invalid_response",
        safeMessage: "The local proxy returned an invalid test response.",
      });
    }
  });
});
