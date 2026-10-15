import { describe, expect, it } from "vitest";
import { confirmationFor } from "./use-lifecycle";

describe("lifecycle confirmations", () => {
  it("asks before anything that would let a held tunnel go direct", () => {
    expect(confirmationFor("recover", "faulted", false)).toBe("recover");
    expect(confirmationFor("start", "faulted", false)).toBe("faulted-start");
    expect(confirmationFor("stop", "running", true)).toBe("stop-blocked");
  });

  it("does not ask for ordinary starts and stops", () => {
    expect(confirmationFor("start", "stopped", false)).toBeNull();
    expect(confirmationFor("stop", "running", false)).toBeNull();
  });
});
