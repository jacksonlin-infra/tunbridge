import { describe, expect, it } from "vitest";
import { detectLanguage } from "./use-preferences";

describe("detectLanguage", () => {
  it("follows the first supported system language", () => {
    expect(detectLanguage(["en-US", "zh-CN"])).toBe("en");
    expect(detectLanguage(["zh-CN", "en"])).toBe("zh-CN");
    expect(detectLanguage(["zh-Hans-CN"])).toBe("zh-CN");
    expect(detectLanguage(["ja-JP"])).toBe("ja");
  });

  it("maps traditional Chinese regions and scripts to zh-TW", () => {
    for (const tag of ["zh-TW", "zh-HK", "zh-MO", "zh-Hant", "zh-Hant-TW"]) {
      expect(detectLanguage([tag])).toBe("zh-TW");
    }
  });

  it("skips unsupported languages and falls back to English", () => {
    expect(detectLanguage(["fr-FR", "ja"])).toBe("ja");
    expect(detectLanguage(["de-DE"])).toBe("en");
    expect(detectLanguage([])).toBe("en");
  });
});
