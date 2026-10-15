import { useEffect, useLayoutEffect, useState } from "react";
import type { Language } from "../i18n";

export type ThemeMode = "light" | "dark" | "system";

/** The first supported language in the system preference list; English otherwise. */
export function detectLanguage(preferred: readonly string[]): Language {
  for (const tag of preferred) {
    const lower = tag.toLowerCase();
    if (/^zh(-hant|-tw|-hk|-mo)/.test(lower)) return "zh-TW";
    if (lower.startsWith("zh")) return "zh-CN";
    if (lower.startsWith("ja")) return "ja";
    if (lower.startsWith("en")) return "en";
  }
  return "en";
}

export function usePreferences() {
  // New installs follow the system language; an explicit choice is kept.
  const [language, setLanguage] = useState<Language>(() =>
    (localStorage.getItem("tunbridge.language") as Language | null) ?? detectLanguage(navigator.languages ?? [navigator.language]));
  // New installs follow the system appearance; an explicit choice is kept.
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => (localStorage.getItem("tunbridge.theme") as ThemeMode | null) ?? "system");

  useEffect(() => {
    localStorage.setItem("tunbridge.language", language);
    document.documentElement.lang = language;
  }, [language]);

  // Layout effect: apply the theme before the first paint to avoid a light flash.
  useLayoutEffect(() => {
    localStorage.setItem("tunbridge.theme", themeMode);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme = themeMode === "system"
        ? media.matches ? "dark" : "light"
        : themeMode;
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [themeMode]);

  return { language, setLanguage, themeMode, setThemeMode };
}
