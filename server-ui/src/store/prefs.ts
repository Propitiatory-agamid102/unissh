import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { AccentKey, Density, Mode } from "../theme/tokens";

export type PubkeyFormat = "truncate" | "full";
export type Lang = "ru" | "en";

interface PrefsState {
  mode: Mode;
  accent: AccentKey;
  density: Density;
  lang: Lang;
  pubkeyFormat: PubkeyFormat;
  /** Base URL of the server instance. Empty → same origin as the panel. */
  instanceUrl: string;
  setMode: (m: Mode) => void;
  toggleMode: () => void;
  setAccent: (a: AccentKey) => void;
  setDensity: (d: Density) => void;
  setLang: (l: Lang) => void;
  setPubkeyFormat: (f: PubkeyFormat) => void;
  setInstanceUrl: (u: string) => void;
}

export const usePrefs = create<PrefsState>()(
  persist(
    (set) => ({
      mode: "dark",
      accent: "blue",
      density: "cards",
      lang: "ru",
      pubkeyFormat: "truncate",
      instanceUrl: "",
      setMode: (mode) => set({ mode }),
      toggleMode: () =>
        set((s) => ({ mode: s.mode === "light" ? "dark" : "light" })),
      setAccent: (accent) => set({ accent }),
      setDensity: (density) => set({ density }),
      setLang: (lang) => set({ lang }),
      setPubkeyFormat: (pubkeyFormat) => set({ pubkeyFormat }),
      setInstanceUrl: (instanceUrl) => set({ instanceUrl }),
    }),
    { name: "unissh-admin-prefs" },
  ),
);
