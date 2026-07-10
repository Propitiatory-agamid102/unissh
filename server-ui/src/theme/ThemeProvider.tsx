import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { usePrefs } from "../store/prefs";
import {
  buildPalette,
  paletteToVars,
  type AccentKey,
  type Density,
  type EffMode,
  type Mode,
  type Palette,
} from "./tokens";

interface ThemeCtx {
  palette: Palette;
  mode: Mode;
  effMode: EffMode;
  accent: AccentKey;
  density: Density;
}

const Ctx = createContext<ThemeCtx | null>(null);

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const mode = usePrefs((s) => s.mode);
  const accent = usePrefs((s) => s.accent);
  const density = usePrefs((s) => s.density);

  const [systemDark, setSystemDark] = useState(systemPrefersDark);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setSystemDark(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const effMode: EffMode =
    mode === "auto" ? (systemDark ? "dark" : "light") : mode;
  const palette = useMemo(() => buildPalette(effMode, accent), [effMode, accent]);

  // Apply CSS custom properties + data-* attributes on <html> so every node
  // (including overlay portals) resolves var(--…) correctly.
  useEffect(() => {
    const root = document.documentElement;
    const vars = paletteToVars(palette);
    for (const [k, v] of Object.entries(vars)) root.style.setProperty(k, v);
    root.dataset.theme = effMode;
    root.dataset.accent = accent;
    root.dataset.density = density;
    root.style.colorScheme = effMode;
  }, [palette, effMode, accent, density]);

  const value = useMemo<ThemeCtx>(
    () => ({ palette, mode, effMode, accent, density }),
    [palette, mode, effMode, accent, density],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme must be used within ThemeProvider");
  return v;
}
