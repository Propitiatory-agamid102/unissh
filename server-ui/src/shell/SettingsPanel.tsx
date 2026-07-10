import { useTranslation } from "react-i18next";
import { usePrefs } from "../store/prefs";
import { useUi } from "../store/ui";
import { ACCENTS, ACCENT_KEYS } from "../theme/tokens";
import { Icon } from "../ui/icons";
import { Segmented } from "../ui/primitives";

export function SettingsPanel() {
  const { t } = useTranslation();
  const open = useUi((s) => s.panelOpen);
  const togglePanel = useUi((s) => s.togglePanel);

  const mode = usePrefs((s) => s.mode);
  const setMode = usePrefs((s) => s.setMode);
  const accent = usePrefs((s) => s.accent);
  const setAccent = usePrefs((s) => s.setAccent);
  const density = usePrefs((s) => s.density);
  const setDensity = usePrefs((s) => s.setDensity);
  const lang = usePrefs((s) => s.lang);
  const setLang = usePrefs((s) => s.setLang);

  if (!open) return null;

  return (
    <>
      <div onClick={togglePanel} style={{ position: "fixed", inset: 0, zIndex: 120 }} />
      <div
        style={{
          position: "fixed",
          top: 56,
          right: 18,
          width: 290,
          zIndex: 121,
          background: "var(--bg1)",
          border: "1px solid var(--line2)",
          borderRadius: 14,
          boxShadow: "var(--shadow)",
          padding: "14px 16px",
          animation: "popIn .2s ease",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 13 }}>{t("settings.title")}</div>

        <Label>{t("settings.theme")}</Label>
        <Segmented
          value={mode === "light" ? "light" : "dark"}
          onChange={(v) => setMode(v)}
          options={[
            { value: "light", label: t("settings.light") },
            { value: "dark", label: t("settings.dark") },
          ]}
        />

        <Label style={{ marginTop: 13 }}>{t("settings.accent")}</Label>
        <div style={{ display: "flex", gap: 9 }}>
          {ACCENT_KEYS.map((k) => {
            const c = ACCENTS[k].accent;
            const on = accent === k;
            return (
              <button
                key={k}
                onClick={() => setAccent(k)}
                style={{
                  width: 30,
                  height: 30,
                  borderRadius: "50%",
                  background: c,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: on ? "2px solid var(--txt)" : "2px solid transparent",
                  boxShadow: on ? `0 0 0 2px var(--bg1), 0 0 0 4px ${c}` : undefined,
                }}
              >
                {on ? <Icon name="check" size={13} color="#fff" /> : null}
              </button>
            );
          })}
        </div>

        <Label style={{ marginTop: 13 }}>{t("settings.density")}</Label>
        <Segmented
          value={density}
          onChange={(v) => setDensity(v)}
          options={[
            { value: "cards", label: t("common.cards") },
            { value: "list", label: t("common.list") },
          ]}
        />

        <Label style={{ marginTop: 13 }}>{t("settings.lang")}</Label>
        <Segmented
          value={lang}
          onChange={(v) => setLang(v)}
          options={[
            { value: "ru", label: "RU" },
            { value: "en", label: "EN" },
          ]}
        />
      </div>
    </>
  );
}

function Label({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ fontSize: 11, color: "var(--txt3)", fontWeight: 600, marginBottom: 7, ...style }}>
      {children}
    </div>
  );
}
