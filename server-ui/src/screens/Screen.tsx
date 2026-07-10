import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** Standard screen frame: header (title/sub/zk tag + actions) + scrollable body. */
export function Screen({
  title,
  sub,
  zk,
  actions,
  children,
}: {
  title: string;
  sub: string;
  zk?: boolean;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg0)" }}>
      <div
        style={{
          flexShrink: 0,
          padding: "18px 26px 16px",
          borderBottom: "1px solid var(--line)",
          display: "flex",
          alignItems: "flex-start",
          gap: 16,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <h1 style={{ margin: 0, fontSize: 21, fontWeight: 800, letterSpacing: -0.5 }}>{title}</h1>
            {zk ? (
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: 0.4,
                  color: "var(--accent)",
                  background: "var(--accentSoft)",
                  border: "1px solid var(--accentLine)",
                  borderRadius: 6,
                  padding: "2px 7px",
                  whiteSpace: "nowrap",
                }}
              >
                {t("zk.tag")}
              </span>
            ) : null}
          </div>
          <div style={{ fontSize: 13, color: "var(--txt3)", marginTop: 3 }}>{sub}</div>
        </div>
        {actions ? <div style={{ display: "flex", alignItems: "center", gap: 9 }}>{actions}</div> : null}
      </div>
      <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
        <div style={{ padding: "22px 26px 36px" }}>{children}</div>
      </div>
    </div>
  );
}
