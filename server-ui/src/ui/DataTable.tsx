import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { IconName } from "./icons";
import { Btn, EmptyState, ErrorCard, Spinner } from "./primitives";

export interface Column<T> {
  key: string;
  label: ReactNode;
  /** CSS grid track, e.g. "2fr", "90px", "1.5fr". */
  width: string;
  align?: "left" | "right" | "center";
  render: (row: T) => ReactNode;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, i: number) => string;
  onRowClick?: (row: T) => void;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  empty?: {
    title: string;
    hint?: string;
    icon?: IconName;
    actionLabel?: string;
    onAction?: () => void;
  };
  more?: { hasMore: boolean; loading?: boolean; onMore: () => void };
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  loading,
  error,
  onRetry,
  empty,
  more,
}: DataTableProps<T>) {
  const { t } = useTranslation();
  const template = columns.map((c) => c.width).join(" ");

  const headerCells = columns.map((c) => (
    <span key={c.key} style={{ textAlign: c.align ?? "left" }}>
      {c.label}
    </span>
  ));

  return (
    <div
      style={{
        background: "var(--bg1)",
        border: "1px solid var(--line)",
        borderRadius: 13,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: template,
          gap: 12,
          padding: "11px 16px",
          borderBottom: "1px solid var(--line)",
          background: "var(--bg2)",
          fontSize: 10.5,
          fontWeight: 700,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--txt3)",
        }}
      >
        {headerCells}
      </div>

      {error ? (
        <div style={{ padding: 16 }}>
          <ErrorCard message={error} onRetry={onRetry} />
        </div>
      ) : loading && rows.length === 0 ? (
        <div style={{ display: "flex", justifyContent: "center", padding: "48px 0" }}>
          <Spinner />
        </div>
      ) : rows.length === 0 && empty ? (
        <EmptyState
          icon={empty.icon}
          title={empty.title}
          hint={empty.hint}
          actionLabel={empty.actionLabel}
          onAction={empty.onAction}
        />
      ) : (
        rows.map((row, i) => (
          <div
            key={rowKey(row, i)}
            className={onRowClick ? "dt-row clickable" : "dt-row"}
            onClick={onRowClick ? () => onRowClick(row) : undefined}
            style={{
              display: "grid",
              gridTemplateColumns: template,
              gap: 12,
              padding: "11px 16px",
              borderBottom: "1px solid var(--line)",
              alignItems: "center",
            }}
          >
            {columns.map((c) => (
              <span
                key={c.key}
                style={{
                  textAlign: c.align ?? "left",
                  minWidth: 0,
                  overflow: "hidden",
                  display: c.align === "right" ? "flex" : undefined,
                  justifyContent: c.align === "right" ? "flex-end" : undefined,
                }}
              >
                {c.render(row)}
              </span>
            ))}
          </div>
        ))
      )}

      {more && more.hasMore ? (
        <div style={{ display: "flex", justifyContent: "center", padding: 14 }}>
          <Btn size="sm" variant="ghost" loading={more.loading} onClick={more.onMore}>
            {t("common.more")}
          </Btn>
        </div>
      ) : null}
    </div>
  );
}
