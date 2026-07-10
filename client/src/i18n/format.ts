// Locale-aware formatting built on Intl.*. Replaces the hand-rolled, locale-naive
// helpers (ViewSftp.fmtSize hardcoded B/KB + '.' separator; ViewKnown.fmtAdded
// bare toLocaleDateString). Read the active locale from i18n unless overridden.

import { i18n, currentLang } from "./index";
import { useTranslation } from "react-i18next";

const INTL_LOCALE: Record<string, string> = { ru: "ru-RU", en: "en-US" };
function intlLocale(lang?: string): string {
  const l = (lang ?? currentLang()).toLowerCase().startsWith("ru") ? "ru" : "en";
  return INTL_LOCALE[l];
}
function unit(key: "b" | "kb" | "mb" | "gb" | "ms", lang?: string): string {
  return i18n.t(`format.unit.${key}`, { lng: lang });
}

/** Human file size with locale decimal separator (1,5 MB in ru / 1.5 MB in en). Binary base. */
export function fmtSize(bytes: number, lang?: string): string {
  const nf = new Intl.NumberFormat(intlLocale(lang), { maximumFractionDigits: 1 });
  if (bytes < 1024) return `${nf.format(bytes)} ${unit("b", lang)}`;
  if (bytes < 1024 * 1024) return `${nf.format(bytes / 1024)} ${unit("kb", lang)}`;
  if (bytes < 1024 * 1024 * 1024) return `${nf.format(bytes / (1024 * 1024))} ${unit("mb", lang)}`;
  return `${nf.format(bytes / (1024 * 1024 * 1024))} ${unit("gb", lang)}`;
}

/** Locale date from epoch seconds. Empty string for missing/zero timestamps. */
export function fmtDate(epochSeconds: number, lang?: string): string {
  if (!epochSeconds) return "";
  return new Intl.DateTimeFormat(intlLocale(lang), { dateStyle: "medium" }).format(
    new Date(epochSeconds * 1000),
  );
}

/** Percent from a 0..1 ratio. */
export function fmtPercent(ratio: number, lang?: string): string {
  return new Intl.NumberFormat(intlLocale(lang), {
    style: "percent",
    maximumFractionDigits: 0,
  }).format(ratio);
}

/** Duration in ms with a localized unit (e.g. `123 ms`). */
export function fmtDuration(ms: number, lang?: string): string {
  const nf = new Intl.NumberFormat(intlLocale(lang), { maximumFractionDigits: 0 });
  return `${nf.format(ms)} ${unit("ms", lang)}`;
}

/** Hook variant bound to the active language (re-renders on language change). */
export function useFmt() {
  const { i18n: inst } = useTranslation();
  const lang = inst.language;
  return {
    fmtSize: (b: number) => fmtSize(b, lang),
    fmtDate: (s: number) => fmtDate(s, lang),
    fmtPercent: (r: number) => fmtPercent(r, lang),
    fmtDuration: (ms: number) => fmtDuration(ms, lang),
  };
}
