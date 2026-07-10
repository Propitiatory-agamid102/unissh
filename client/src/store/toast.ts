// Event-bus toast — `toast(text, kind)` dispatches a CustomEvent that ToastHost
// listens for. Mirrors the prototype's ui-feedback toast system.

export type ToastKind = "ok" | "err" | "warn" | "info";

export interface ToastDetail {
  text: string;
  kind: ToastKind;
}

export function toast(text: string, kind: ToastKind = "info") {
  window.dispatchEvent(new CustomEvent<ToastDetail>("unissh:toast", { detail: { text, kind } }));
}
