// Desktop terminal keyboard shortcuts. Installed by ViewTerminal (desktop only);
// the listener is capture-phase so it intercepts a combo before xterm forwards it
// to the shell, and only handled combos preventDefault/stopPropagation — plain
// typing (and shell Ctrl+C / Ctrl+D EOF) fall straight through.
//
// Modifier scheme (avoids clobbering the shell):
//   macOS      → Cmd (metaKey)
//   others     → Ctrl+Shift  (so a bare Ctrl+<key> still reaches the shell)
// Shortcuts: new tab (T), close pane/tab (W), split right (D) / down (E),
//   jump to tab N (1..8, 9=last), focus prev/next pane (Arrows). Tab cycling is
//   Ctrl+Tab / Ctrl+Shift+Tab on every platform.

import { useEffect } from "react";
import { useApp, layoutPaneOrder } from "@/store/app";
import { isMac } from "@/bridge/platform";

export function useTerminalShortcuts(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    const mac = isMac();
    const onKey = (e: KeyboardEvent) => {
      const st = useApp.getState();
      if (st.route !== "terminal") return;
      const tabs = st.terminals;
      const active = tabs.find((t) => t.id === st.activeTermId) ?? tabs[tabs.length - 1];

      // Cycle tabs: Ctrl+Tab / Ctrl+Shift+Tab (all platforms).
      if (e.ctrlKey && e.key === "Tab") {
        if (!tabs.length) return;
        e.preventDefault();
        e.stopPropagation();
        const idx = active ? tabs.findIndex((t) => t.id === active.id) : -1;
        const n = tabs.length;
        const next = e.shiftKey ? (idx - 1 + n) % n : (idx + 1) % n;
        st.setActiveTerm(tabs[next].id);
        return;
      }

      const primary = mac
        ? e.metaKey && !e.ctrlKey && !e.altKey
        : e.ctrlKey && e.shiftKey && !e.altKey && !e.metaKey;
      if (!primary) return;

      // Jump to tab N (1..8), 9 = last. e.code so Shift+digit symbols still map.
      const digit = /^Digit([1-9])$/.exec(e.code);
      if (digit) {
        e.preventDefault();
        e.stopPropagation();
        if (!tabs.length) return;
        const n = parseInt(digit[1], 10);
        const target = n === 9 ? tabs[tabs.length - 1] : tabs[n - 1];
        if (target) st.setActiveTerm(target.id);
        return;
      }

      const k = e.key.toLowerCase();

      // New tab → open the inline host picker.
      if (k === "t") {
        e.preventDefault();
        e.stopPropagation();
        st.requestNewTab();
        return;
      }

      if (!active) return; // the rest need an active tab

      if (k === "w") {
        e.preventDefault();
        e.stopPropagation();
        st.closePane(active.id, active.activePaneId);
        return;
      }
      if (k === "d") {
        e.preventDefault();
        e.stopPropagation();
        st.splitPane(active.id, active.activePaneId, "row");
        return;
      }
      if (k === "e") {
        e.preventDefault();
        e.stopPropagation();
        st.splitPane(active.id, active.activePaneId, "col");
        return;
      }
      if (
        e.key === "ArrowLeft" ||
        e.key === "ArrowRight" ||
        e.key === "ArrowUp" ||
        e.key === "ArrowDown"
      ) {
        const order = layoutPaneOrder(active.layout);
        if (order.length < 2) return;
        e.preventDefault();
        e.stopPropagation();
        const cur = order.indexOf(active.activePaneId);
        const back = e.key === "ArrowLeft" || e.key === "ArrowUp";
        const nxt = (cur + (back ? -1 : 1) + order.length) % order.length;
        st.setActivePane(active.id, order[nxt]);
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [enabled]);
}
