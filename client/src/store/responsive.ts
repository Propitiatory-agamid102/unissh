// Responsive helpers. The phone shell is selected by the `device` flag (set on
// iOS/Android at boot, or via the desktop⇄mobile preview toggle). Embedded
// desktop views read this to switch to single-column, touch-friendly layouts
// instead of their fixed-width desktop grids/tables.

import { useEffect, useState } from "react";
import { useApp } from "./app";

/** True when the app is rendering the mobile/phone shell. */
export function useIsMobile(): boolean {
  return useApp((s) => s.device === "mobile");
}

/** True when the viewport is in landscape (wider than tall). On a phone this is
 *  the cramped case — the fixed header + tab bar leave little content height — so
 *  the shell compacts its chrome. */
export function useLandscape(): boolean {
  const [land, setLand] = useState(
    typeof window !== "undefined" ? window.innerWidth > window.innerHeight : false,
  );
  useEffect(() => {
    const on = () => setLand(window.innerWidth > window.innerHeight);
    window.addEventListener("resize", on);
    window.addEventListener("orientationchange", on);
    return () => {
      window.removeEventListener("resize", on);
      window.removeEventListener("orientationchange", on);
    };
  }, []);
  return land;
}

/** Height (px) the software keyboard currently overlaps the layout viewport.
 *  The iOS/Android keyboard overlays a `position:fixed` shell rather than
 *  resizing it, so without this the prompt/inputs sit underneath. Apply the
 *  returned value as bottom padding on the fixed shell to lift content clear. */
export function useKeyboardInset(): number {
  const [inset, setInset] = useState(0);
  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    // Auto-calibrate the keyboard height rather than guessing an absolute px gap.
    // `window.innerHeight - visualViewport.height` is NON-ZERO at rest on mobile
    // WebViews (safe-area/home-indicator, sub-pixel rounding), and a fixed
    // threshold (which we tried) is device-dependent — too low and the residual
    // becomes permanent bottom padding that shrinks the fixed shell (the "fills
    // only ~80% of the screen" dead band, and a terminal that fits short leaving a
    // black gap above the bottom bars). Instead: the keyboard-CLOSED visual
    // viewport height is the largest we see for the current orientation, and the
    // keyboard is whatever shrinks it below that. At rest this is exactly 0 on any
    // device; only a real keyboard produces a positive inset.
    let baseInner = window.innerHeight;
    let restHeight = vv.height;
    const onResize = () => {
      // Orientation / layout change (innerHeight moves) → recalibrate the baseline;
      // the software keyboard alone never changes innerHeight, only the viewport.
      if (window.innerHeight !== baseInner) {
        baseInner = window.innerHeight;
        restHeight = vv.height;
      }
      restHeight = Math.max(restHeight, vv.height);
      const overlap = restHeight - vv.height;
      // ignore sub-keyboard jitter (momentum scroll, rounding)
      setInset(overlap > 80 ? Math.round(overlap) : 0);
    };
    vv.addEventListener("resize", onResize);
    vv.addEventListener("scroll", onResize);
    onResize();
    return () => {
      vv.removeEventListener("resize", onResize);
      vv.removeEventListener("scroll", onResize);
    };
  }, []);
  return inset;
}
