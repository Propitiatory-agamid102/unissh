// useCtx() — the action bundle passed implicitly to views, mirroring the
// prototype's `ctx` DI object so ported views read almost 1:1.

import { useTheme } from "@/theme/ThemeProvider";
import type { ConnectionProfile } from "@/bridge/types";
import { useApp, makePane, mkTabId, type ModalKind, type Route } from "./app";
import { toast } from "./toast";

/** Open a new terminal tab (single pane) for a saved host profile. The Terminal
 *  view performs the actual session_open (it needs the xterm write callback). */
export function connectProfile(profile: ConnectionProfile) {
  const s = useApp.getState();
  s.markConnected(profile.profileId);
  const pane = makePane(profile);
  s.addTerminal({
    id: mkTabId(profile.profileId),
    title: profile.label,
    panes: [pane],
    layout: { kind: "pane", paneId: pane.id },
    activePaneId: pane.id,
  });
}

export function connectById(profileId: string) {
  const s = useApp.getState();
  const profile = s.hosts.find((h) => h.profileId === profileId);
  if (profile) connectProfile(profile);
}

export interface Ctx {
  go: (r: Route) => void;
  goFiltered: (f: string) => void;
  vault: string | null;
  hostFilter: string;
  setHostFilter: (f: string) => void;
  openModal: (m: ModalKind) => void;
  onNewHost: () => void;
  openImport: () => void;
  openGroups: () => void;
  openPalette: () => void;
  onLock: () => void;
  onShowKit: () => void;
  confirm: (c: import("./app").ConfirmData) => void;
  toast: typeof toast;
  connect: (profile: ConnectionProfile) => void;
  connectById: (id: string) => void;
  reloadVault: () => Promise<void>;
  termThemeId: string;
}

export function useCtx(): Ctx {
  const s = useApp();
  const theme = useTheme();
  return {
    go: s.go,
    goFiltered: s.goFiltered,
    vault: s.vaultId,
    hostFilter: s.hostFilter,
    setHostFilter: s.setHostFilter,
    openModal: s.openModal,
    onNewHost: () => s.openModal({ kind: "host" }),
    openImport: () => s.setImporting(true),
    openGroups: () => s.setGroupsModal(true),
    openPalette: () => s.setPalette(true),
    onLock: s.lockInstance,
    onShowKit: () => s.setOverlay("kit"),
    confirm: (c) => s.setConfirm(c),
    toast,
    connect: connectProfile,
    connectById,
    reloadVault: s.reloadVault,
    termThemeId: theme.termThemeId,
  };
}
