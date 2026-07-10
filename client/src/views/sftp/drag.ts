// Shared drag payload for SFTP rows. We keep the dragged entries in a module ref
// (not DataTransfer) because they're rich objects and stay within the app.

import type { Entry, LocationRef } from "@/store/sftp-types";

export interface DragPayload {
  slotKey: string; // which slot the drag started in ("left" | "right" | "mobile")
  loc: LocationRef;
  cwd: string;
  entries: Entry[]; // one or more dragged entries
}

let current: DragPayload | null = null;

export const dragCtx = {
  set: (d: DragPayload) => {
    current = d;
  },
  get: (): DragPayload | null => current,
  clear: () => {
    current = null;
  },
};
