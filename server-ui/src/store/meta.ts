import { create } from "zustand";

type CountKey = "accounts" | "pending_invites" | "devices";

interface MetaState {
  counts: Partial<Record<CountKey, number>>;
  setCounts: (c: Partial<Record<CountKey, number>>) => void;
  clear: () => void;
}

/** Sidebar badge counts, populated by the Overview screen / shell bootstrap. */
export const useMeta = create<MetaState>()((set) => ({
  counts: {},
  setCounts: (c) => set((s) => ({ counts: { ...s.counts, ...c } })),
  clear: () => set({ counts: {} }),
}));
