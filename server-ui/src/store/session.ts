import { create } from "zustand";

export interface KeysetSession {
  bearer: string;
  refreshToken: string;
  accessExpires: number;
  /** base64 account_id + device_id used to mint this Bearer. */
  accountId: string;
  deviceId: string;
  /** Human label for the header badge (initials / handle). */
  label: string;
}

interface SessionState {
  /** Ops-tier auth: static X-UniSSH-Ops-Token (in memory only). */
  opsToken: string | null;
  /** Admin-tier auth: Bearer from the keyset unlock (in memory only). */
  bearer: string | null;
  refreshToken: string | null;
  accessExpires: number | null;
  keysetUnlocked: boolean;
  adminAccountId: string | null;
  adminDeviceId: string | null;
  adminLabel: string | null;
  /** Reason the ops session ended (shown on the login screen after a bounce). */
  opsNotice: string | null;

  setOpsToken: (t: string) => void;
  clearOps: (notice?: string | null) => void;
  setKeysetSession: (s: KeysetSession) => void;
  setBearer: (bearer: string, accessExpires: number) => void;
  lock: () => void;
}

export const useSession = create<SessionState>()((set) => ({
  opsToken: null,
  bearer: null,
  refreshToken: null,
  accessExpires: null,
  keysetUnlocked: false,
  adminAccountId: null,
  adminDeviceId: null,
  adminLabel: null,
  opsNotice: null,

  setOpsToken: (opsToken) => set({ opsToken, opsNotice: null }),
  clearOps: (notice = null) => set({ opsToken: null, opsNotice: notice }),
  setKeysetSession: (s) =>
    set({
      bearer: s.bearer,
      refreshToken: s.refreshToken,
      accessExpires: s.accessExpires,
      keysetUnlocked: true,
      adminAccountId: s.accountId,
      adminDeviceId: s.deviceId,
      adminLabel: s.label,
    }),
  setBearer: (bearer, accessExpires) => set({ bearer, accessExpires }),
  lock: () =>
    set({
      bearer: null,
      refreshToken: null,
      accessExpires: null,
      keysetUnlocked: false,
      adminAccountId: null,
      adminDeviceId: null,
      adminLabel: null,
    }),
}));
