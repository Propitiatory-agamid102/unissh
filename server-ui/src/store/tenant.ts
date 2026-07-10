import { create } from "zustand";
import type { OpsTenant } from "../api/types";

interface TenantState {
  tenants: OpsTenant[];
  /** base64 tenant_id for the UniSSH-Tenant header; null until chosen. */
  activeTenantId: string | null;
  loaded: boolean;
  setTenants: (tenants: OpsTenant[]) => void;
  setActive: (tenantId: string) => void;
}

export const useTenant = create<TenantState>()((set, get) => ({
  tenants: [],
  activeTenantId: null,
  loaded: false,
  setTenants: (tenants) =>
    set({
      tenants,
      loaded: true,
      // keep current active if still present; else pick the first.
      activeTenantId:
        get().activeTenantId && tenants.some((t) => t.tenant_id === get().activeTenantId)
          ? get().activeTenantId
          : (tenants[0]?.tenant_id ?? null),
    }),
  setActive: (activeTenantId) => set({ activeTenantId }),
}));

export function activeTenant(): OpsTenant | undefined {
  const { tenants, activeTenantId } = useTenant.getState();
  return tenants.find((t) => t.tenant_id === activeTenantId);
}
