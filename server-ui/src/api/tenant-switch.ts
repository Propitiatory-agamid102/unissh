import i18n from "i18next";
import { getCrypto } from "../crypto/provider";
import { useSession } from "../store/session";
import { useTenant } from "../store/tenant";
import { useUi } from "../store/ui";

/**
 * Switch the active space (tenant). The admin keyset Bearer is minted per-tenant
 * (challenge/verify carries the UniSSH-Tenant header), so an unlocked keyset is
 * invalid for a different space — leaving it "unlocked" would show a green badge
 * that lies and 401 on every admin call. Lock it and tell the operator instead.
 */
export function switchTenant(tenantId: string): void {
  const tenant = useTenant.getState();
  if (tenant.activeTenantId === tenantId) return;
  const wasUnlocked = useSession.getState().keysetUnlocked;
  tenant.setActive(tenantId);
  if (wasUnlocked) {
    try {
      getCrypto().lock();
    } catch {
      /* crypto may be unavailable */
    }
    useSession.getState().lock();
    useUi.getState().toast("info", i18n.t("access.keysetLockedTenantSwitch"));
  } else {
    useUi.getState().toast("info", i18n.t("screen.tenants.toastSwitched"));
  }
}
