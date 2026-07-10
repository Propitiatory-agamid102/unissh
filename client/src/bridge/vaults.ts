import type { ServerStatus, VaultInfo } from "./types";

/** Short human label for a server link: its handle, else the host of its base URL. */
export function serverShortLabel(s: ServerStatus): string {
  if (s.handle) return s.handle;
  if (s.baseUrl) {
    try {
      return new URL(s.baseUrl).host;
    } catch {
      return s.baseUrl;
    }
  }
  return "server";
}

/** Where a vault physically lives: on-device (local) or a cloud Space on a server. */
export function vaultLoc(
  v: VaultInfo,
  servers: ServerStatus[],
): { local: boolean; server: string | null } {
  if (v.syncTarget !== "cloud") return { local: true, server: null };
  const s = servers.find((x) => x.tenantId && x.tenantId === v.syncTenant) ?? null;
  return { local: false, server: s ? serverShortLabel(s) : null };
}

/** A cloud vault in a Space YOU own (bootstrapped) — the kind that can hold identities
 *  inside the company perimeter, invisible to that server's admin. */
export function isOwnedCloud(v: VaultInfo, servers: ServerStatus[]): boolean {
  return (
    v.syncTarget === "cloud" &&
    servers.some((s) => s.tenantId && s.tenantId === v.syncTenant && s.owned)
  );
}
