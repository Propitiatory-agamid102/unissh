// Lightweight pub/sub so vault-mutating bridge calls can trigger an auto-sync
// without bridge/api.ts importing the store (which would create an import cycle).
// The store registers a handler via `onVaultMutated`; each mutating command calls
// `vaultMutated(vaultId)` after it succeeds.

type VaultMutatedFn = (vaultId: string) => void;

let handler: VaultMutatedFn | null = null;

/** Register the (single) handler invoked after any vault mutation. */
export function onVaultMutated(fn: VaultMutatedFn): void {
  handler = fn;
}

/** Notify that `vaultId` was just mutated (best-effort; no-op if unregistered). */
export function vaultMutated(vaultId: string): void {
  try {
    handler?.(vaultId);
  } catch {
    /* never let an auto-sync hook break a mutation's result path */
  }
}
