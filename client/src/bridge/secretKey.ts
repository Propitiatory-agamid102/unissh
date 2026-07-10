// Process-wide cache around the OS-keychain Secret Key. Each keychain access can
// trigger a prompt (esp. macOS), so we read at most ONCE per process and update
// the cache locally after a save. Shared by boot() (startup auto-unlock) and the
// Unlock screen so they never both hit the keychain for the same value.

import * as api from "@/bridge/api";

let secretKeyRead: Promise<string | null> | null = null;

/** Read the Secret Key from the OS keychain, cached for the process lifetime. */
export function readSecretKeyOnce(): Promise<string | null> {
  if (!secretKeyRead) secretKeyRead = api.keychainGetSecretKey().catch(() => null);
  return secretKeyRead;
}

/** Persist the Secret Key to the keychain and prime the cache so later reads
 *  don't re-prompt. The write itself is best-effort. */
export function rememberSecretKey(key: string) {
  secretKeyRead = Promise.resolve(key);
  api.keychainSaveSecretKey(key).catch(() => {});
}

/** Drop the cached Secret Key on lock / logout. JS strings can't be truly
 *  zeroized, but releasing the reference removes the long-lived guaranteed-live
 *  copy so GC can reclaim it — matching the user's "locked = secret gone from
 *  memory" expectation. Next read re-fetches from the keychain. */
export function clearSecretKey() {
  secretKeyRead = null;
}
