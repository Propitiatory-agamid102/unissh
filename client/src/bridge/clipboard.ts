// Copy a SECRET to the OS clipboard with an optional auto-clear.
//
// The Settings toggle "Clear clipboard after ~30s" (`unissh.clipclear`, default
// ON) promised this but was never implemented — revealed passwords, SSH key
// material, the Secret Key and OOB pairing codes lingered in the shared clipboard
// indefinitely. This wires the actual behaviour: after the delay we re-read the
// clipboard and clear it ONLY if it still holds exactly what we wrote, so we never
// clobber something the user copied in the meantime. OS clipboards can't be
// securely zeroized; this just bounds the exposure window.

import { writeText, readText, clear } from "@tauri-apps/plugin-clipboard-manager";

const CLEAR_DELAY_MS = 30_000;

function clearEnabled(): boolean {
  try {
    return localStorage.getItem("unissh.clipclear") !== "0"; // default on
  } catch {
    return true;
  }
}

let pending: ReturnType<typeof setTimeout> | null = null;

/** Write a secret to the clipboard, scheduling an auto-clear when enabled. */
export async function writeSecretToClipboard(text: string): Promise<void> {
  await writeText(text);
  if (pending) {
    clearTimeout(pending);
    pending = null;
  }
  if (!clearEnabled()) return;
  pending = setTimeout(() => {
    pending = null;
    void (async () => {
      try {
        if ((await readText()) === text) await clear();
      } catch {
        /* best-effort: clipboard may be unavailable or already changed */
      }
    })();
  }, CLEAR_DELAY_MS);
}
