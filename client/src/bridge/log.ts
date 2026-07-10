// Frontend logging facade. Routes through the Tauri log plugin so messages land
// in the same sinks as the backend (stdout + rotating file + webview console),
// and falls back to the browser console when not in a Tauri context (e.g. plain
// `vite dev`), so a log is never silently lost.
//
// Redaction (mirrors the backend, spec §13): never pass secrets here — no private
// keys, passphrases, master password, Secret Key, tokens or vault plaintext. Log
// metadata and error messages only.

import { error as plogError, warn as plogWarn, info as plogInfo, debug as plogDebug } from "@tauri-apps/plugin-log";

function emit(
  plugin: (m: string) => Promise<void>,
  fallback: (m: string) => void,
  msg: string,
) {
  try {
    plugin(msg).catch(() => fallback(msg));
  } catch {
    fallback(msg);
  }
}

export const logError = (msg: string) => emit(plogError, (m) => console.error(m), msg);
export const logWarn = (msg: string) => emit(plogWarn, (m) => console.warn(m), msg);
export const logInfo = (msg: string) => emit(plogInfo, (m) => console.info(m), msg);
export const logDebug = (msg: string) => emit(plogDebug, (m) => console.debug(m), msg);
