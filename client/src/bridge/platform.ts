// Compile-time platform of the running binary (via @tauri-apps/plugin-os).
import { platform } from "@tauri-apps/plugin-os";

let cached: string | null = null;

export function osPlatform(): string {
  if (cached) return cached;
  try {
    cached = platform();
  } catch {
    cached = "unknown"; // not in a Tauri context (e.g. plain browser preview)
  }
  return cached;
}

/** macOS shows native traffic lights; other desktops need custom controls. */
export const isMac = (): boolean => osPlatform() === "macos";
