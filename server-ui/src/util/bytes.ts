// base64 (STANDARD) + hex helpers for the wire format. The server emits/accepts
// base64-STANDARD for all crypto blobs and ids.

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

/** Short, copy-friendly rendering of a base64 id/pubkey: `head…tail`. */
export function truncId(b64: string | null | undefined, head = 6, tail = 4): string {
  if (!b64) return "—";
  if (b64.length <= head + tail + 1) return b64;
  return `${b64.slice(0, head)}…${b64.slice(-tail)}`;
}
