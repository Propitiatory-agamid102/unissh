import { b64ToBytes, bytesToB64 } from "./bytes";

export interface ManifestMember {
  ed25519_pub: string; // base64
  role: number; // 0 viewer · 1 editor · 2 admin
}
export interface DecodedManifest {
  epoch: number;
  members: ManifestMember[];
}

const MANIFEST_DOMAIN = "unissh-manifest-v1";

/**
 * Decode a base64 SyncObject manifest envelope (tag 3) → member set.
 * `/v1/grants` returns `manifest` as base64 of the wire envelope, not JSON.
 * Envelope: [3] put(vault) epoch:u64be put(manifest_blob) put(sig) put(author),
 * put = u32be length-prefix. manifest_blob = "unissh-manifest-v1" || epoch:u64be ||
 * count:u32be || [role:u8 || ed_len:u16be || ed25519_pub]*.
 */
export function decodeManifestMembers(manifestB64: string): DecodedManifest | null {
  try {
    const buf = b64ToBytes(manifestB64);
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let p = 0;
    if (buf[p++] !== 3) return null; // tag
    const take = (): Uint8Array => {
      const n = dv.getUint32(p);
      p += 4;
      const b = buf.subarray(p, p + n);
      p += n;
      return b;
    };
    take(); // vault_id
    const epoch = Number(dv.getBigUint64(p));
    p += 8;
    const blob = take(); // manifest_blob

    const bd = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    const dom = new TextDecoder().decode(blob.subarray(0, MANIFEST_DOMAIN.length));
    if (dom !== MANIFEST_DOMAIN) return null;
    // Cross-check: the epoch baked into the signed blob MUST equal the envelope
    // epoch — otherwise a server could present an epoch-mismatched manifest
    // (envelope vs signed body) to confuse the displayed member set.
    const blobEpoch = Number(bd.getBigUint64(MANIFEST_DOMAIN.length));
    if (blobEpoch !== epoch) return null;
    let q = MANIFEST_DOMAIN.length + 8; // skip domain + epoch (== epoch above)
    const count = bd.getUint32(q);
    q += 4;
    const members: ManifestMember[] = [];
    for (let i = 0; i < count; i++) {
      const role = blob[q++];
      const edlen = bd.getUint16(q);
      q += 2;
      const ed = blob.subarray(q, q + edlen);
      q += edlen;
      members.push({ ed25519_pub: bytesToB64(ed), role });
    }
    return { epoch, members };
  } catch {
    return null;
  }
}
