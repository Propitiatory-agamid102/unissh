import { getCrypto } from "../crypto/provider";
import { useSession } from "../store/session";
import { b64ToBytes, bytesToB64, truncId } from "../util/bytes";
import { api } from "./index";

export interface UnlockParams {
  /** EncryptedKeyset bytes (imported .keyset file). */
  encKeyset: Uint8Array;
  password: string | null;
  /** Secret Key from the Emergency Kit. */
  secretKey: Uint8Array;
  /** base64 account_id + device_id this admin device is registered under. */
  accountId: string;
  deviceId: string;
  label?: string;
}

/**
 * Two-level keyset unlock: decrypt the keyset locally (key never leaves memory),
 * then challenge → sign (unissh-server-auth-v1) → verify to obtain the admin Bearer.
 */
export async function unlockWithKeyset(p: UnlockParams): Promise<void> {
  const crypto = getCrypto();
  const id = await crypto.unlock(p.encKeyset, p.password, p.secretKey);
  const keyId = bytesToB64(id.ed25519_pub);

  const challenge = await api.identity.challenge(p.accountId, p.deviceId, keyId);
  const sig = await crypto.signChallenge({
    host: challenge.host ? b64ToBytes(challenge.host) : new Uint8Array(0),
    account_id: b64ToBytes(challenge.account_id),
    device_id: b64ToBytes(challenge.device_id),
    key_id: b64ToBytes(challenge.key_id),
    nonce: b64ToBytes(challenge.nonce),
    expiry: challenge.expiry,
  });

  const verify = await api.identity.verify(challenge, bytesToB64(sig));
  useSession.getState().setKeysetSession({
    bearer: verify.access_token,
    refreshToken: verify.refresh_token,
    accessExpires: verify.access_expires,
    accountId: p.accountId,
    deviceId: p.deviceId,
    label: p.label || truncId(p.accountId),
  });
}

/** Wipe the unlocked keyset + Bearer from memory (ops session stays). */
export function lockKeyset(): void {
  getCrypto().lock();
  useSession.getState().lock();
}
