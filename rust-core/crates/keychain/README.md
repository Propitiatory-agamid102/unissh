# unissh-keychain

The UniSSH key hierarchy (spec 5.1). Built on [`unissh-crypto`](../crypto).

## Hierarchy (bottom up)

1. **Secret Key** — `~128 bits`, generated on the device, never leaves for the server.
   Makes an offline brute-force of the password impossible even with a DB dump. Per-instance.
2. **Argon2id** on top of the master password (the primitive and parameters come from
   `crypto`, `KdfParams`).
3. **Unlock Key** = `combine(Argon2id(password), Secret Key)` via **HKDF-SHA256**
   (domain separation: salt `unissh-unlock-salt-v1`, info `unissh-unlock-key-v1`).
4. **Personal keyset** — an X25519 pair (encryption) + Ed25519 (signing),
   encrypted under the Unlock Key.

## API

```rust
use unissh_keychain::{create_account, unlock_account, KdfParams, SecretKey};

// Create an account (first device in the instance)
let (secret_key, encrypted, unlocked) =
    create_account(Some(b"master-password"), KdfParams::recommended()).unwrap();
// secret_key → show in the Emergency Kit; encrypted → persist (storage);
// unlocked → keyset in memory (encryption: X25519, signing: Ed25519).

// Unlock (new launch / another device)
let unlocked = unlock_account(&encrypted, Some(b"master-password"), &secret_key).unwrap();

// Change the master password: re-wrap the keyset under a new Unlock Key (generation+1).
// The old credentials are checked — with wrong ones there is no re-wrap (protection
// against "bricking").
// new_password = None → switch to SecretKeyOnly mode.
let rotated = change_password(&encrypted, Some(b"master-password"), Some(b"new-pw"),
    &secret_key, KdfParams::recommended()).unwrap();
```

## Passwordless mode (SSO + trusted devices)

`create_account(None, …)` → `UnlockMode::SecretKeyOnly`: the root is the Secret Key
(+ in the future a device secret from the Secure Enclave, the `device_secret`
parameter in `derive_unlock_key` is laid out). **Biometrics are not implemented
here** — that is the platform layer of the UI project.

## `EncryptedKeyset` record format

```text
[0]      keyset_format_version : u8 (=1)
[1]      mode                  : u8 (1=Password, 2=SecretKeyOnly)
[2..4]   kdf_params_len        : u16 be (0 if there is no password)
[..]     kdf_params            : crypto::KdfParams blob (if present)
[..+32]  x25519_public         : 32
[..+32]  ed25519_public        : 32
[..]     wrapped_keyset        : crypto AEAD blob over the keyset secrets
```

The plaintext under AEAD = `x25519_secret(32) || ed25519_secret(32)`, bound
(associated data) to the public X25519 key.

## Security

- The Secret Key, Unlock Key and keyset secrets are zeroized (`zeroize`); the
  intermediate buffers (IKM, plaintext keyset) — manually.
- A wrong password/Secret Key → `KeychainError::InvalidCredentials` (without
  distinguishing what exactly is wrong).
- `#![forbid(unsafe_code)]`.

## P5 — identity, server-auth, generation-floor, device onboarding (Milestone 2)

### account-id + registration (server-tz §2.1, §13.3)
- `generate_account_id()` → 16 random bytes (a public id, NOT a secret).
- `store_account_id`/`load_account_id` — persisted in storage-meta (`"account_id"`); re-writing a differing id → `AccountIdConflict`.
- `build_registration(&UnlockedKeyset, &account_id)` → a self-attested blob: an Ed25519 signature (domain `unissh-registration-v1`) over `(account_id ‖ x25519_pub ‖ ed25519_pub)`. `verify_registration(blob, account_id, x_pub, ed_pub)` — self-verify before publishing. Server-side issuance/verification is the server repo.

### server-auth sign side (server-tz §2.2, §13.4)
- `sign_server_challenge(&UnlockedKeyset, &ServerAuthChallenge)` — a wrapper over `crypto::sign_server_auth` (domain `unissh-server-auth-v1`, non-colliding with record signatures). Verification/nonce/expiry are done by the server.

### unlock-from-server-blob + generation-floor (server-tz §9 Path A, §13.13)
- Path A: `EncryptedKeyset::from_bytes(server_bytes)` → `unlock_account_checked(record, pw, sk, &Storage)`.
- A trusted keyset generation floor in storage-meta (`"keyset_gen_floor"`): a record with `generation < floor` → `GenerationRollback` (anti-rollback / protection against a password downgrade). The floor is raised monotonically on a successful unlock and after `change_password` (`raise_floor_after_change_password`).
- **Honest gap (TOFU-generation):** a fresh device without a prior floor accepts the first generation it sees. Confidentiality is preserved, but on the very first unlock the server could hand back a stale generation. Closing it (the Emergency Kit commits the generation) is a seam onto the `recovery` crate. Do NOT hide it behind the invariant "the server cannot hand it out".

### device-to-device PAKE onboarding (server-tz §9 Path B, §13.14)
- PAKE crate: **`spake2` (SPAKE2, Ed25519Group)** — vetted, RustCrypto-aligned, battle-tested in magic-wormhole.rs. NOT `cpace` (the only experimental 0.1.0). We do NOT roll our own crypto.
- Flow: short OOB code → `OnboardInitiator::start` (msg1) → `OnboardResponder::respond` (msg2 = PAKE ‖ responder-confirm-tag) → `OnboardInitiator::confirm_and_seal` (verify responder-tag → msg3 = initiator-tag ‖ sealed-keyset) → `OnboardResponder::finish_install` (verify initiator-tag → decrypt → own device record).
- **Mandatory key confirmation:** SPAKE2 `finish` returns a key even for a wrong code (different keys with no error) → a mutual HMAC transcript tag (directional initiator/responder subkeys) is mandatory; a wrong code → `ConfirmationFailed`, the secrets are not transmitted.
- Secrets live in `Zeroizing`/`SymmetricKey`(ZeroizeOnDrop); plaintext keys are not written to disk and do not cross the FFI (they are transferred only E2E-encrypted).
- The server only relays blobs; in this repo the relay = in-memory passing (tests).

## What is not here

Storage (`storage`), vaults/VK (`vault`), SSH, per-instance DB isolation
(the responsibility of `storage`). The Emergency Kit (formatting) and org-escrow — ⏳ Milestone 2.
