# unissh-crypto

Cryptographic foundation of the **UniSSH** core. A standalone crate: it builds and
tests without storage, SSH, UI, or the network. On top of it are built `keychain`
(the key hierarchy), `storage`, `vault`, and the SSH layer.

> We do not write our own crypto. Only audited RustCrypto crates and
> `hpke` (RFC 9180) are used. See spec 5.5.

## What's inside

| Purpose | Algorithm | Crate |
|---|---|---|
| KDF (password → key) | Argon2id | `argon2` |
| Default symmetric cipher (AEAD) | XChaCha20-Poly1305 | `chacha20poly1305` |
| Public-key encryption | HPKE RFC 9180, DHKEM(X25519, HKDF-SHA256) + ChaCha20-Poly1305 | `hpke` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Content hash for signing | SHA-256 | `sha2` |

### Capabilities (modules)

- **`version`** — per-blob versioning (crypto agility): the header
  `format_version(1) || alg_id(2 be)` + the algorithm registry.
- **`keys`** — key types with secret zeroization (`SymmetricKey`,
  `X25519{Public,Secret}Key`, `Ed25519{Signing,Verifying}Key`).
- **`kdf`** — Argon2id with configurable (adaptive) parameters and their
  serialization.
- **`aead`** — XChaCha20-Poly1305 with **associated data** (binding to
  `vault_id + item_id + version`).
- **`hpke_seal`** — wrapping of a symmetric key under an X25519 public key;
  the `vk_wrap_info` builder for epoch-binding the VK wrapper.
- **`keywrap`** — symmetric wrapping of a key by another key (KEK).
- **`signature`** — signature of a versioned object (Ed25519) + version rollback
  detection.
- **`domain_sig`** — domain-separated Ed25519 signatures over an arbitrary
  canonical payload (contexts outside `VersionedObject`: server-auth, audit).
- **`server_auth`** — a signed server-auth challenge (proof of possession of the
  keyset key) built on top of `domain_sig`.

## Blob formats

Each encrypted/signed blob begins with a **3-byte header**:

```text
[0]      format_version : u8           (current = 0x01)
[1..3]   alg_id         : u16 big-endian
[3..]    body, algorithm-dependent
```

This gives **crypto agility**: a new `alg_id` can be added later, old blobs read
by their id and new ones written by the new one, without breaking storage. `format_version`
changes only on an incompatible change to the layout of the header itself.

### `alg_id` registry

Values are stable forever and are never reused.

| id | Algorithm | Status |
|---|---|---|
| `0x0001` | XChaCha20-Poly1305 (AEAD) | implemented |
| `0x0002` | AES-256-GCM (AEAD) | **reserved** (FIPS/compliance option) |
| `0x0010` | HPKE DHKEM-X25519-HKDF-SHA256 + ChaCha20-Poly1305 | implemented |
| `0x0011` | HPKE hybrid X25519+ML-KEM | **reserved** (post-quantum) |
| `0x0020` | Ed25519 signature | implemented |
| `0x0030` | Argon2id KDF parameters | implemented |

### Blob bodies

```text
AEAD       (0x0001):  header || nonce(24) || ciphertext || tag(16)
HPKE-seal  (0x0010):  header || enc(32)   || ciphertext+tag
Ed25519    (0x0020):  header || signature(64)
KDF-params (0x0030):  header || kdf_id:u8(=1) || mem_kib:u32 be || iterations:u32 be
                              || parallelism:u32 be || salt_len:u8 || salt
```

`keywrap` reuses the AEAD format (`0x0001`): a wrapped key is an ordinary
AEAD ciphertext over the 32 bytes of the key.

### Associated data (context binding)

**Not written** into the blob; reconstructed by the caller, fed into AEAD, and
included in the signed object. Canonical length-prefixed form:

```text
len(vault_id):u16 || vault_id || len(item_id):u16 || item_id || version:u64 be
```

The server (once it exists) will not be able to silently substitute or reorder blobs:
decryption of a foreign/reordered blob will fail AEAD authentication.

### The signed object

```text
domain("unissh-sig-v1") || AssociatedData.canonical || content_digest(32, SHA-256)
```

The signature simultaneously authorizes the object's identity, its version, and its content.

**Rollback detection is stateless.** The signature itself is also valid for an old version
(an attacker could have saved an old signed blob), so "freshness" is checked by
`verify_no_rollback`, comparing `version` against the last seen one. Storing
the "last seen version" is the caller's responsibility (the `storage` crate).

### Domain signatures (`domain_sig`)

For contexts that do not fit into `VersionedObject` (the server-auth challenge,
an audit record), there is a domain-separated signature over an **arbitrary** canonical
payload. The signed message is a length-prefixed domain + payload:

```text
len(domain):u16 be || domain || payload
```

Domains (stable forever):

| Domain | Purpose |
|---|---|
| `unissh-server-auth-v1` | signature of the server-auth challenge (`server_auth`) |
| `unissh-audit-v1` | signature of an audit record (the payload schema is built by the audit module) |

The signature blob is **the same** Ed25519 (`0x0020`): `header || signature(64)`; domain
separation lives in the signed message, not in `alg_id`.

**Non-collision guarantee with `unissh-sig-v1`.** The `sign_version` message begins with
the ASCII bytes of the `unissh-sig-v1` domain (the first is `'u'` = `0x75`), whereas the domain
message begins with the high byte of the domain length (`0x00` for short domains). These
prefixes do not match, so no domain signature can be passed off as a
`VersionedObject` signature or vice versa; the length-prefixed domain also excludes any overlap
between two different domains with each other.

**`server_auth`.** `ServerAuthChallenge { host, account_id, device_id, key_id,
nonce, expiry }` is signed in the `unissh-server-auth-v1` domain. The canonical
payload is the length-prefixed fields + `expiry:u64 be`. The crypto binds all fields
with the signature; checking the expiry/nonce freshness is done by the server, not the crate.

### vk_wrap_info — binding of the VK wrapper (`hpke_seal`)

`vk_wrap_info(vault_id, member_pubkey, key_epoch)` builds the canonical HPKE `info`
for the VK wrapper and binds it to the vault, the recipient, and the **key epoch**:

```text
b"unissh-vkwrap-v1" || len(vault_id):u16 be || vault_id
                    || len(member_pubkey):u16 be || member_pubkey
                    || key_epoch:u64 be
```

`info` is passed to `seal_key_to_public`/`open_key_with_secret` and enters the HPKE
key schedule. Any mismatch (a different vault/recipient/epoch) → `CryptoError::Hpke`
on `open`. **Why the epoch (rotation anti-replay, spec §1.1):** without it the server could
pass off an old `Enc(VK_old, member_pub)` as a fresh wrapper of the current epoch; binding
`key_epoch` makes the old wrapper un-openable under the new epoch.

## Example

```rust
use unissh_crypto::{
    aead_encrypt, aead_decrypt, AssociatedData, SymmetricKey,
    sign_version, verify_no_rollback, VersionedObject, Ed25519Keypair,
};

let key = SymmetricKey::generate();
let aad = AssociatedData::new(b"vault:demo".to_vec(), b"item:1".to_vec(), 1);

let blob = aead_encrypt(&key, b"secret", &aad).unwrap();
let pt = aead_decrypt(&key, &blob, &aad).unwrap();
assert_eq!(pt, b"secret");

let signer = Ed25519Keypair::generate();
let vo = VersionedObject::from_content(aad, &blob);
let sig = sign_version(&signer.signing, &vo).unwrap();
// version 1 is fresher than the last seen 0 — ok; not fresher than 1 — rollback
assert!(verify_no_rollback(&signer.verifying, &vo, &sig, 0).is_ok());
assert!(verify_no_rollback(&signer.verifying, &vo, &sig, 1).is_err());
```

## Security

- **Zeroization.** Secret keys are zeroized on `Drop` (`zeroize`). Temporary
  buffers with decrypted keys are zeroized manually. Access to a secret's raw
  bytes is only through explicit `expose_*` methods (so that a leak into a log/serialization
  is visible in the code).
- **No oracles.** Errors are terse: an AEAD failure does not distinguish "wrong key" from
  "wrong associated data" — both are `CryptoError::Decrypt`.
- **No panics on malformed input** — only `Err`.
- **`#![forbid(unsafe_code)]`.**

## What is not here (other crates / ⏳ later)

- The key hierarchy: Secret Key, `combine`, unlock, the personal keyset → the
  `keychain` crate.
- Storage (SQLCipher), the item/vault/version/tombstone model → `storage`.
- SSH, the built-in agent, **`mlock`** of memory pages → `ssh-agent`/`ssh-transport`.
  Only `zeroize` here.
- Real AES-256-GCM and the PQ hybrid X25519+ML-KEM — only **reserved** in
  the `alg_id` registry, not implemented.
- Sync/network/server.

## Tests

```bash
cargo test -p unissh-crypto
```

They cover every primitive, the round-trip of all wrappers, and negative scenarios
(a broken signature, a version rollback, a wrong key/associated data/password,
a corrupted/foreign/truncated blob). See also `tests/roundtrip.rs` — an end-to-end scenario
of the envelope hierarchy on the `crypto` primitives alone.
