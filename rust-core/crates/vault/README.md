# unissh-vault (local part)

Local UniSSH vaults (spec 5.2–5.3). Builds on `crypto`, `keychain`, `storage`.

## Model

```text
keyset (X25519) ──HPKE──> wrapped_vk ──> VK (256 bits, per vault)
                                          │
                                          └─keywrap─> per-item key ──AEAD(+AD)──> content
```

- **Local vault** (`SyncTarget::Local`): `create` / `open` / `delete`.
- **Vault Key (VK)** — a random 256-bit per-vault key, wrapped under the
  owner's X25519 public key (HPKE). This is also the sharing format.
- **Per-item keys**, wrapped by the VK (not by the VK itself) → granular
  revocation, bounded blast radius.
- Content is encrypted with the per-item key, bound to `vault_id+item_id+version`
  (associated data). Every record is signed with the owner's **Ed25519** and a
  **monotonic version**; `open`/`get_item` verify the signature.

## API

```rust
let v = Vault::create(&storage, &keyset, b"vault-1".to_vec(), b"Prod")?;
let version = v.put_item(b"ssh-prod", /*item_type*/ 1, ssh_private_key)?;
let item = v.get_item(b"ssh-prod")?.unwrap();   // item.content: Zeroizing<Vec<u8>>
v.list_items()?;                                 // metadata (+ created_at/updated_at)
v.rename_item(b"ssh-prod", b"ssh-prod-2")?;      // moves content, old → tombstone
v.set_name(b"Production")?;                       // rename the vault (version+1)
v.delete_item(b"ssh-prod-2")?;                    // tombstone
// later:
let v = Vault::open(&storage, &keyset, b"vault-1")?;
```

## Membership and grants (P3, Milestone 2)

On top of the local vault, membership, grant, and access-verification primitives
are added (spec §13 items 5–8). Storage keeps signed blobs; **all verification is
in `vault`**. Existing single-owner local vaults are **unchanged** (D2).

- **`vault_id` for cloud** — a random UUIDv4 (`new_vault_id()` → 16 bytes). Local
  vaults may still use any unique bytes.
- **Membership manifest** — one per `key_epoch`, lists the entire member set
  (`ed25519_pub` + role), signed by an admin. Canonical payload (deterministic,
  members sorted by `ed25519_pub` ASC):

  ```text
  b"unissh-manifest-v1" || key_epoch:u64be || member_count:u32be
    || for each member: role:u8 (Viewer=0/Editor=1/Admin=2)
                        || len(ed25519_pub):u16be || ed25519_pub
  ```

  Signature (`sign_version`) with AAD `vault_id + "__manifest__" + key_epoch`.
- **Authority chain (D1, sigchain):** genesis (`epoch 1`) is anchored on the
  vault **creator's** pubkey (passed as `genesis_owner`, pinned at onboarding).
  The manifest of epoch `N` must be signed by an admin from the manifest of epoch
  `N-1`, and `key_epoch` strictly `prev+1`. `verify_manifest` checks the
  signature, authority, and monotonicity.
- **Per-member grant** — `wrapped_vk = seal_key_to_public(recipient_x25519,
  vk, vk_wrap_info(vault_id, member_ed25519_pub, key_epoch))` (D3 binding to
  vault/recipient/epoch). Signature `GRANT_DOMAIN || role:u8 || wrapped_vk` under
  AAD `vault_id + member_ed25519_pub + key_epoch`. `verify_grant` requires the
  author to be an admin in the verified set; `open_grant` unwraps the VK for the
  recipient — any epoch/member/vault mismatch → `Decrypt`.
- **`add_member`** — builds the manifest + grants, **verifies** them (D1 + against
  the set), and persists atomically (one transaction). This is the only write path
  for a manifest into storage → only verified manifests reach the DB.
- **Access predicate (`verify_record_authority`, item 8):** if the vault has a
  manifest for the record's epoch — it requires `author ∈ members@epoch` AND
  `epoch >= vault epoch floor` (`get_vault_epoch_floor`, default 0); otherwise it
  falls back to the single-owner model (`author == genesis_owner`). Integrated into
  `decrypt_record` additively: when no manifest is present, the behavior and error
  type are identical to before (D2).
- **member-pubkey pinning (item 7):** `pin_and_verify_member` — TOFU (like
  `known_hosts`): the first pubkey under `account_id` is pinned, subsequent ones
  must match exactly, otherwise `PinMismatch` (the trusted key is not overwritten).
  `member_fingerprint` = hex(SHA-256(ed25519_pub)) for OOB confirmation.

### Explicitly NOT implemented (⏳ LATER)

- The full person-to-person sharing flow, member key revocation/rotation, key-transparency.
- Reading pre-rotation history (one-way seed-chain of old VKs) — do not write your own crypto.

## VK rotation and purge (P4, server-tz §6.2/§6.4, §13 items 9/10)

### `Vault::rotate_vk(admin_keyset, remaining_members, grants) -> new_epoch`
Eager rotation of the Vault Key for vaults **with membership** (a manifest exists). Atomically:
1. a new `VK'`; `new_epoch = current + 1` (where `current` is the highest epoch of
   an existing manifest, via `Storage::latest_membership_epoch`);
2. a new admin-signed manifest @ `new_epoch` over the remaining members (sigchain
   from the previous epoch — the admin must be Admin@current);
3. per-member grants under `VK'` (binding `vk_wrap_info(vault_id, member, new_epoch)`);
4. **re-wrap** of each live item: the per-item key is re-wrapped under `VK'`, the
   content is re-encrypted with the same per-item key under a versioned AAD (the
   plaintext does not change), version+1, `key_epoch=new_epoch`, re-signed;
5. vault record: the owner's `wrapped_vk` under `VK'`, `version+1`, `key_epoch=new_epoch`;
6. raising the **epoch floor** (`set_vault_epoch_floor`) to `new_epoch`.

Everything runs in one `storage.transaction` (a partial failure → a consistent rollback).
A revoked member is simply absent from the manifest/grants → gets no grant under `VK'`.
A local vault (no manifest) is **not rotated** (`NotAMember`). Rotation by a non-admin →
`AuthorityInvalid`. After rotation the `Vault` instance is stale — reopen via
`Vault::open`/grant (the method takes `&self`, updates only storage; the in-memory
`vk`/`version` stay old and are valid for re-wrapping OLD records until commit).

**Design note (re-wrap):** the per-item key wrapping (`wrapped_item_key`) is bound
to `item_id` (not to the epoch/version) — re-wrapping under `VK'` is trivial. But
`content_blob` is bound to AAD `vault_id+item_id+version`, and storage requires a
strictly increasing version (UPSERT `WHERE excluded.version > items.version`), so the
version must be bumped, and with it the content AAD changes → `content_blob`
**is re-encrypted with the same per-item key** under the new-versioned AAD. The
plaintext and per-item key are identical; byte-for-byte immutability of the ciphertext
is impossible on a version bump (the XChaCha20 nonce is random). Only the key wrapping
(VK→VK') and the epoch change.

**Not covered:** reading pre-rotation history requires keeping old VKs at the
remaining members (old wrappings `@epoch_k` are valid by the §1.1 binding); a full
one-way seed-chain — ⏳ LATER (do not write your own crypto).

### `Vault::purge_vault(self)`
Cooperative hard-delete on a verified revoke signal: physically deletes the
vault record, items (incl. tombstones), history, manifests, grants, the epoch floor (via
`Storage::purge_vault_data`); zeroizes the in-memory VK (consumes `self`).
**Best-effort/hygiene, NOT remote-wipe** — already-synced plaintext on other/
modified clients is not revoked; hard cryptographic revocation is
`rotate_vk`.

### `verify_chain` (member-aware, P4)
For records whose `key_epoch` has a manifest — the author is verified by the full D1
authority chain up to genesis AND `key_epoch >= floor` (anti-rollback); otherwise —
a single-owner check (`author == owner`, D2 — the local audit is not weakened).
Old-epoch/non-member records are flagged `IntegrityFailure::NotAuthorized`.

## Extension points (⏳ Milestone 2, partially laid out)

- **Cloud vault** — `SyncTarget` is extensible.
- **Person-to-person sharing** — membership/grant/verification primitives added (P3,
  above); `Vault::seal_vk_to_recipient(recipient_pub)` remains as the owner's VK
  wrapping. The full distribution/revocation flow comes later.
- **VK rotation / purge** — implemented (P4, see the section above).

## Security

- VK and per-item keys are `SymmetricKey` (zeroized on Drop); decrypted content is
  `Zeroizing<Vec<u8>>`.
- A wrong keyset → `VaultError::Decrypt`; metadata tampering → `SignatureInvalid`.
- `#![forbid(unsafe_code)]`.

## What is not here

Cloud sync, the full sharing flow, SSH.
