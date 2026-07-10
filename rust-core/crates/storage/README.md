# unissh-storage

UniSSH local encrypted storage: **SQLite + SQLCipher** (bundled, linked
against the system OpenSSL). Stores already-encrypted blobs + cleartext metadata.

## Instance isolation (spec 2A)

Each instance is a **separate encrypted DB file with its own 32-byte key**
(SQLCipher raw key). Data from different instances is never physically mixed;
compromising one instance's key does not expose another. A local vault is an "instance
without a server".

```rust
use unissh_storage::Storage;
let db_key = [0u8; 32];                 // instance key (from vault/keychain)
let s = Storage::open(std::path::Path::new("/path/inst.db"), &db_key)?;
```

Wrong key → `StorageError::WrongKeyOrCorrupt`.

## Data model (laid out for future sync, spec 9 / 5.4)

`VaultRecord` and `ItemRecord` carry sync fields even though sync does not exist yet:

| Field | Purpose |
|---|---|
| `version: u64` | monotonic version (storage enforces the increase — anti-rollback at the DB level) |
| `signature`, `author_pubkey` | signature of the change's author (Ed25519 blob from `crypto`) |
| `tombstone: bool` | deletion as a first-class sync event |
| `server_seq` (in the schema) | sync cursor (not used yet) |
| `wrapped_vk` / `wrapped_item_key` | wrapped keys (the `vault` layer) |
| `name_blob` / `content_blob` | ciphertext (the `vault` layer) |

Storage **does not encrypt content and does not verify signatures** — that is the `vault` layer. Storage
provides: instance isolation, ciphertext storage, version monotonicity,
soft deletion (tombstone), TOFU pinning of the host key (`known_hosts`, for `ssh-transport`).

## API (in brief)

- Vaults: `put_vault`, `get_vault`, `list_vaults` (without tombstones). `VaultRecord`
  carries `key_epoch` (the vault key's epoch) and `cache_policy` (`OfflineAllowed`/
  `OnlineOnly`); `sync_target` is `Local`/`Cloud`.
- Items: `put_item` (version monotonicity), `get_item`, `list_items`,
  `list_items_including_tombstones`. Deletion = `put_item` with `tombstone=true` and
  an increased version. `ItemRecord` carries `key_epoch`.
- `purge_vault_data(vault_id)` — an atomic hard-delete of all of a vault's rows across all
  tables (vaults, items, item_history, membership_manifests, membership_grants,
  vault_epoch_floor, cert_meta). Unlike a tombstone (a logical deletion with
  a version increase for sync), here the rows are physically deleted. Used
  by the `vault` layer for `purge_vault` (a cooperative revoke, server-spec §6.4) —
  best-effort, not a remote wipe.
- TOFU: `get_known_host`, `put_known_host`, `list_known_hosts`, `remove_known_host`.
- Instance metadata: `set_meta`, `get_meta`.
- Membership (storage): `put_membership_manifest`, `get_membership_manifest`,
  `latest_membership_epoch` (the highest manifest epoch, used to determine the current
  membership epoch before a VK rotation), `put_membership_grant`,
  `list_membership_grants`, `remove_membership_grant`.
- Pinning of the member pubkey: `pin_member_key`, `get_pinned_member_key`,
  `list_pinned_member_keys`, `remove_pinned_member_key`.
- Audit (append-only): `append_audit` (returns `seq`), `list_audit(since_seq)`.
- Sync-state: `set_sync_cursor`/`get_sync_cursor`,
  `set_vault_epoch_floor`/`get_vault_epoch_floor`.

Items carry `created_at`/`updated_at` (unix seconds) — **cleartext, unsigned, and
non-synced** timestamps; storage sets them (created on the first insert and
preserved thereafter, updated on every write), values in the input record are ignored.

## Schema and migrations

`PRAGMA user_version` holds the schema version (currently `5`); `migrate()` applies DDL
idempotently in steps (`if current < N`), each step atomic (`run_step`: DDL and bumping
`user_version` in one transaction, rolling back on failure). Version 2 added
`items.created_at`/`items.updated_at`; version 3 added `item_history`; version 5 added
`vaults.sync_tenant` (a 1:1 binding of a cloud vault to a server by its `tenant_id`;
empty = unbound/legacy/local).

### Schema V4 (server-prerequisites Milestone 2)

V4 extends the schema for future server-side sync/sharing. **Storage only stores
ciphertext, signed blobs, and cleartext metadata — it does not verify signatures,
epochs, or membership. All crypto verification and authorization is the `vault`/`crypto` layer
(P3/P4).** What was added:

| Object | Purpose | Who verifies the crypto/invariant |
|---|---|---|
| `vaults.key_epoch`, `items.key_epoch`, `item_history.key_epoch` | the vault key's epoch (spec §13 item 9) | epoch rotation — `vault` |
| `vaults.cache_policy` | the offline-cache policy (item 11) | policy enforcement — a higher layer |
| `membership_manifests` (PK `vault_id,key_epoch`) | a signed membership manifest per epoch | signature/composition — `vault` |
| `membership_grants` (PK `vault_id,member_pubkey,key_epoch`) | a wrapped VK + role for a member | signature/right to issue — `vault` |
| `pinned_member_keys` (PK `account_id`) | anti-spoof pinning of the member pubkey (item 12) | the decision to change a key — a higher layer |
| `audit_log` (append-only, autoincrement `seq`) | signed audit events | signature — a higher layer; there is **no** update/delete here |
| `sync_state` (`k`→`v`) | sync cursor / anti-rollback (item 2) | cursor monotonicity — `sync` |
| `vault_epoch_floor` (PK `vault_id`) | the minimum allowed epoch (anti-rollback, item 2) | forbidding downgrades — `vault`/`sync` |
| `cert_meta` (PK `vault_id,item_id`) | ⏳ **seam** for a CA orchestrator (item 15): certificate metadata | no CRUD logic for now |

`cert_meta` is only an extension point: the table is created, but there are no CRUD methods or logic at
this layer (the CA implementation is ⏳ LATER, outside this repository).

## What is not here

Network sync (there is no server), VK/sharing/content encryption and any
crypto verification (the `vault` layer). VK rotation, grant issuance/verification, CA logic
(⏳ LATER). `#![forbid(unsafe_code)]`.
