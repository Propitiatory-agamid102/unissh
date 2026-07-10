# unissh-sync

UniSSH client-side sync engine (server-tz §3, §9, §1.1). Part of the core; **there
is no real server/network here** — the server is modeled by the `SyncTransport` trait +
the in-memory mock `InMemoryTransport`, which acts as an **untrusted** stand-in.

## What it does
- `sync_pull(transport, storage, ctx)` — pulls the delta with `server_seq > cursor`,
  applies **verify-before-apply**, merges signed-version LWW, surfacing
  equal-version conflicts, and moves the trusted cursor forward only.
- `sync_push(transport, storage, target_tenant)` — collects the local objects and
  pushes ONLY the vaults bound to `target_tenant` (1:1 binding of a cloud vault to
  a server; local vaults and vaults bound to other servers are skipped).

## SyncObject (formats)
A tagged object (`Vault`/`Item`/`MembershipManifest`/`MembershipGrant`/
`Audit`/`Keyset`) carrying **already-encrypted/signed** blobs + open
metadata. Serialization is a hand-written length-prefixed byte codec
(`tag:u8 || length-prefixed fields`), without `serde`. Crypto stays in `vault`/
`crypto`/`keychain` — the engine only transports and verifies.

## Threat model: transport is UNTRUSTED
The engine does NOT trust `server_seq`, ordering, or content. Every object:
1. signature (`crypto`/`vault`) → otherwise REJECTED;
2. `key_epoch >= floor` (`storage.get_vault_epoch_floor`) → otherwise REJECTED;
3. author authority (the `vault` member model: `verify_record_authority` /
   `verify_chain_to_epoch`) → otherwise REJECTED;
4. keyset generation `>= floor` (`keychain`) → otherwise REJECTED;
5. only then the monotonic `storage.put_*` (LWW).

## Guarantees (never panics)
- stale/version rollback → SKIP (`skipped_stale`);
- equal version with different content → Conflict (local NOT overwritten);
- equivocating manifest@epoch (a different member-set of the same epoch, even validly
  signed) → Conflict, the trusted manifest NOT overwritten (anti-equivocation);
- forged/non-member object → REJECTED, not applied;
- `key_epoch`/generation below the floor → REJECTED;
- keyset: the generation floor (`keyset_gen_floor`) is NOT moved from
  the unauthenticated header of the keyset blob (see below) — otherwise tampering with
  the `generation` header bytes would poison the floor and lock the legitimate keyset;
- a transport that hands off/reports a cursor `< last-seen` → REJECTED
  (`TransportRollback` / `RejectReason::BelowCursor`);
- the trusted cursor (`sync:pull`/`sync:push` in `sync_state`) is monotonic.

## Keyset objects: only credentials move the floor (P6)
`EncryptedKeyset.generation` is the blob's header bytes, authenticated only
at `unlock_account` (they are part of the `wrapped_keyset` AAD). The sync engine does NOT raise
`keyset_gen_floor` from this field: it only discards a feed with a generation BELOW
the trusted floor (anti-rollback gate). The floor is raised exclusively on
the trusted unlock path (`unlock_account_checked` / password change) —
an untrusted transport cannot move it.

## Anti-rollback cursor (server-tz §1.1, §3.2)
The storage vault epoch floor (`vault_epoch_floor`) already exists (P2); this crate adds
the cursor engine: a trusted last-seen `server_seq` outside the server-replicated
stream, a check of `report_version >= cursor`, and a refusal to accept `server_seq <= cursor`.
The cursor is stored locally-to-the-instance in `sync_state` and is NOT replicated back
from the server. It advances **incrementally** in strict `server_seq` ASC after
each object is processed (applied/skip/conflict/reject-verify move the cursor;
below-cursor does not), so an interrupted delta neither loses progress nor skips
an unverified tail.

## What is not here (⏳ LATER / other crates)
- A real network/server (only the trait + mock).
- Content/VK decryption (no plaintext leaves).
- CRDT merge (v1 — signed-version LWW; CRDT — ⏳ LATER).
- The full audit format/scoping (a seam onto the `audit` crate, Milestone 2): in v1 audit is
  instance-level; the engine requires that the author be the trusted instance anchor
  (`genesis_owner`), and it verifies its Ed25519 signature over `entry_blob` through
  `crypto` with AAD `(vault_id, "__audit__", 0)`. Vault-scoped audit authority
  (the author as the vault's admin@epoch) and the exact signature domain will be defined by the `audit` crate.
- Per-object dirty-tracking in push (v1 sends everything; the server dedups by LWW).
