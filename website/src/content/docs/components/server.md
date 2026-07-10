---
title: Server & API surface
description: The UniSSH zero-knowledge control plane — its stack, the /v1 API endpoint groups, the identity/account/device model, and how it is verified byte-compatible with the core.
---

The UniSSH server is a **self-hostable, zero-knowledge control plane**: an untrusted ciphertext store plus device/team sync, membership/sharing/revocation, and audit. **SSH traffic does not flow through the server** — it sees only encrypted blobs and open metadata. Think of it as a private, self-hosted sync backend ("self-hosted Termius").

## Stack

tokio · **axum 0.8** · **sqlx 0.9** (**SQLite** default, **Postgres** for scale) · rustls (**TLS 1.3**) · `ed25519-dalek` (`verify_strict`, the same library as the core) · figment (layered config) · tracing + **Prometheus** metrics.

By design the server performs **no payload crypto** — only TLS and Ed25519 signature verification for auth, registration, and (defense-in-depth) record validation.

## Identity, accounts, and devices

```
tenant ─┬─ account "Vasya"  ── canonical keyset (ed25519 = MEMBER-ID, x25519)
        │     ├─ device A (laptop)   ┐ share the same keyset
        │     └─ device B (phone)    ┘ (one identity, many devices)
        ├─ account "John"   ── keyset …
        └─ account "Igor"   ── keyset …
```

- An **account = one keyset identity.** Its **Ed25519 public key is the canonical member-id** — the thing vault grants and membership are keyed on. The server holds only the two **public** keys; the private keyset never leaves the device.
- **Devices of an account share that keyset** (so granting "Vasya" once works on all his devices). Each device has its own `device_id` for sessions and revocation.
- **Human identifiers** (`display_name`, `handle`) live on the account and are **server-visible metadata**. For privacy-sensitive deployments, use a pseudonym.

Keep the **two "admin" concepts** distinct:

- **Instance-admin** (`is_admin`) — *server-trusted* authority for invites, audit, device-revoke, and publishing grants. The genesis admin cannot be demoted; the last admin cannot be removed (anti-lockout).
- **Vault role** (viewer / editor / **admin**) — *cryptographic*, living in the signed manifest + grant; controls who can decrypt/write a vault.

The full client flows (first device, add a sibling device, admin team management) are in the repository's `server/CLIENT.md`.

## API surface (`/v1`, JSON over TLS)

All crypto blobs are base64 (STANDARD). `UniSSH-Tenant: <base64(tenant_id)>` is required on `/v1` routes (except bootstrap-time); `Authorization: Bearer` on private routes; mutating routes accept an `Idempotency-Key`.

### Identity / auth

`POST /v1/bootstrap`, `/v1/register`, `/v1/invite`, `/v1/invite/redeem`, `/v1/auth/challenge`, `/v1/auth/verify`, `/v1/session/{refresh,logout,device-revoke}`, `GET|PUT /v1/keyset`, and the device-to-device PAKE relay `/v1/relay/{open,msg1,msg2,msg3}` + `GET /v1/relay/poll`.

### Accounts / devices / admin

`POST /v1/devices/add` (a sibling device sharing the keyset), `GET /v1/accounts` (admin: handles, display names, member-ids, device counts), `POST /v1/admin/set` (instance-admin promote/demote), `POST /v1/account/profile`.

### Sync

`POST /v1/sync/push`, `GET /v1/sync/delta`, `GET /v1/sync/version`. These implement the server side of the core's untrusted-transport sync — see [Sync & anti-rollback](../../architecture/sync-model/).

### Vaults / policy

`POST /v1/vaults/claim`, `POST /v1/grants/publish` (publish a new-epoch manifest + per-member grants — membership, rotation, or revoke), `GET /v1/grants`.

### Audit

`POST /v1/audit`, `GET /v1/audit` (admin). The log is a server-side hash chain; `GET /v1/admin/audit/verify` recomputes it. Entry formats: [Audit log & entry format](../server-audit/).

### Admin / ops (for the admin panel)

A Bearer-admin, per-tenant read surface plus lifecycle controls, deliberately **suspended-gate-exempt** so a suspended tenant stays recoverable:

`GET /v1/admin/{overview,devices,sessions,invites,vaults,vault,objects,relay,keysets,config,migrations}` and `POST /v1/admin/{tenant/status,account/status,session/revoke,invite/revoke,seq-bump}`.

These are **read-projections of open metadata** plus lifecycle controls; they **never** expose ciphertext (object bytes, keyset bytes, or relay messages). `config` is read-only with secrets masked. Account-disable is enforced in the auth path (existing sessions stop) with genesis/last-admin anti-lockout.

### Service

`GET /healthz`, `/readyz`, `/metrics`, `/v1/version`.

:::note[Ops vs. admin]
Cross-tenant infrastructure operations (list tenants, suspend, `seq-bump`) sit on a separate `/v1/ops/*` surface gated by a static `X-UniSSH-Ops-Token`. That is server-trusted infrastructure access — **not** a keyset, and never decryption. See [Server configuration](../../operations/configuration/) and [Admin panel](../server-ui/).
:::

## Build, run, and verification

```bash
cargo build --release
cp config.example.toml config.toml
./target/release/unissh-server migrate --config config.toml   # also auto-applied on serve
./target/release/unissh-server --config config.toml
```

The server is **byte-compatible** with the Milestone-2 core: every wire format mirrors the core 1:1 and is mechanically verified. The test suite includes an **oracle** that implements the core's `SyncTransport` trait over HTTP and runs the real core `sync_pull` engine against a live server, asserting identical results to the reference in-memory transport plus verbatim byte round-trips. Codec and crypto are parity-gated against the actual `rust-core` source.

See also: [Server configuration](../../operations/configuration/), [Docker Compose deployment](../../operations/deploy/), and [Backups & anti-rollback restore](../../operations/backups/).

## License

MIT OR Apache-2.0.
