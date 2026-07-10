# Client integration guide — accounts, devices, admins

How the identity model works and the flows a client app implements against this server.

## Identity model (the mental model)

```
tenant ─┬─ account "Alice" ── canonical keyset (ed25519 = MEMBER-ID, x25519)
        │     ├─ device A (laptop)   ┐ share the same keyset
        │     └─ device B (phone)    ┘ (one identity, many devices)
        ├─ account "John"  ── keyset …
        └─ account "Bob"   ── keyset …
```

- An **account = one keyset identity**. Its **Ed25519 public key is the canonical
  member-id** — the thing vault grants and membership are keyed on. The server holds
  only the two **public** keys; the private keyset never leaves the device.
- **Devices of an account share that keyset** (so granting "Alice" once works on all
  his devices). Each device has its own `device_id` for sessions/revocation.
- **Human identifiers** live on the account: `display_name` ("Alice Smith") and a
  unique `handle` ("vasya"). ⚠️ **These are server-visible metadata** (like the member
  set already is). For privacy-sensitive deployments, put a pseudonym, not real PII.

There are **two distinct "admin" concepts** — keep them separate in the UI:
- **Instance-admin** (`is_admin` on the account) — *server-trusted* authority for
  invites, audit, device-revoke, and publishing grants. Set via `/v1/admin/set`.
- **Vault role** (viewer/editor/**admin**) — *cryptographic*, lives in the signed
  manifest+grant. Controls who can decrypt/write a vault. Set via `/v1/grants/publish`.

## Flow 1 — first device (create the account)

1. Client generates the keyset locally (`keychain::create_account`) and a Secret Key.
2. Build the registration payload + `unissh-registration-v1` signature.
3. Either **bootstrap** (first account of the tenant → instance-admin) or **register**
   with an invite token:
   ```http
   POST /v1/bootstrap          (or /v1/register with "invite_token")
   { "registration_payload": "...", "registration_signature": "...",
     "tier": "org", "display_name": "Alice", "handle": "vasya" }
   → 201 { "account_id", "device_id", "role" }
   ```
4. Authenticate to get a session:
   ```http
   POST /v1/auth/challenge { account_id, device_id, key_id } → ServerAuthChallenge
   # sign challenge.canonical with the keyset → signature
   POST /v1/auth/verify { challenge, signature } → { access_token, refresh_token, … }
   ```

## Flow 2 — add another device (shared keyset)

1. On the **existing** (authenticated) device:
   ```http
   POST /v1/devices/add          (Bearer)
   → 201 { "device_id" }         # a new device_id under the same account
   ```
2. Transfer the keyset to the **new** device out-of-band:
   - **Path B (recommended):** PAKE relay (`/v1/relay/*`) — device-to-device with an
     OOB code; the new device receives the sealed keyset. Pass it the `device_id` too.
   - **Path A:** the new device pulls the `EncryptedKeyset` (`GET /v1/keyset`) and
     unlocks it with the Secret Key from the Emergency Kit.
3. The new device authenticates with that `device_id`, signing the challenge with the
   **shared keyset**. It now has the same member-id → **all of the account's vault
   grants already apply**. No re-granting.

Revoke a single device with `POST /v1/session/device-revoke { device_id }` — kills its
sessions without touching siblings.

## Flow 3 — admin: see who's who, manage the team

```http
GET /v1/accounts              (Bearer-admin)
→ { "accounts": [
     { "account_id", "display_name": "Alice", "handle": "vasya",
       "is_admin": true, "member_pubkey": "<b64 ed25519>", "status": "active",
       "device_count": 2 }, … ] }
```
Use `member_pubkey` when you build a manifest/grant for someone (that's their member-id).

- **Make/unmake an instance-admin** (server-trusted powers):
  ```http
  POST /v1/admin/set { "account_id": "...", "is_admin": true }   (Bearer-admin)
  ```
  Guards: the genesis admin can't be demoted, and you can't remove the last admin.
  Shortcut: issue an invite with `"role":"admin"` → the registered account is
  instance-admin immediately.
- **Give vault access / make a vault-admin** (cryptographic): build a new-epoch
  `manifest` listing the member with their role + a per-member `grant` (VK wrapped to
  their x25519), sign, and:
  ```http
  POST /v1/grants/publish { manifest, grants:[…], new_epoch, revoke_epoch? }
  ```
- **Update your own profile:** `POST /v1/account/profile { display_name?, handle? }`.

## Endpoint quick-reference (new in this iteration)

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/devices/add` | Bearer | add a device under the caller's account (shared keyset) |
| `GET /v1/accounts` | Bearer-admin | list accounts (handle, display_name, is_admin, member_pubkey, device_count) |
| `POST /v1/admin/set` | Bearer-admin | promote/demote instance-admin (anti-lockout) |
| `POST /v1/account/profile` | Bearer | set your own display_name / handle |

`bootstrap`/`register` now also accept optional `display_name` and `handle`.
