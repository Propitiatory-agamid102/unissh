# Audit `entry_blob` format (for UI rendering)

Reference for rendering `GET /v1/audit` entries in the admin panel. Resolves
handoff **P3.9**.

`GET /v1/audit?since_seq&limit` returns:

```json
{
  "entries": [
    {
      "seq": 42,
      "entry_blob": "<base64>",
      "signature": "<base64|null>",
      "author_pubkey": "<base64|null>",
      "recorded_at": 1700000000,
      "source": "server-observed"
    }
  ],
  "has_more": false,
  "next_since": 43
}
```

The shape of the **decoded** `entry_blob` depends entirely on `source`. Branch on
`source` first.

---

## 1. `source: "server-observed"`

`entry_blob` is **UTF-8 JSON** — `JSON.parse(atob(entry_blob))` yields an object.
The server writes these for lifecycle actions it performs itself; there is no
client signature, so `signature` and `author_pubkey` are `null`.

Every server-observed event has:

| Field   | Type             | Notes                                  |
|---------|------------------|----------------------------------------|
| `event` | string (enum)    | Discriminator — see table below.       |
| `ts`    | int (unix secs)  | Server clock at the time of the action. Equals `recorded_at`. |

Additional fields per `event`:

| `event`           | Extra fields                                  | Emitted when                                        |
|-------------------|-----------------------------------------------|-----------------------------------------------------|
| `bootstrap_admin` | `account_id`, `device_id`                     | First admin bootstrapped for a tenant.              |
| `login`           | `account_id`, `device_id`                     | `POST /v1/auth/verify` succeeds.                    |
| `logout`          | `account_id`, `device_id`                     | `POST /v1/session/logout`.                          |
| `device_add`      | `account_id`, `device_id`                     | A new device is registered to an account.           |
| `device_remove`   | `account_id`, `device_id`                     | `POST /v1/session/device-revoke`.                   |
| `keyset_publish`  | `account_id`, `device_id`                     | A keyset generation is published (`PUT /v1/keyset`).|
| `admin_grant`     | `account_id`                                  | `POST /v1/admin/set {is_admin:true}`.               |
| `admin_revoke`    | `account_id`                                  | `POST /v1/admin/set {is_admin:false}`.              |
| `account_disable` | `account_id`                                  | `POST /v1/admin/account/status {disabled:true}`.    |
| `account_enable`  | `account_id`                                  | `POST /v1/admin/account/status {disabled:false}`.   |
| `tenant_suspend`  | `by: "ops"` **only** when via the ops console | Tenant suspended (admin `/v1/admin/tenant/status` or ops `/v1/ops/tenant/status`). |
| `tenant_activate` | `by: "ops"` **only** when via the ops console | Tenant re-activated.                                |
| `tenant_rename`   | `by: "ops"`, `display_name` (string\|null)    | `POST /v1/ops/tenant/profile` set/cleared the tenant label. |
| `access_grant`    | `vault_id`, `new_epoch`, `revoke_epoch` (int\|null) | `POST /v1/grants/publish` (membership publish / rotation / revoke). The entry's top-level `vault_id` column is also set. |

`account_id`, `device_id`, `vault_id` values are **base64** (same encoding as the
rest of the API). Treat the `event` set as **open** — render unknown `event`
strings generically (show `event` + remaining keys) rather than failing.

Example decoded blob:

```json
{ "event": "login", "account_id": "Ym9i...", "device_id": "ZGV2...", "ts": 1700000000 }
```

---

## 2. `source: "client-signed"`

`entry_blob` is **opaque canonical bytes** produced and signed by the client
(rust-core), submitted via `POST /v1/audit` or sync push tag 5. The server stores
it verbatim and **does not parse it** — it only enforces that `author_pubkey`
equals the tenant's genesis owner and that `signature` verifies.

For these entries:

- `signature` and `author_pubkey` are **present** (non-null, base64).
- The internal structure of `entry_blob` is **not defined by the server**. A
  dedicated `audit` crate (rust-core, milestone 2) will fix the canonical
  domain/format; until then it is application-defined and may not be JSON.

**UI guidance:** do **not** assume JSON. Render client-signed entries from the
envelope metadata the server does expose — `seq`, `recorded_at`,
`author_pubkey`, "signed ✓" — and show `entry_blob` as hex/base64 (collapsible),
not as parsed fields. Attempting `JSON.parse` will throw for most client-signed
blobs.

---

## 3. Tamper-evidence (context)

Independent of `entry_blob` content, the whole log is a hash chain
(`prev_hash[n] = SHA-256(prev_hash[n-1] ‖ record_bytes(n))`, domain
`unissh-audit-chain-v1`). The UI verifies integrity via
`GET /v1/admin/audit/verify` → `{ok, count, broken_at, head_hash}` — it does
**not** need to recompute the chain itself, and `prev_hash` is not exposed on the
`/v1/audit` listing.

---

## Rendering decision tree (pseudocode)

```ts
const blob = atob(entry.entry_blob);
if (entry.source === "server-observed") {
  const ev = JSON.parse(blob);            // always valid JSON
  renderEvent(ev.event, ev);              // unknown ev.event → generic row
} else {
  // "client-signed": opaque, signed
  renderSigned({
    author: entry.author_pubkey,
    recordedAt: entry.recorded_at,
    rawHex: toHex(blob),                  // do NOT JSON.parse
  });
}
```
