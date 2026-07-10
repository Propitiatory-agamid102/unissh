---
title: Server configuration
description: The layered configuration for the UniSSH server — the config.toml sections, environment-variable overrides, the TLS strategy, and the bootstrap/ops tokens.
---

The UniSSH server is configured in layers: **defaults → `config.toml` → environment**. Environment keys use the form `UNISSH__SECTION__KEY=...` (double-underscore nesting). Secrets (TLS key, Postgres URL, bootstrap/ops tokens) should come from the environment or Docker secrets, never the committed file.

Start from the shipped template:

```bash
cp config.example.toml config.toml
```

## Sections

### `[server]`

```toml
[server]
bind = "0.0.0.0:8443"
tls_cert = "/secrets/cert.pem"   # in-process TLS 1.3 (rustls)
tls_key  = "/secrets/key.pem"
trust_proxy = false
acme = false
```

Set `tls_cert`/`tls_key` for in-process **rustls (TLS 1.3 only)**, or leave them empty and terminate TLS at a reverse proxy with `trust_proxy = true`.

:::caution[No in-process ACME]
`acme = true` is a **hard startup error** — the server never does ACME itself. Use a reverse proxy (Caddy/nginx) or supply `tls_cert` + `tls_key`. The recommended [Docker Compose deployment](../deploy/) terminates TLS in Caddy and runs the server as plain HTTP behind it with `trust_proxy = true`.
:::

### `[db]`

```toml
[db]
backend = "sqlite"               # "sqlite" | "postgres"
url = "/app/data/unissh.db"      # sqlite: file path (or ":memory:")
                                 # postgres: postgres://user:pass@host/db
max_connections = 16
```

### `[limits]`

Request and object bounds, plus a per-IP rate limit.

```toml
[limits]
max_body_bytes = 16777216        # 16 MiB
max_object_bytes = 1048576       # 1 MiB
max_objects_per_push = 1000
delta_page_size = 500
delta_max_page_size = 1000
rate_limit_per_ip_rps = 20
rate_limit_burst = 40
```

### `[sync]`

```toml
[sync]
freshness_window_seconds = 30    # window for online-only live-grants
validate_signatures = true       # defense-in-depth record-signature checks
min_instance_generation = 0      # anti-rollback floor (Σ next_seq); 0 = off
```

- **`validate_signatures`** (on by default) re-verifies each Vault/Item/Manifest/Grant record's Ed25519 signature on write, byte-exact with the core, dropping forged/tampered objects early. This is **defense-in-depth, not the security boundary** — the client still re-verifies on read.
- **`min_instance_generation`** is an **operator-anchored, out-of-band** floor for the sum of per-tenant sequences. The server **refuses to boot** if a restored snapshot is below it, closing the new-client/TOFU rollback gap. Anchor this value outside the database. See [Backups & anti-rollback restore](../backups/) and the [sync model](../../architecture/sync-model/).

### `[session]`

Token and lifecycle TTLs (seconds):

```toml
[session]
access_ttl_seconds = 900
refresh_ttl_seconds = 2592000
nonce_ttl_seconds = 120
invite_default_ttl_seconds = 86400
relay_ttl_seconds = 120
janitor_interval_seconds = 300
idempotency_ttl_seconds = 86400
```

### `[obs]`

```toml
[obs]
log_format = "json"              # "json" | "text"
otel_endpoint = ""               # OTLP export is NOT compiled in: a value here
                                 # only warns at startup. Metrics: /metrics.
metrics_bind = "127.0.0.1:9090"
```

### `[bootstrap]`

Controls who may create the **first** account of a tenant.

```toml
[bootstrap]
token = ""                       # base64; set via UNISSH__BOOTSTRAP__TOKEN
allow_open = false               # empty token + allow_open=false → bootstrap closed
default_tier = "personal"        # "personal" | "org"
```

### `[ops]`

The cross-tenant operator surface (`/v1/ops/*`, header `X-UniSSH-Ops-Token`):

```toml
[ops]
token = ""                       # empty → ops surface DISABLED
                                 # set via UNISSH__OPS__TOKEN
```

This is **server-trusted infrastructure access** (tenants / suspend / `seq-bump`), **not** a keyset and never decryption. The [admin panel](../../components/server-ui/) uses it as its first access tier.

## Environment overrides

Any key maps to an environment variable by uppercasing and joining with double underscores:

```bash
UNISSH__SERVER__BIND=0.0.0.0:8443
UNISSH__SERVER__TRUST_PROXY=true
UNISSH__DB__BACKEND=postgres
UNISSH__DB__URL=postgres://unissh:secret@postgres:5432/unissh
UNISSH__BOOTSTRAP__TOKEN=$(openssl rand -hex 32)
UNISSH__OPS__TOKEN=$(openssl rand -hex 32)
```

Generate strong tokens with `openssl rand -hex 32`. In the Compose stack these live in a gitignored `.env`; nothing secret is baked into images. See [Docker Compose deployment](../deploy/).
