---
title: Admin panel (server-ui)
description: The UniSSH self-hosted admin panel — a React SPA that does real cryptography in the browser, with a two-tier access model (ops token plus admin keyset).
---

`server-ui` is the production web admin panel for a self-hosted UniSSH **zero-knowledge** control plane. It is a single-page app that connects to a **live** server API and shares its visual language with the desktop client (it ports the client's design tokens).

**Stack:** React 18 · Vite · TypeScript · Zustand · i18next (ru/en) · **real cryptography via WebAssembly** built from the core.

## Real crypto in the browser

Keyset operations in the panel use genuine cryptography, not a re-implementation. A `crypto-wasm` crate — a `wasm-bindgen` wrapper over `rust-core/crates/crypto` — provides them.

It deliberately **does not pull in** `keychain`/`vault` (those depend on `storage` → rusqlite/SQLCipher, which does not compile to wasm). Instead it **vendors the storage-free keyset crypto 1:1**, so the panel's signatures are **byte-compatible** with real clients (domains `unissh-server-auth-v1`, `unissh-registration-v1`).

:::caution
If `crypto-wasm/pkg/` is not built, the panel still loads, but keyset operations (unlock, bootstrap, rotation) report "wasm not loaded". Build it with `npm run build:wasm` — see [Install & prerequisites](../../overview/install/).
:::

## Two-tier access (mirroring the server)

The panel has exactly two ways in, matching the server's two authorities (see [Server & API surface](../server/)):

1. **Ops** — a static token (`X-UniSSH-Ops-Token`) from the server config (`[ops] token`), entered on the login screen. It grants cross-tenant `/v1/ops/*` (tenants, overview, `seq-bump`). This is **server-trusted infrastructure access**, not a keyset.
2. **Admin keyset** — a per-tenant Bearer credential. The flow: import a `.keyset` + password (+ Secret Key) → **unlock in the browser** (the key stays in memory only) → `auth/challenge` → sign (via wasm) → `auth/verify`. This opens all `/v1/admin/*` routes and the cryptographic actions. **Lock** wipes the key.

Cryptographic sections sit behind a `LockGate` until unlocked. Dangerous actions go through a confirmation dialog (for suspend / `seq-bump`, you re-type the identifier). There is no read-only role — the server does not have one.

## Layout

```
src/
  api/         typed client (headers/idempotency/error envelope), auth-service
  crypto/      CryptoProvider (seam) + wasm-provider (real crypto)
  store/       Zustand: session (ops/keyset), tenant, prefs, ui, meta
  theme/       ported tokens + ThemeProvider (CSS vars, dark/light × 5 accents)
  ui/          primitives, DataTable, overlays (Drawer/Modal/ConfirmDialog/LockGate/Toaster)
  shell/       window chrome: Titlebar, Sidebar (TenantSwitcher + nav), SettingsPanel
  access/      OpsLogin, KeysetModal, BootstrapModal, InviteModal
  screens/     16 screens (Instance / Identity / Access / Data)
  i18n/        ru/en
crypto-wasm/   Rust → wasm crate (crypto)
```

The 16 screens cover instance operations (overview, devices, sessions, config, migrations), identity (accounts, invites, keysets), access (vaults, grants), and data (objects, audit) — all driven by the server's [admin/ops read-projections](../server/), which expose only **open metadata** and never ciphertext.

## Build and deploy

```bash
npm run build:wasm          # → crypto-wasm/pkg/
npm install
npm run dev                 # http://localhost:5180
npm run build               # tsc --noEmit && vite build → dist/
npm run preview
```

The `dist/` artifact is served behind a reverse proxy (respect the server's `trust_proxy`/TLS mode) or, optionally, from a static route on the server itself. By default the panel talks to the **same origin**; the instance address is configurable on the login screen and in settings.

In the recommended Docker Compose deployment, the SPA is served **same-origin** by Caddy, so its API client uses a relative base, CORS stays off, and the only CSP relaxation needed is `script-src 'self' 'wasm-unsafe-eval'` for the wasm module. See [Docker Compose deployment](../../operations/deploy/).
