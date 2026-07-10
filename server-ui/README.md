# UniSSH Admin — server administration web panel

A production SPA for the self-hosted **zero-knowledge** UniSSH control plane. It implements
the design mockup (16 screens) and connects to the **live** server API. Styled consistently
with `unissh-client` (a port of the design tokens in `client/src/theme`).

**Stack:** React 18 · Vite · TypeScript · Zustand · i18next (ru/en) · real
crypto via wasm from `rust-core` (`crypto-wasm/`).
## Build and run

```bash
# 1) build the wasm crypto (needs rustup + wasm-pack; see below)
npm run build:wasm          # → crypto-wasm/pkg/

# 2) dev server
npm install
npm run dev                 # http://localhost:5180

# 3) prod build
npm run build               # tsc --noEmit && vite build → dist/
npm run preview
```

**wasm toolchain (one-time):**
```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```
`crypto-wasm/` — a `wasm-bindgen` crate on top of `rust-core/crates/crypto`. It
**does not pull in** `keychain`/`vault` (they depend on `unissh-storage` → rusqlite/sqlcipher,
which does not compile to wasm), and instead **vendors** the storage-free keyset crypto logic 1-to-1, so
signatures are **byte-compatible** with the real clients (domains `unissh-server-auth-v1`,
`unissh-registration-v1`). If `pkg/` is not built, the panel still works, but keyset operations
(unlock, bootstrap, rotation) show "wasm not loaded".

## Access model (two tiers, as on the server)

1. **Ops** — the static `X-UniSSH-Ops-Token` token from the server config (`[ops] token`).
   Entered on the login screen. Grants cross-tenant `/v1/ops/*` (tenants, overview, seq-bump).
2. **Admin keyset** — a per-tenant Bearer. Flow: import `.keyset` + password (+ Secret Key)
   → `unlock` in the browser (key in memory only) → `auth/challenge` → sign (wasm) →
   `auth/verify`. Opens all of `/v1/admin/*` and crypto actions. **Lock** wipes the key.

Crypto sections are behind `LockGate` until unlocked. Dangerous actions go through `ConfirmDialog`
(for suspend/seq-bump — re-entering the identifier). There is no read-only role (there isn't one on the server either).

## Deploy

The `dist/` artifact is served behind a reverse proxy (mind the server's `trust_proxy`/TLS modes)
or, optionally, from a dedicated static route on the server. By default the panel talks to the same
origin; the instance address is configured on the login screen and in settings.

## Structure

```
src/
  api/         typed client (headers/idempotency/error envelope), auth-service
  crypto/      CryptoProvider (seam) + wasm-provider (real crypto)
  store/       Zustand: session(ops/keyset), tenant, prefs, ui, meta
  theme/       token port + ThemeProvider (CSS variables, dark/light × 5 accents)
  ui/          primitives, DataTable, overlays (Drawer/Modal/ConfirmDialog/LockGate/Toaster)
  shell/       Win chrome: Titlebar, Sidebar (TenantSwitcher+nav), SettingsPanel
  access/      OpsLogin, KeysetModal, BootstrapModal, InviteModal
  screens/     16 screens (Instance / Identity / Access / Data)
  i18n/        ru/en
crypto-wasm/   Rust → wasm crate (crypto)
```
