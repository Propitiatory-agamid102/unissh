---
title: CI/CD & releases
description: The UniSSH GitHub Actions pipelines — core/server CI, the docs site deploy, and the desktop client build/release flow, plus the core release artifacts.
---

UniSSH ships three GitHub Actions workflows: continuous integration for the Rust workspace, the desktop client build/release, and this documentation site's deploy.

## Core & server CI (`ci.yml`)

Runs on every push to `main`, every pull request, and weekly on a schedule (to surface new advisories via cargo-deny). Three jobs:

- **`lint`** — `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`. The toolchain (channel 1.94 + rustfmt/clippy) comes from `rust-toolchain.toml`.
- **`test`** — `cargo test --workspace` inside a `rust:bookworm` **root container**. The sshd-backed integration tests are designed to run as root against a self-spawned `sshd`, so the container provides a privileged, reproducible environment; it installs `openssh-server`/`openssh-client` plus the OpenSSL headers and C toolchain for bundled SQLCipher.
- **`deny`** — `cargo-deny check advisories bans sources licenses`, reading `deny.toml` from the repo root (supply-chain gate).

## Release artifacts (core)

A `vX.Y.Z` tag on the core triggers a release that publishes:

- the **`unissh` CLI** binary for **Linux x86_64** and **macOS arm64**, and
- **`UniSSHCore.xcframework`** — the UniFFI bindings for the macOS UI.

Artifacts land on the project's GitHub Releases page. See [rust-core](../../components/rust-core/).

## Desktop client (`client.yml`)

One file carries two flows:

- **CI** — on pull requests and pushes to `main`: build the desktop bundles to validate they compile and bundle. No GitHub Release is created.
- **Release** — on a `v*` tag: build release bundles and attach them to a GitHub Release.

It builds on a matrix of `ubuntu-22.04` (pinned for webkit2gtk-4.1 availability and broad AppImage glibc compatibility → `.deb`/`.rpm`/`.AppImage`), `windows-latest` (`.msi` via WiX + NSIS `.exe`), and `macos-latest` (`.dmg`/`.app`). Node 22 + the repo-root pinned Rust toolchain are used; the client's path dependency on `../../rust-core/crates/ffi` resolves inside the single checkout (no cross-repo checkout, no PAT).

:::caution[Unsigned by design (privacy)]
The client builds ship **unsigned** — no Apple cert/notarization, no Windows code-signing. This is a deliberate privacy choice: no developer identity is attached.

- **macOS** (`.dmg`/`.app`): Gatekeeper will quarantine the app. After moving it to `/Applications`, run `xattr -dr com.apple.quarantine /Applications/UniSSH.app`.
- **Windows** (`.msi`/`.exe`): SmartScreen may warn — choose "More info" → "Run anyway".
- **Linux** (`.deb`/`.rpm`/`.AppImage`): unsigned.
:::

Mobile (iOS/Android) is intentionally **out of scope** for the workflow: there is no privacy-preserving unsigned distributable for those stores/runtimes.

## Documentation site (`docs.yml`)

This site deploys to **GitHub Pages** as a project page (`https://goduni.github.io/unissh/`). The workflow runs on pushes to `main` that touch `website/**` (or the workflow itself), and on manual dispatch:

- **build** — Astro build via `withastro/action@v3` (path `website`, Node 22).
- **deploy** — `actions/deploy-pages@v4` to the `github-pages` environment, with `pages: write` and `id-token: write` permissions and a single-concurrency `pages` group.

To build the site locally, see [Build from source](../build/) and the site's own `package.json` (`npm run build`).
