# UniSSH threat model

This is the canonical, top-level threat model for UniSSH. It states what the
system protects, which adversaries it is designed against, the metadata that is
visible **by design**, and — just as importantly — what it does **not** protect.
It is deliberately honest: some properties are cryptographic, others are merely
**server-trusted**, and the difference is spelled out below.

This file promotes the model out of the docs subpage so reviewers find it at the
repo root. The deeper, primitive-level write-up (byte formats, key hierarchy) lives
in the
[zero-knowledge model docs](https://goduni.github.io/unissh/architecture/zero-knowledge-model/).
To report something that breaks these guarantees, see [`SECURITY.md`](SECURITY.md).

## What UniSSH protects

UniSSH's core property is **zero-knowledge (end-to-end encryption)**: a server
instance is an **untrusted ciphertext store**. It routes blobs and applies policy,
but never holds anything in the clear.

- **Zero-knowledge vaults.** All vault content is encrypted on the client before
  it leaves the device. The server stores ciphertext blobs plus open metadata and
  performs **no payload crypto** — it cannot decrypt vaults, mint access, or forge
  records.
- **Keys never cross the FFI / UI boundary.** The private keyset never leaves the
  device; the server holds only the **public** halves. The UI never receives
  plaintext private keys — the core won't hand them out. The only revealable
  secrets are user passwords/notes, strictly type-gated. Secrets are zeroized,
  private-key plaintext is never written to disk, and key pages are `mlock`'d where
  possible.
- **Signed, monotonic versions + associated-data binding.** Every item is
  encrypted with its `vault_id + item_id + version` bound into the AEAD associated
  data, so the server cannot silently swap or reorder blobs (a misplaced blob fails
  authentication). Each object change carries a monotonic version counter **signed
  by its author (Ed25519, `verify_strict`)**; a client detects a rolled-back
  version or a foreign signature. Vault keys are envelope-encrypted under each
  member's public key (HPKE/X25519) and bound to `(vault_id, recipient, key_epoch)`,
  so the server only ever sees wrappers and cannot pass off a stale wrapper as a
  current-epoch one. These same signed-version primitives underpin both sync and
  the local integrity audit (`verify_chain`).
- **Transport.** TLS 1.3 only — via the bundled Caddy, in-process rustls, or a
  reverse proxy you control. SSH traffic always goes **straight from your device to
  your hosts** and never tunnels through the sync server.
- **Honest-but-curious server, stated plainly.** A malicious server can **deny,
  withhold, delay, or replay** — but it **cannot decrypt, mint access, or forge
  records**.

UniSSH does **not** roll its own crypto: it builds on RustCrypto, `hpke`,
SQLCipher, and Argon2id, with Ed25519 for signatures.

## Adversaries considered

In decreasing order of importance:

1. **Backend compromise / an honest-but-curious instance operator.** A database
   dump yields only ciphertext. This is exactly what zero-knowledge addresses.
2. **A malicious insider at the operator, or legal compulsion.** The operator
   physically cannot hand over what it cannot decrypt.
3. **A malicious team member** with legitimate vault access. Cryptography does not
   help here — least-privilege (cryptographic vault roles: viewer/editor/admin) and
   audit do.
4. **A compromised client device.** Mitigated by auto-lock, OS keychain / Secure
   Enclave storage of the Secret Key, biometric unlock, and a minimal
   plaintext lifetime — but a fully compromised, unlocked device sees what its user
   sees.
5. **An active MITM during public-key distribution.** Arises when sharing /
   onboarding, where a member's public key is first learned (see the TOFU gap
   below).

## Metadata visible by design

A UniSSH server is, by definition, a store of opaque ciphertext **plus open
metadata**. Confidentiality is cryptographic; access enforcement is server-trusted.
The operator can see — and this is an accepted, documented trade-off:

- vault and item **ids**, **versions**, and **tombstones**;
- author / member **public keys**, **roles**, and `key_epoch`;
- `sync_target`, `cache_policy`, and `server_seq` (sequence numbers);
- the full **signed (unencrypted) member-set** manifest — the social graph of
  who shares with whom;
- **blob sizes** and **push/pull timings**.

For privacy-sensitive deployments, an account's human labels (`display_name`,
`handle`) are also server-visible metadata — **use a pseudonym, not real PII.**

The server **never** sees: item/vault **names** or **content**, Vault Keys (VK),
per-item keys, audit bodies, or private keys. Content — **including item names** —
is always encrypted. But membership, the social graph, sizes, and timings are
visible to the operator by definition; this is documented to the user rather than
hidden.

## Honest limitations / NOT protected

**Confidentiality is cryptographic; access enforcement is server-trusted.** The
following are enforced by the server's good behavior, **not** by cryptography —
overclaiming them would be dishonest:

- **Revocation is server-trusted and protects the future, not the past.**
  Revocation does not retrieve already-synced plaintext. The server's
  read-deny/write-deny can be ignored by a malicious server, which could keep
  serving a revoked member. The only revocation effective against a forked or
  untrusted client is **cryptographic VK rotation + a client-side epoch floor** —
  after which the revoked member still cannot read *new* plaintext.
- **Live-grant expiry (`not_after`) is unauthenticated server metadata** — an
  availability-revoke under server trust, not cryptographic enforcement.
- **SSH-key offboarding requires host-side rotation.** Rotating the VK does **not**
  invalidate an exfiltrated private SSH key still sitting in a host's
  `authorized_keys` or a CA. Rotate it on the host.
- **TOFU onboarding keyset-freshness gap.** A freshly onboarding device has no
  prior generation floor, so a malicious server could serve a **stale generation**
  — a trust-on-first-use gap. The server rejects downgrades best-effort; the real
  protection is the client's floor once it's established.
- **Whole-DB snapshot rollback is bounded, not eliminated.** Per-record version
  monotonicity catches lowering of any single object. Across the whole DB, an
  **instance generation** (the sum of per-tenant sequences) is checked at startup
  against an operator-anchored, out-of-band floor (`min_instance_generation`); the
  server refuses to boot below it. The client's trusted **anti-rollback cursor**
  (a last-seen `server_seq` held locally, never replicated back from the server)
  refuses any delta or reported cursor below what it has already seen. Together
  these bound a stale restore — but a restore *within* the bound can still
  resurrect a deleted item, which is why a full re-push is safe and expected.
- **Audit: integrity is provable, origin is not.** Client-signed entries are
  authentic (genesis-owner Ed25519 signature, verified with associated data
  `(vault_id, "__audit__", 0)`). The log is a server-side **hash chain**, and a
  verify endpoint detects any edit, reorder, or deletion. But a malicious operator
  can still refuse to serve the log wholesale, and server-observed entries are
  unsigned — their **integrity in the recorded sequence** is provable, their
  **origin** is not.

There is also **no "reset password via email"** for zero-knowledge vaults — that
would nullify the property. Lose every device **and** the Emergency Kit (Secret
Key), and that instance's data is gone. An optional, opt-in, audited M-of-N org
escrow is a planned future capability, not a default.

---

For the primitives and key hierarchy, see the
[zero-knowledge model docs](https://goduni.github.io/unissh/architecture/zero-knowledge-model/)
and [`rust-core/crates/sync/README.md`](rust-core/crates/sync/README.md) for the
verify-before-apply pipeline. To report a vulnerability, see
[`SECURITY.md`](SECURITY.md).
