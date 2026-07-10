---
title: Security & zero-knowledge model
description: The UniSSH threat model, what a server instance can and cannot see, and the honest limits of zero-knowledge access control.
---

UniSSH's core security property is **zero-knowledge (end-to-end encryption)**: a server instance is an untrusted ciphertext store. It routes blobs and applies policy, but never holds anything in the clear. This page states the threat model, then is deliberately honest about what that does — and does not — buy you.

## Threat model

In decreasing order of importance:

1. **Backend compromise / an honest-but-curious instance operator.** A database dump yields only ciphertext. This is what zero-knowledge addresses.
2. **A malicious insider at the operator, or legal compulsion.** The operator physically cannot hand over what it cannot decrypt.
3. **A malicious team member** with legitimate vault access. Crypto does not help here; least-privilege and audit do.
4. **A compromised client device.** Auto-lock, Secure Enclave, biometrics, and minimal plaintext lifetime.
5. **An active MITM during public-key distribution** (arises when sharing — see below).

:::tip[The base property, stated plainly]
The server is **honest-but-curious**. A malicious server can **deny, withhold, or replay**, but it **cannot decrypt or mint access**.
:::

## What the server stores — and what it never sees

A UniSSH server is, by design, a store of opaque ciphertext plus open metadata. Confidentiality is cryptographic; access enforcement is server-trusted.

### Never visible to the server

Names and content, Vault Keys (VK), per-item keys, audit bodies, and private keys. The private keyset never leaves the device; the server holds only the **public** halves of each account's keyset.

### Metadata leaks by design

This is an accepted, documented tradeoff. The server can see:

- vault and item ids, versions, tombstones;
- author/member public keys, roles, `key_epoch`;
- `sync_target`, `cache_policy`, `server_seq`;
- the full **signed (unencrypted) manifest member-set** — who shares with whom;
- blob sizes and push/pull timings.

For privacy-sensitive deployments, the human labels on an account (`display_name`, `handle`) are also **server-visible metadata** — use a pseudonym, not real PII.

:::caution[Metadata is not content]
Content (including item **names**) is always encrypted. But the social graph (who-shares-with-whom), membership, sizes, and timings are visible to the instance operator by definition. This is documented to the user rather than hidden.
:::

## How confidentiality is enforced

Several cryptographic mechanisms make "untrusted store" a meaningful guarantee. The details and byte formats are in [Crypto & key hierarchy](../crypto-and-keys/); the essentials:

- **AEAD + associated data.** Every item is encrypted with its `vault_id + item_id + version` bound into the associated data, so the server cannot silently swap or reorder blobs — a misplaced blob fails AEAD authentication.
- **Anti-rollback via signed monotonic versions.** Each object change carries a monotonic version counter **signed by its author (Ed25519)**. A client detects a rolled-back version or a foreign signature. See [Sync & anti-rollback](../sync-model/).
- **Envelope encryption.** A vault's VK is wrapped under each member's public key (HPKE/X25519); the server only ever sees wrappers, never the VK.
- **Epoch-bound key wraps.** A VK wrapper is bound to `(vault_id, recipient, key_epoch)`, so the server cannot pass off an old wrapper as a current-epoch one.

## Two distinct "admin" concepts

Keep these separate — they answer different questions:

- **Instance-admin** — *server-trusted* authority for invites, audit, device-revoke, and publishing grants. Set via the server API; the genesis admin cannot be demoted and the last admin cannot be removed.
- **Vault role** (viewer / editor / **admin**) — *cryptographic*, living in the signed manifest + grant. It controls who can **decrypt and write** a vault.

A server-trusted instance-admin can manage the team; only a cryptographic vault-admin can actually grant the ability to decrypt a vault.

## Honest limitations (read this)

Access enforcement is server-trusted; **confidentiality is not**. The following are enforced honestly, not cryptographically:

- **Revocation does not retrieve already-synced plaintext.** It protects the future, not the past. The only revocation effective against a forked or untrusted client is **cryptographic VK rotation + an epoch floor** (client-side). The server's read-deny / write-deny are server-trusted: a malicious server can keep serving a revoked member — but they still cannot read new plaintext.
- **Live-grant expiry (`not_after`)** is unauthenticated server metadata — an availability-revoke under server trust, not cryptographic enforcement.
- **SSH-key offboarding requires host-side rotation.** Rotating the VK does not invalidate an exfiltrated private SSH key that still sits in a host's `authorized_keys` or a CA. Rotate it on the host.
- **Onboarding keyset-freshness gap (Path A).** A fresh onboarding device has no prior generation floor, so a malicious server could serve a stale generation (a trust-on-first-use gap). The server rejects downgrades best-effort; the real protection is the client's floor once established.
- **Whole-DB snapshot rollback.** Per-record version monotonicity catches lowering. Additionally an **instance generation** (the sum of per-tenant sequences) is checked at startup against an operator-anchored, out-of-band floor (`min_instance_generation`); the server refuses to boot below it, closing the new-client/TOFU gap.
- **Audit authenticity vs. integrity.** Client-signed entries are authentic (genesis-owner signature). The log is a server-side **hash chain**, and a verify endpoint detects any edit, reorder, or deletion. But a malicious operator can still refuse to serve the log wholesale, and server-observed entries are unsigned — their integrity in the recorded sequence is provable, their origin is not. See [Audit log & entry format](../../components/server-audit/).

## Recovery and the cost of zero-knowledge

There is **no "reset password via email"** for zero-knowledge vaults — that would nullify the property. Recovery is per-instance:

- On first device, the core generates a **Secret Key** and shows an **Emergency Kit** (printable). The Secret Key never goes to the server.
- A new device recovers via the Secret Key from the Kit, or via device-to-device confirmation (QR/code) from an existing device.
- **Lose every device and the Kit, and that instance's data is gone.** This is stated honestly at account creation.

An optional org/admin **escrow** mode (M-of-N, audited, opt-in, visible to every member) is a planned future capability; it is a deliberate, opt-in compromise and is not the default.

Continue to [Crypto & key hierarchy](../crypto-and-keys/) for the primitives, or [Sync & anti-rollback](../sync-model/) for how clients converge without trusting the server.
