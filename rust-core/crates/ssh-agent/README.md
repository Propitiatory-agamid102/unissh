# unissh-ssh-agent

Embedded **in-memory** SSH agent for UniSSH (spec 10.1). NOT the system ssh-agent:
private keys live only inside the core process.

**Key types:** Ed25519, ECDSA (p256/p384/p521) — fully; RSA — import +
public key (RSA signing deferred due to pre-release `ssh-key`↔`rsa`, see the test
`rsa_signing_pending`). Signing goes through `ssh-key` (a correct SSH format per algorithm).
**User certificates** are supported (`attach_certificate`/`certificate`).

## Key flow

```text
vault (item, ciphertext) ──vault::get_item──> OpenSSH private key (in memory)
        └─add_ed25519_from_item──> agent: seed under mlock, zeroize on removal
                                    sign(challenge) ──> Ed25519 signature
```

- The private key is an ordinary vault item. It is decrypted by the `vault` layer
  and handed to the agent **only for the moment of use**.
- Inside the agent the secret (a 32-byte Ed25519 seed) sits in **`mlock`-ed**
  memory (don't leak into swap) and is **zeroized** on removal/Drop. The signing key
  is reconstructed from the seed only for the duration of signing and is zeroized
  right away.
- A plaintext key is **never written to disk**. `generate_ed25519_openssh()`
  returns the private key as `Zeroizing<String>` — it is stored encrypted in the vault.

## API

```rust
use unissh_ssh_agent::{generate_ed25519_openssh, InMemoryAgent};

let (private_pem, public) = generate_ed25519_openssh()?;   // private_pem → into the vault (encrypted)
let mut agent = InMemoryAgent::new();
agent.add_ed25519_from_item(b"id_ed25519".to_vec(), &decrypted_item)?;
let sig = agent.sign(b"id_ed25519", challenge)?;            // AgentSignature { algorithm, signature }
let pubkey = agent.public_key(b"id_ed25519");              // ssh_key::PublicKey
agent.remove(b"id_ed25519");
```

For authentication in russh: `reconstruct_private_key(id)` returns a transient
`ssh_key::PrivateKey` (zeroized on Drop; not `mlock`-ed — use it and release it
immediately).

## mlock — best-effort

In environments without the right to lock memory (no `CAP_IPC_LOCK`, `RLIMIT_MEMLOCK`
exceeded, non-Unix) `mlock` may fail — in that case the buffer is still
used and **zeroized**, but not locked. Zeroization is always performed.

## Out of scope

The SSH transport/connect itself is the `ssh-transport` crate. The system agent and
**agent forwarding** are not implemented (spec 10.2, ProxyJump instead of forwarding).
In Milestone 1 — Ed25519 only. A single `unsafe` module (`mlock`/`munlock`),
`#![deny(unsafe_op_in_unsafe_fn)]`.
