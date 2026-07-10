<!--
Thanks for contributing to UniSSH! Please fill this out so review is fast.
Security fix? Do NOT describe the vulnerability in a public PR — coordinate
privately first via uni@goduni.me (see SECURITY.md).
-->

## Summary

<!-- What does this PR do, and why? Keep it focused on one component / one concern. -->

## Linked issue

<!-- e.g. "Closes #123" / "Refs #123". If there's no issue, briefly say why. -->

Closes #

## Type of change

<!-- Mark all that apply with an "x". -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior/format/protocol)
- [ ] Docs only
- [ ] Build / CI / deps / tooling
- [ ] Refactor (no functional change)

## Checklist

<!-- See CONTRIBUTING.md. All applicable boxes should be checked before review. -->

- [ ] `cargo fmt --all --check` passes (or `just lint`).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes (or `just lint`).
- [ ] `cargo test --workspace` passes. <!-- ssh-transport/ffi integration tests need `sshd` + `ssh-keygen` on PATH. -->
- [ ] If I touched the admin panel, `just build-ui` still builds the wasm bundle + SPA.
- [ ] Changes stay **within one component's boundary**.
- [ ] **No core logic is duplicated** — crypto, blob/wire formats, storage, SSH, and the agent live only in `rust-core`; other components call into it.
- [ ] **No plaintext private keys cross the core↔UI/FFI boundary** (private key material never leaves the core's in-memory agent).
- [ ] Docs updated where relevant (README / component READMEs / `website/`).
- [ ] I agree my contribution is licensed under the project's dual **MIT OR Apache-2.0** license (inbound = outbound, per Apache-2.0 §5).

## Notes for reviewers

<!-- Anything that helps review: design trade-offs, things you're unsure about, screenshots, manual testing done. -->
