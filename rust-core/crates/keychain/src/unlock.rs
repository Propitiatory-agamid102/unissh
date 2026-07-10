//! Unlock Key derivation: `combine(Argon2id(password), Secret Key)`.
//!
//! The Unlock Key is a 256-bit symmetric key that encrypts the personal keyset.
//! The combining is done via HKDF-SHA256 (extract+expand), with domain separation.
//!
//! The passwordless mode (SSO + trusted devices, spec 5.1/12) is laid out as an
//! extension point: when `argon_key = None` the root becomes the Secret Key
//! (+ in the future a device secret from the Secure Enclave, the `device_secret`
//! parameter). The biometrics themselves are not implemented here — that is the
//! platform layer of the UI project.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use unissh_crypto::SymmetricKey;

use crate::secret_key::SecretKey;

/// HKDF salt (domain separation of the scheme).
const UNLOCK_HKDF_SALT: &[u8] = b"unissh-unlock-salt-v1";
/// HKDF `info` (binding to the key's purpose).
const UNLOCK_HKDF_INFO: &[u8] = b"unissh-unlock-key-v1";

/// Derives the Unlock Key from the (optional) Argon2id key, the Secret Key and
/// the (optional, for the future) device secret.
///
/// IKM = `argon_key? || secret_key || device_secret?`. The order and the domain
/// labels are fixed — they cannot change without bumping the keyset format version.
pub(crate) fn derive_unlock_key(
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
    device_secret: Option<&[u8]>,
) -> SymmetricKey {
    // We keep IKM and OKM in Zeroizing — they are zeroized even during stack unwinding.
    // Each component is length-framed: `present:u8 || len:u32be || data`. Without
    // framing, different input triples with the same concatenation would yield ONE
    // Unlock Key (ambiguous IKM) — critical before enabling the device_secret mode.
    fn push_field(ikm: &mut Vec<u8>, present: bool, data: &[u8]) {
        ikm.push(present as u8);
        ikm.extend_from_slice(&(data.len() as u32).to_be_bytes());
        ikm.extend_from_slice(data);
    }
    let mut ikm = Zeroizing::new(Vec::new());
    match argon_key {
        Some(ak) => push_field(&mut ikm, true, ak.expose_bytes()),
        None => push_field(&mut ikm, false, &[]),
    }
    push_field(&mut ikm, true, secret_key.expose_bytes());
    match device_secret {
        Some(ds) => push_field(&mut ikm, true, ds),
        None => push_field(&mut ikm, false, &[]),
    }

    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(UNLOCK_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    SymmetricKey::from_bytes(*okm)
}

/// **FROZEN. Pre-round-2 ("pre-crypto-agility") Unlock Key derivation.** IKM is a
/// RAW concatenation without length-framing: `argon_key? || secret_key || device_secret?`.
/// The salt/`info` are the same as in the current [`derive_unlock_key`] — the ONLY
/// difference is the absence of framing.
///
/// Its sole purpose is to open a keyset created before round 2, in
/// `migrate-on-open` (the keyset is migrated to the current scheme right after a
/// successful unlock). It cannot change: the bytes are pinned by a golden vector in
/// `tests/`. See `SECURITY.md`, the "On-disk format changes" section.
pub(crate) fn derive_unlock_key_legacy_v1(
    argon_key: Option<&SymmetricKey>,
    secret_key: &SecretKey,
    device_secret: Option<&[u8]>,
) -> SymmetricKey {
    let mut ikm = Zeroizing::new(Vec::new());
    if let Some(ak) = argon_key {
        ikm.extend_from_slice(ak.expose_bytes());
    }
    ikm.extend_from_slice(secret_key.expose_bytes());
    if let Some(ds) = device_secret {
        ikm.extend_from_slice(ds);
    }

    let hk = Hkdf::<Sha256>::new(Some(UNLOCK_HKDF_SALT), ikm.as_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(UNLOCK_HKDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    SymmetricKey::from_bytes(*okm)
}
