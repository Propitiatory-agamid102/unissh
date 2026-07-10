//! The frozen pre-agility AEAD codec (the format before round 2: the blob header is NOT
//! bound to the AAD) and its incompatibility with the current scheme.
//!
//! `current_and_pre_agility_are_incompatible` is the "canary" that was missing
//! in round 2: binding the header into the AAD changed the ciphertext authentication, i.e.
//! this is a FORMAT change, not just an internal detail. Had such a test been on the
//! keyset path — round 2 would have caught the lockout at commit time.

use unissh_crypto::{
    aead_decrypt, aead_decrypt_pre_agility, aead_encrypt, aead_encrypt_pre_agility, unwrap_key,
    unwrap_key_pre_agility, wrap_key, wrap_key_pre_agility, AssociatedData, SymmetricKey,
};

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes([0x42u8; 32])
}
fn aad() -> AssociatedData {
    AssociatedData::new(b"vault".to_vec(), b"item".to_vec(), 7)
}

#[test]
fn pre_agility_roundtrips() {
    let k = key();
    let blob = aead_encrypt_pre_agility(&k, b"secret payload", &aad()).unwrap();
    assert_eq!(
        aead_decrypt_pre_agility(&k, &blob, &aad()).unwrap(),
        b"secret payload"
    );
}

#[test]
fn current_and_pre_agility_are_incompatible() {
    let k = key();
    let current = aead_encrypt(&k, b"x", &aad()).unwrap();
    let legacy = aead_encrypt_pre_agility(&k, b"x", &aad()).unwrap();
    // The current reader does not open a legacy blob and vice versa: the AAD differs by
    // the 3-byte header (round-2 crypto-agility binding).
    assert!(aead_decrypt(&k, &legacy, &aad()).is_err());
    assert!(aead_decrypt_pre_agility(&k, &current, &aad()).is_err());
}

#[test]
fn pre_agility_rejects_wrong_aad() {
    let k = key();
    let blob = aead_encrypt_pre_agility(&k, b"x", &aad()).unwrap();
    let other = AssociatedData::new(b"vault".to_vec(), b"item".to_vec(), 8);
    assert!(aead_decrypt_pre_agility(&k, &blob, &other).is_err());
}

#[test]
fn keywrap_pre_agility_roundtrips() {
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    let k = SymmetricKey::from_bytes([0x66u8; 32]);
    let blob = wrap_key_pre_agility(&kek, &k, b"item-1").unwrap();
    let got = unwrap_key_pre_agility(&kek, &blob, b"item-1").unwrap();
    assert_eq!(got.expose_bytes(), k.expose_bytes());
}

#[test]
fn keywrap_current_and_pre_agility_incompatible() {
    // Canary for keywrap: round 2 added the KEYWRAP_DOMAIN domain tag and header
    // binding — this is a change to the wrapped-key format. The current unwrap does not open
    // a pre-round-2 wrapper and vice versa.
    let kek = SymmetricKey::from_bytes([0x55u8; 32]);
    let k = SymmetricKey::from_bytes([0x66u8; 32]);
    let current = wrap_key(&kek, &k, b"item-1").unwrap();
    let legacy = wrap_key_pre_agility(&kek, &k, b"item-1").unwrap();
    assert!(unwrap_key(&kek, &legacy, b"item-1").is_err());
    assert!(unwrap_key_pre_agility(&kek, &current, b"item-1").is_err());
}
