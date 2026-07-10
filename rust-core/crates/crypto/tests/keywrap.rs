//! Symmetric wrapping of a key by a key (KEK).

use unissh_crypto::{unwrap_key, wrap_key, SymmetricKey};

#[test]
fn roundtrip() {
    let kek = SymmetricKey::generate();
    let key = SymmetricKey::generate();
    let blob = wrap_key(&kek, &key, b"owner-1").unwrap();
    let got = unwrap_key(&kek, &blob, b"owner-1").unwrap();
    assert_eq!(got.expose_bytes(), key.expose_bytes());
}

#[test]
fn empty_aad_roundtrip() {
    let kek = SymmetricKey::generate();
    let key = SymmetricKey::generate();
    let blob = wrap_key(&kek, &key, b"").unwrap();
    let got = unwrap_key(&kek, &blob, b"").unwrap();
    assert_eq!(got.expose_bytes(), key.expose_bytes());
}

#[test]
fn wrong_kek_fails() {
    let kek = SymmetricKey::generate();
    let other = SymmetricKey::generate();
    let key = SymmetricKey::generate();
    let blob = wrap_key(&kek, &key, b"a").unwrap();
    assert!(unwrap_key(&other, &blob, b"a").is_err());
}

#[test]
fn wrong_aad_fails() {
    let kek = SymmetricKey::generate();
    let key = SymmetricKey::generate();
    let blob = wrap_key(&kek, &key, b"a").unwrap();
    assert!(unwrap_key(&kek, &blob, b"b").is_err());
}
