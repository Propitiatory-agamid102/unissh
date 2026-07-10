//! AEAD (XChaCha20-Poly1305) + associated data: round-trip and negative tests.

use unissh_crypto::{aead_decrypt, aead_encrypt, AssociatedData, CryptoError, SymmetricKey};

fn aad() -> AssociatedData {
    AssociatedData::new(b"vault-1".to_vec(), b"item-1".to_vec(), 1)
}

#[test]
fn roundtrip() {
    let key = SymmetricKey::generate();
    let pt = b"top secret ssh key material";
    let blob = aead_encrypt(&key, pt, &aad()).unwrap();
    let got = aead_decrypt(&key, &blob, &aad()).unwrap();
    assert_eq!(got, pt);
}

#[test]
fn empty_plaintext_roundtrip() {
    let key = SymmetricKey::generate();
    let blob = aead_encrypt(&key, b"", &aad()).unwrap();
    assert_eq!(aead_decrypt(&key, &blob, &aad()).unwrap(), b"");
}

#[test]
fn wrong_key_fails() {
    let key = SymmetricKey::generate();
    let other = SymmetricKey::generate();
    let blob = aead_encrypt(&key, b"x", &aad()).unwrap();
    assert_eq!(
        aead_decrypt(&other, &blob, &aad()).unwrap_err(),
        CryptoError::Decrypt
    );
}

#[test]
fn wrong_aad_fails() {
    let key = SymmetricKey::generate();
    let blob = aead_encrypt(&key, b"x", &aad()).unwrap();
    // a different version in the associated data → decryption does not authenticate
    let tampered = AssociatedData::new(b"vault-1".to_vec(), b"item-1".to_vec(), 2);
    assert_eq!(
        aead_decrypt(&key, &blob, &tampered).unwrap_err(),
        CryptoError::Decrypt
    );
}

#[test]
fn tampered_ciphertext_fails() {
    let key = SymmetricKey::generate();
    let mut blob = aead_encrypt(&key, b"hello world", &aad()).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(aead_decrypt(&key, &blob, &aad()).is_err());
}

#[test]
fn tampered_version_byte_fails() {
    let key = SymmetricKey::generate();
    let mut blob = aead_encrypt(&key, b"hello", &aad()).unwrap();
    blob[0] = 0xff;
    assert_eq!(
        aead_decrypt(&key, &blob, &aad()).unwrap_err(),
        CryptoError::UnsupportedVersion(0xff)
    );
}

#[test]
fn truncated_blob_fails() {
    let key = SymmetricKey::generate();
    let blob = aead_encrypt(&key, b"hello", &aad()).unwrap();
    assert_eq!(
        aead_decrypt(&key, &blob[..4], &aad()).unwrap_err(),
        CryptoError::Format
    );
}
