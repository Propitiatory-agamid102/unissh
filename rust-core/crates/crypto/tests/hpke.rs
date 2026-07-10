//! HPKE wrapping of a symmetric key under an X25519 public key.

use unissh_crypto::{
    open_key_with_secret, seal_key_to_public, SymmetricKey, X25519Keypair, X25519PublicKey,
    X25519SecretKey,
};

#[test]
fn roundtrip() {
    let kp = X25519Keypair::generate();
    let key = SymmetricKey::generate();
    let blob = seal_key_to_public(&kp.public, &key, b"vault:demo").unwrap();
    let got = open_key_with_secret(&kp.secret, &blob, b"vault:demo").unwrap();
    assert_eq!(got.expose_bytes(), key.expose_bytes());
}

#[test]
fn wrong_recipient_fails() {
    let kp = X25519Keypair::generate();
    let other = X25519Keypair::generate();
    let key = SymmetricKey::generate();
    let blob = seal_key_to_public(&kp.public, &key, b"ctx").unwrap();
    assert!(open_key_with_secret(&other.secret, &blob, b"ctx").is_err());
}

#[test]
fn wrong_info_fails() {
    let kp = X25519Keypair::generate();
    let key = SymmetricKey::generate();
    let blob = seal_key_to_public(&kp.public, &key, b"ctx-a").unwrap();
    assert!(open_key_with_secret(&kp.secret, &blob, b"ctx-b").is_err());
}

#[test]
fn tampered_blob_fails() {
    let kp = X25519Keypair::generate();
    let key = SymmetricKey::generate();
    let mut blob = seal_key_to_public(&kp.public, &key, b"ctx").unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    assert!(open_key_with_secret(&kp.secret, &blob, b"ctx").is_err());
}

#[test]
fn public_key_bytes_roundtrip() {
    let kp = X25519Keypair::generate();
    let bytes = kp.public.to_bytes();
    let restored = X25519PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored.to_bytes(), bytes);
}

#[test]
fn secret_key_bytes_roundtrip_and_derive_public() {
    let kp = X25519Keypair::generate();
    let sk_bytes = kp.secret.expose_to_bytes();
    let restored = X25519SecretKey::from_bytes(&sk_bytes).unwrap();
    // the public key derived from the restored private key matches
    assert_eq!(restored.public_key().to_bytes(), kp.public.to_bytes());
}
