//! Blob versioning / crypto agility through the public API.

use unissh_crypto::{
    aead_decrypt, aead_encrypt, sign_version, AlgId, AssociatedData, CryptoError, Ed25519Keypair,
    SymmetricKey, VersionedObject, FORMAT_VERSION,
};

fn aad() -> AssociatedData {
    AssociatedData::new(b"v".to_vec(), b"i".to_vec(), 1)
}

#[test]
fn blob_carries_versioned_header() {
    let key = SymmetricKey::generate();
    let blob = aead_encrypt(&key, b"x", &aad()).unwrap();
    assert_eq!(blob[0], FORMAT_VERSION);
    assert_eq!(
        &blob[1..3],
        &AlgId::XChaCha20Poly1305.to_u16().to_be_bytes()
    );
}

#[test]
fn cross_algorithm_blob_rejected() {
    // a signature blob (alg 0x0020) cannot be "decrypted" as AEAD (which expects 0x0001)
    let kp = Ed25519Keypair::generate();
    let o = VersionedObject::from_content(aad(), b"c");
    let sig = sign_version(&kp.signing, &o).unwrap();
    let key = SymmetricKey::generate();
    assert_eq!(
        aead_decrypt(&key, &sig, &aad()).unwrap_err(),
        CryptoError::UnsupportedAlgorithm(AlgId::Ed25519.to_u16())
    );
}

#[test]
fn unknown_algorithm_rejected() {
    let blob = [FORMAT_VERSION, 0x00, 0x99, 0, 0, 0, 0, 0];
    let key = SymmetricKey::generate();
    assert_eq!(
        aead_decrypt(&key, &blob, &aad()).unwrap_err(),
        CryptoError::UnsupportedAlgorithm(0x0099)
    );
}

#[test]
fn unsupported_version_rejected() {
    let blob = [0x02, 0x00, 0x01, 0, 0, 0, 0, 0];
    let key = SymmetricKey::generate();
    assert_eq!(
        aead_decrypt(&key, &blob, &aad()).unwrap_err(),
        CryptoError::UnsupportedVersion(0x02)
    );
}
