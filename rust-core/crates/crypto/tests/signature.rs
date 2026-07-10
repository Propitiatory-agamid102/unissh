//! Ed25519 signatures over versioned objects + rollback detection.

use unissh_crypto::{
    sign_version, verify_no_rollback, verify_version, AssociatedData, CryptoError, Ed25519Keypair,
    VersionedObject,
};

fn obj(version: u64) -> VersionedObject {
    VersionedObject::from_content(
        AssociatedData::new(b"vault".to_vec(), b"item".to_vec(), version),
        b"content bytes",
    )
}

#[test]
fn sign_and_verify() {
    let kp = Ed25519Keypair::generate();
    let o = obj(5);
    let sig = sign_version(&kp.signing, &o).unwrap();
    assert!(verify_version(&kp.verifying, &o, &sig).is_ok());
}

#[test]
fn tampered_object_fails() {
    let kp = Ed25519Keypair::generate();
    let sig = sign_version(&kp.signing, &obj(5)).unwrap();
    // a different object (a different version) under the same signature → failure
    assert_eq!(
        verify_version(&kp.verifying, &obj(6), &sig).unwrap_err(),
        CryptoError::Signature
    );
}

#[test]
fn wrong_key_fails() {
    let kp = Ed25519Keypair::generate();
    let other = Ed25519Keypair::generate();
    let o = obj(5);
    let sig = sign_version(&kp.signing, &o).unwrap();
    assert_eq!(
        verify_version(&other.verifying, &o, &sig).unwrap_err(),
        CryptoError::Signature
    );
}

#[test]
fn forged_signature_bytes_fail() {
    let kp = Ed25519Keypair::generate();
    let o = obj(5);
    let mut sig = sign_version(&kp.signing, &o).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert!(verify_version(&kp.verifying, &o, &sig).is_err());
}

#[test]
fn rollback_detected() {
    let kp = Ed25519Keypair::generate();
    let o = obj(3);
    let sig = sign_version(&kp.signing, &o).unwrap();
    assert_eq!(
        verify_no_rollback(&kp.verifying, &o, &sig, 5).unwrap_err(),
        CryptoError::Rollback {
            attempted: 3,
            last_seen: 5
        }
    );
}

#[test]
fn equal_version_is_rollback() {
    let kp = Ed25519Keypair::generate();
    let o = obj(5);
    let sig = sign_version(&kp.signing, &o).unwrap();
    assert!(verify_no_rollback(&kp.verifying, &o, &sig, 5).is_err());
}

#[test]
fn fresh_version_accepted() {
    let kp = Ed25519Keypair::generate();
    let o = obj(6);
    let sig = sign_version(&kp.signing, &o).unwrap();
    assert!(verify_no_rollback(&kp.verifying, &o, &sig, 5).is_ok());
}
