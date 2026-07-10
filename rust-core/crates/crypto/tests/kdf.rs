//! Argon2id KDF: determinism, dependence on salt/password, parameter serialization.

use unissh_crypto::{derive_key, KdfParams};

/// Lightweight parameters for test speed (still Argon2id).
fn fast(salt: u8) -> KdfParams {
    KdfParams {
        mem_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
        salt: vec![salt; 16],
    }
}

#[test]
fn deterministic() {
    let p = fast(7);
    let k1 = derive_key(b"correct horse battery staple", &p).unwrap();
    let k2 = derive_key(b"correct horse battery staple", &p).unwrap();
    assert_eq!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn different_salt_differs() {
    let k1 = derive_key(b"pw", &fast(1)).unwrap();
    let k2 = derive_key(b"pw", &fast(2)).unwrap();
    assert_ne!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn wrong_password_differs() {
    let p = fast(5);
    let k1 = derive_key(b"password", &p).unwrap();
    let k2 = derive_key(b"Password", &p).unwrap();
    assert_ne!(k1.expose_bytes(), k2.expose_bytes());
}

#[test]
fn params_blob_roundtrip() {
    let p = KdfParams::recommended();
    let blob = p.to_blob().unwrap();
    let p2 = KdfParams::from_blob(&blob).unwrap();
    assert_eq!(p, p2);
}

#[test]
fn params_blob_rejects_truncation() {
    let p = KdfParams::recommended();
    let blob = p.to_blob().unwrap();
    assert!(KdfParams::from_blob(&blob[..blob.len() - 3]).is_err());
}

#[test]
fn recommended_meets_memory_floor() {
    // spec 5.5: Argon2id memory ≥ 64 MiB.
    assert!(KdfParams::recommended().mem_kib >= 64 * 1024);
}

#[test]
fn from_blob_rejects_oversized_params() {
    // An untrusted blob with a huge mem_kib must not parse (DoS protection:
    // the Argon2 allocation happens before AEAD authentication on the import_vault path).
    let evil = KdfParams {
        mem_kib: u32::MAX,
        iterations: 3,
        parallelism: 1,
        salt: vec![0u8; 16],
    };
    let blob = evil.to_blob().unwrap();
    assert!(KdfParams::from_blob(&blob).is_err());

    // Out-of-bounds iterations/parallelism are rejected too.
    let evil_iter = KdfParams {
        mem_kib: 65536,
        iterations: 1_000_000,
        parallelism: 1,
        salt: vec![0u8; 16],
    };
    assert!(KdfParams::from_blob(&evil_iter.to_blob().unwrap()).is_err());

    // The recommended parameters are still valid.
    let ok = KdfParams::recommended();
    assert!(KdfParams::from_blob(&ok.to_blob().unwrap()).is_ok());
}
