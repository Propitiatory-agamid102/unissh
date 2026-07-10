//! The crate's error type. Principle: any malformed input (a corrupted blob, a wrong
//! key/AD/password, a broken signature, a version rollback) yields `Err`, not a panic.

use thiserror::Error;

/// Errors of cryptographic operations.
///
/// Deliberately "terse" on detail: an AEAD failure does not distinguish "wrong key" from
/// "wrong associated data" — both are `Decrypt` (we do not give the attacker an oracle).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The AEAD operation failed: wrong key, wrong associated data,
    /// corrupted ciphertext/tag. (Also covers the rare internal encryption failure.)
    #[error("AEAD operation failed (bad key, associated data or ciphertext)")]
    Decrypt,

    /// The blob is structurally malformed: too short, truncated, wrong field length.
    #[error("malformed crypto blob")]
    Format,

    /// The blob format version is not supported by this build.
    #[error("unsupported blob format version: {0:#04x}")]
    UnsupportedVersion(u8),

    /// The algorithm identifier is unknown or not the one expected for the operation.
    #[error("unsupported or unexpected algorithm id: {0:#06x}")]
    UnsupportedAlgorithm(u16),

    /// The Ed25519 signature does not verify (forgery, foreign key, corrupted data).
    #[error("signature verification failed")]
    Signature,

    /// Version rollback: the presented version is not greater than the last seen one.
    #[error("version rollback detected: attempted {attempted} <= last seen {last_seen}")]
    Rollback {
        /// The version from the presented (signed) object.
        attempted: u64,
        /// The last version the caller has already seen.
        last_seen: u64,
    },

    /// Key derivation failure (Argon2id): invalid parameters or salt.
    #[error("key derivation (Argon2id) failed")]
    Kdf,

    /// HPKE seal/open failure (malformed encapped key, foreign private key, etc.).
    #[error("HPKE seal/open failed")]
    Hpke,

    /// The key/input length does not match the expected one.
    #[error("invalid key or input length")]
    InvalidLength,
}
