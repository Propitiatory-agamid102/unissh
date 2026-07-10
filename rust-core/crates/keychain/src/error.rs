//! Errors of the keychain crate.

use thiserror::Error;
use unissh_crypto::CryptoError;
use unissh_storage::StorageError;

/// Errors of the key hierarchy.
///
/// `PartialEq`/`Eq` are implemented by hand: the [`KeychainError::Storage`] variant
/// wraps [`StorageError`], which itself does not implement `PartialEq` (inside —
/// `rusqlite::Error`). `Storage` variants are compared by their `Display` string,
/// the rest structurally. This keeps `assert_eq!` in tests against the typed
/// variants (`AccountIdConflict`, `GenerationRollback`, …) without losing `#[from]`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeychainError {
    /// Wrong password or Secret Key (or a corrupted keyset): the unwrap did not
    /// authenticate. Deliberately does not distinguish what exactly is wrong.
    #[error("invalid password or secret key")]
    InvalidCredentials,

    /// Structurally malformed keyset record.
    #[error("malformed keyset record")]
    Format,

    /// The unlock mode requires a password, but none was provided (or vice versa).
    #[error("password required for this keyset but not provided")]
    PasswordRequired,

    /// Attempt to write an account-id different from the one already stored.
    #[error("account id already set to a different value")]
    AccountIdConflict,

    /// The registration blob failed verification: the signature or the embedded
    /// keys/account-id did not match the expected ones.
    #[error("registration payload verification failed")]
    RegistrationInvalid,

    /// Keyset generation rollback: the presented record is older than the trusted
    /// floor (anti-rollback / password downgrade protection). Not a panic.
    #[error("keyset generation rollback: record gen {attempted} < trusted floor {floor}")]
    GenerationRollback {
        /// Generation of the presented record.
        attempted: u64,
        /// Trusted generation floor (from storage-meta).
        floor: u64,
    },

    /// Mutual onboarding confirmation failed (wrong PAKE code / a forged tag): there
    /// is no channel agreement, secrets are NOT transferred.
    #[error("device onboarding confirmation failed")]
    ConfirmationFailed,

    /// Error from the underlying storage crate.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// Error from the underlying crypto crate.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl PartialEq for KeychainError {
    fn eq(&self, other: &Self) -> bool {
        use KeychainError::*;
        match (self, other) {
            (InvalidCredentials, InvalidCredentials)
            | (Format, Format)
            | (PasswordRequired, PasswordRequired)
            | (AccountIdConflict, AccountIdConflict)
            | (RegistrationInvalid, RegistrationInvalid)
            | (ConfirmationFailed, ConfirmationFailed) => true,
            (
                GenerationRollback {
                    attempted: a1,
                    floor: f1,
                },
                GenerationRollback {
                    attempted: a2,
                    floor: f2,
                },
            ) => a1 == a2 && f1 == f2,
            (Crypto(a), Crypto(b)) => a == b,
            // StorageError does not implement PartialEq — compare by Display.
            (Storage(a), Storage(b)) => a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl Eq for KeychainError {}
