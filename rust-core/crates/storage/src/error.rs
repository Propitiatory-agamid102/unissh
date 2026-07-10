//! Errors of the storage crate.

use thiserror::Error;

/// Local storage errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// Wrong DB key or a corrupt file (SQLCipher could not decrypt).
    #[error("wrong database key or corrupt database")]
    WrongKeyOrCorrupt,

    /// Attempt to write an object version no greater than the one already stored (rollback).
    #[error("version rollback: attempted {attempted} <= current {current}")]
    VersionRollback {
        /// The current stored version.
        current: u64,
        /// The version from the rejected write.
        attempted: u64,
    },

    /// The DB key has the wrong length (32 bytes expected).
    #[error("database key must be 32 bytes")]
    BadKeyLength,

    /// The object version is out of range (a SQLite INTEGER is an i64).
    #[error("version out of range (must be <= i64::MAX)")]
    VersionOutOfRange,

    /// Incompatible DB schema version.
    #[error("unsupported schema version: {0}")]
    SchemaVersion(i64),

    /// SQLite/SQLCipher error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}
