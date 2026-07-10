//! Errors of the embedded SSH agent.

use thiserror::Error;

/// Agent errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    /// No key with this id is loaded into the agent.
    #[error("key not found in agent")]
    NotFound,

    /// Failed to parse the private key (corrupt or unrecognized format).
    #[error("failed to parse private key")]
    Parse,

    /// The key is encrypted with a passphrase, but no passphrase was provided —
    /// the UI must prompt for one and retry the import.
    #[error("private key is encrypted (passphrase-protected); a passphrase is required")]
    Encrypted,

    /// An incorrect passphrase was provided for the encrypted key.
    #[error("incorrect passphrase for the private key")]
    WrongPassphrase,

    /// Legacy OpenSSL PEM encryption (`Proc-Type: 4,ENCRYPTED` / `DEK-Info`) is
    /// not supported; the key needs to be reconverted.
    #[error("legacy OpenSSL-encrypted PEM is not supported; convert it first (e.g. `ssh-keygen -p -f <key>`)")]
    LegacyEncrypted,

    /// The private key type/format is not supported (for example DSA).
    #[error("unsupported private key type or format")]
    Unsupported,

    /// Error from the ssh-key library.
    #[error("ssh key error: {0}")]
    Ssh(String),
}

impl From<ssh_key::Error> for AgentError {
    fn from(e: ssh_key::Error) -> Self {
        AgentError::Ssh(e.to_string())
    }
}
