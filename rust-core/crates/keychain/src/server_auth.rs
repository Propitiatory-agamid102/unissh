//! Server-auth sign side (server-tz §2.2, §13.4): sign the server challenge
//! with the Ed25519 key of the unlocked keyset.
//!
//! A thin wrapper over [`unissh_crypto::sign_server_auth`] (domain
//! `unissh-server-auth-v1`, non-colliding with record signatures). Signature
//! verification, nonce freshness and expiry are done by the server — here only
//! the sign side: the UI/FFI receives a ready-made signature blob, the private
//! key is never handed out.

use unissh_crypto::{sign_server_auth, ServerAuthChallenge};

use crate::error::KeychainError;
use crate::keyset::UnlockedKeyset;

/// Signs the server challenge with the Ed25519 key of the device keyset.
pub fn sign_server_challenge(
    unlocked: &UnlockedKeyset,
    challenge: &ServerAuthChallenge,
) -> Result<Vec<u8>, KeychainError> {
    Ok(sign_server_auth(&unlocked.signing.signing, challenge)?)
}
