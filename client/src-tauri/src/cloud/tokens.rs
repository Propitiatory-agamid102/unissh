//! Refresh-token storage in the OS keychain, per linked server.
//!
//! The refresh token is a long-lived bearer credential, so it gets the same
//! native-keychain treatment as the instance Secret Key (see `crate::keychain`);
//! the short-lived access token stays in memory only. Active wherever a native
//! keychain exists (`native_keychain`); on Android it is still a no-op (re-login
//! after restart) pending a Keystore-backed plugin.
//!
//! Tokens are namespaced by `server_id` (keychain account `refresh/<server_id>`)
//! so that disconnecting one server never wipes another's refresh token.

#[cfg(native_keychain)]
const SERVICE: &str = "me.goduni.unissh";

/// Keychain account name for a server's refresh token. The id is opaque and
/// path-safe (hex), so embedding it keeps each server's token distinct.
#[cfg(native_keychain)]
fn account(server_id: &str) -> String {
    format!("cloud-refresh-token/{server_id}")
}

/// Pre-multi-server account: a single global refresh token (no per-server id).
#[cfg(native_keychain)]
const LEGACY_ACCOUNT: &str = "cloud-refresh-token";

#[cfg(native_keychain)]
pub fn save_refresh(server_id: &str, token: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, &account(server_id))
        .map_err(|e| e.to_string())?
        .set_password(token)
        .map_err(|e| e.to_string())
}

#[cfg(native_keychain)]
pub fn load_refresh(server_id: &str) -> Option<String> {
    let entry = keyring::Entry::new(SERVICE, &account(server_id)).ok()?;
    entry.get_password().ok()
}

#[cfg(native_keychain)]
pub fn delete_refresh(server_id: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, &account(server_id)).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Move a pre-multi-server refresh token (single global account) onto the
/// per-server account on upgrade, then delete the legacy entry. No-op if absent.
/// Best-effort: keychain errors are swallowed (worst case = one extra re-login).
#[cfg(native_keychain)]
pub fn migrate_legacy(server_id: &str) {
    let Ok(legacy) = keyring::Entry::new(SERVICE, LEGACY_ACCOUNT) else {
        return;
    };
    if let Ok(token) = legacy.get_password() {
        let _ = save_refresh(server_id, &token);
        let _ = legacy.delete_credential();
    }
}

#[cfg(not(native_keychain))]
pub fn save_refresh(_server_id: &str, _token: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(native_keychain))]
pub fn load_refresh(_server_id: &str) -> Option<String> {
    None
}

#[cfg(not(native_keychain))]
pub fn delete_refresh(_server_id: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(native_keychain))]
pub fn migrate_legacy(_server_id: &str) {}
