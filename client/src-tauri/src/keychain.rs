//! OS keychain storage for the instance Secret Key.
//!
//! Lets the app remember the Secret Key on a trusted device (macOS Keychain /
//! Windows Credential Manager / Linux kernel keyring / iOS Keychain) so unlock
//! can prefill it. This matches the core's "trusted device" unlock model. Active
//! wherever a native keychain exists (`native_keychain` — every target except
//! Android, still a no-op pending a Keystore-backed plugin).

use crate::error::{ApiError, ApiResult};

#[cfg(native_keychain)]
const SERVICE: &str = "me.goduni.unissh";
#[cfg(native_keychain)]
const ACCOUNT: &str = "secret-key";

#[cfg(native_keychain)]
fn ks_entry() -> Result<keyring::Entry, ApiError> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(ApiError::other)
}

#[tauri::command]
pub fn keychain_available() -> bool {
    cfg!(native_keychain)
}

#[tauri::command]
pub fn keychain_save_secret_key(secret_key: String) -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        ks_entry()?
            .set_password(&secret_key)
            .map_err(ApiError::other)
    }
    #[cfg(not(native_keychain))]
    {
        let _ = secret_key;
        Err(ApiError::other("keychain unavailable on this platform"))
    }
}

#[tauri::command]
pub fn keychain_get_secret_key() -> ApiResult<Option<String>> {
    #[cfg(native_keychain)]
    {
        match ks_entry()?.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(ApiError::other(e)),
        }
    }
    #[cfg(not(native_keychain))]
    {
        Ok(None)
    }
}

/// Trusted-device auto-unlock entirely inside Rust: read the Secret Key from the
/// OS keychain and hand it straight to the core's `unlock` — the key NEVER crosses
/// into the webview JS heap (where any future XSS could read it). The boot path
/// uses THIS instead of `keychain_get_secret_key` + `unlock`; `keychain_get` is
/// kept only for the explicit "show my Secret Key" reveal UI.
#[tauri::command]
pub async fn keychain_unlock(
    password: Option<String>,
    state: tauri::State<'_, crate::state::AppState>,
) -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        let raw = match ks_entry()?.get_password() {
            Ok(s) => s,
            Err(keyring::Error::NoEntry) => {
                return Err(ApiError::other("no Secret Key stored in keychain"))
            }
            Err(e) => return Err(ApiError::other(e)),
        };
        // Normalize (strip spacing/dashes) exactly as the old JS unlock path did.
        let secret_key_hex: String = raw
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let core = state.core.clone();
        crate::commands::blocking(move || core.unlock(password, secret_key_hex)).await
    }
    #[cfg(not(native_keychain))]
    {
        let _ = (password, state);
        Err(ApiError::other("keychain unavailable on this platform"))
    }
}

#[tauri::command]
pub fn keychain_delete_secret_key() -> ApiResult<()> {
    #[cfg(native_keychain)]
    {
        match ks_entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(ApiError::other(e)),
        }
    }
    #[cfg(not(native_keychain))]
    {
        Ok(())
    }
}
