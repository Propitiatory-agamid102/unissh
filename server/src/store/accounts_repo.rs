//! Accounts repository: canonical keyset (= member-id), human identifiers
//! (display_name/handle), instance-admin flag, admin listing, device-add.

use super::models::{AccountListRow, AccountRow};
use super::{Store, Val};
use crate::error::{AppError, AppResult};

const ACCOUNT_COLS: &str =
    "account_id, display_name, handle, is_admin, ed25519_pub, x25519_pub, status";

impl Store {
    pub async fn get_account_by_id(
        &self,
        tid: &[u8],
        account_id: &[u8],
    ) -> AppResult<Option<AccountRow>> {
        self.fetch_optional_as::<AccountRow>(
            &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE tenant_id = ? AND account_id = ?"),
            vec![Val::b(tid), Val::b(account_id)],
        )
        .await
    }

    /// Account by canonical ed25519 keyset (= member-id).
    pub async fn get_account_by_ed(
        &self,
        tid: &[u8],
        ed25519_pub: &[u8],
    ) -> AppResult<Option<AccountRow>> {
        self.fetch_optional_as::<AccountRow>(
            &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE tenant_id = ? AND ed25519_pub = ?"),
            vec![Val::b(tid), Val::b(ed25519_pub)],
        )
        .await
    }

    pub async fn handle_taken(&self, tid: &[u8], handle: &str) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE tenant_id = ? AND handle = ?",
                vec![Val::b(tid), Val::t(handle)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// handle taken by ANOTHER account (for update profile, where one's own handle is ok).
    pub async fn handle_taken_by_other(
        &self,
        tid: &[u8],
        handle: &str,
        account_id: &[u8],
    ) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE tenant_id = ? AND handle = ? AND account_id != ?",
                vec![Val::b(tid), Val::t(handle), Val::b(account_id)],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// Admin listing of the tenant's accounts + device count.
    pub async fn list_accounts(&self, tid: &[u8]) -> AppResult<Vec<AccountListRow>> {
        self.fetch_all_as::<AccountListRow>(
            "SELECT a.account_id, a.display_name, a.handle, a.is_admin, a.ed25519_pub, a.x25519_pub, a.status, \
             a.reg_payload, a.reg_signature, \
             (SELECT COUNT(*) FROM device_pubkeys d \
              WHERE d.tenant_id = a.tenant_id AND d.account_id = a.account_id) AS device_count \
             FROM accounts a WHERE a.tenant_id = ? ORDER BY a.created_at ASC",
            vec![Val::b(tid)],
        )
        .await
    }

    /// Update the profile (display_name/handle). Empty fields leave the existing values untouched.
    pub async fn update_account_profile(
        &self,
        tid: &[u8],
        account_id: &[u8],
        display_name: Option<&str>,
        handle: Option<&str>,
    ) -> AppResult<()> {
        if let Some(dn) = display_name {
            self.exec(
                "UPDATE accounts SET display_name = ? WHERE tenant_id = ? AND account_id = ?",
                vec![Val::t(dn), Val::b(tid), Val::b(account_id)],
            )
            .await?;
        }
        if let Some(h) = handle {
            self.exec(
                "UPDATE accounts SET handle = ? WHERE tenant_id = ? AND account_id = ?",
                vec![Val::t(h), Val::b(tid), Val::b(account_id)],
            )
            .await?;
        }
        Ok(())
    }

    pub async fn admin_count(&self, tid: &[u8]) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE tenant_id = ? AND is_admin = 1",
                vec![Val::b(tid)],
            )
            .await?
            .unwrap_or(0))
    }

    /// Grant/revoke instance-admin (server-trusted, §10). Does NOT grant decryption —
    /// only the invite/audit/device-revoke/grants-publish authority.
    pub async fn set_account_admin(
        &self,
        tid: &[u8],
        account_id: &[u8],
        is_admin: bool,
    ) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE accounts SET is_admin = ? WHERE tenant_id = ? AND account_id = ?",
                vec![Val::I(is_admin as i64), Val::b(tid), Val::b(account_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("account"));
        }
        Ok(())
    }
}
