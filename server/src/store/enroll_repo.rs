//! Enrollment-grants repository: instance-level (NOT tenant-scoped) single-use
//! revocable bootstrap credentials. The operator (ops-token) issues a grant, the engineer
//! redeems it at /v1/bootstrap, creating THEIR OWN tenant. Only sha256(secret) is stored.

use super::models::{EnrollGrantRow, EnrollGrantState};
use super::{Store, Tx, Val};
use crate::error::{AppError, AppResult};

impl Store {
    /// Issue a grant (state='pending'). The secret itself is not stored — only its hash.
    pub async fn create_enrollment_grant(
        &self,
        grant_id: &[u8],
        token_hash: &[u8],
        label: &str,
        tier: Option<&str>,
        expires_at: Option<i64>,
        now: i64,
    ) -> AppResult<()> {
        self.exec(
            "INSERT INTO enrollment_grants \
             (grant_id, token_hash, label, tier, state, expires_at, created_at) \
             VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            vec![
                Val::b(grant_id),
                Val::b(token_hash),
                Val::t(label),
                Val::OptT(tier.map(str::to_string)),
                Val::OptI(expires_at),
                Val::I(now),
            ],
        )
        .await?;
        Ok(())
    }

    /// List of grants for the operator (token_hash is intentionally NOT exposed).
    pub async fn list_enrollment_grants(&self) -> AppResult<Vec<EnrollGrantRow>> {
        self.fetch_all_as::<EnrollGrantRow>(
            "SELECT grant_id, label, tier, state, expires_at, redeemed_tenant, redeemed_at, created_at \
             FROM enrollment_grants ORDER BY created_at ASC",
            vec![],
        )
        .await
    }

    /// Revoke a grant BEFORE use (gated on state='pending'). An already
    /// redeemed/revoked grant cannot be revoked → 409; unknown → 404.
    pub async fn revoke_enrollment_grant(&self, grant_id: &[u8]) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE enrollment_grants SET state = 'revoked' \
                 WHERE grant_id = ? AND state = 'pending'",
                vec![Val::b(grant_id)],
            )
            .await?;
        if n == 0 {
            let exists = self
                .fetch_scalar_i64(
                    "SELECT COUNT(*) FROM enrollment_grants WHERE grant_id = ?",
                    vec![Val::b(grant_id)],
                )
                .await?
                .unwrap_or(0)
                > 0;
            return Err(if exists {
                AppError::conflict("enrollment grant not pending")
            } else {
                AppError::not_found("enrollment grant")
            });
        }
        Ok(())
    }
}

impl Tx<'_> {
    /// Atomically redeem a grant by token_hash and bind it to the tenant being created.
    /// Single-use via a conditional UPDATE (state='pending' AND not expired). Returns
    /// the tier pinned by the grant (if set). Runs INSIDE the bootstrap transaction,
    /// so losing the genesis race rolls back this redemption too.
    pub async fn redeem_enrollment_grant_cas(
        &mut self,
        token_hash: &[u8],
        tenant_id: &[u8],
        now: i64,
    ) -> AppResult<Option<String>> {
        // Read for failure classification (an identical gone envelope, so as not to
        // reveal which secrets ever existed).
        let row = self
            .fetch_optional_as::<EnrollGrantState>(
                "SELECT tier, state, expires_at FROM enrollment_grants WHERE token_hash = ?",
                vec![Val::b(token_hash)],
            )
            .await?
            .ok_or_else(|| AppError::forbidden("invalid enrollment grant"))?;

        let n = self
            .exec(
                "UPDATE enrollment_grants \
                 SET state = 'redeemed', redeemed_tenant = ?, redeemed_at = ? \
                 WHERE token_hash = ? AND state = 'pending' \
                   AND (expires_at IS NULL OR expires_at > ?)",
                vec![
                    Val::b(tenant_id),
                    Val::I(now),
                    Val::b(token_hash),
                    Val::I(now),
                ],
            )
            .await?;
        if n == 1 {
            Ok(row.tier)
        } else if row.state == "revoked" {
            Err(AppError::gone("enrollment grant revoked"))
        } else if row.expires_at.is_some_and(|e| e <= now) {
            Err(AppError::gone("enrollment grant expired"))
        } else {
            Err(AppError::gone("enrollment grant already used"))
        }
    }
}
