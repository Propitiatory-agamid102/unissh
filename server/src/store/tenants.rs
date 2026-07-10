//! Tenants repository (§4.1/§12): tenant creation, reads (for the tenant-middleware
//! and suspended-check), fixing genesis_owner_pubkey at bootstrap.

use super::models::TenantRow;
use super::{Store, Val};
use crate::error::{AppError, AppResult};

impl Store {
    pub async fn get_tenant(&self, tenant_id: &[u8]) -> AppResult<Option<TenantRow>> {
        self.fetch_optional_as::<TenantRow>(
            "SELECT tenant_id, tier, display_name, next_seq, genesis_owner_pubkey, created_at, status \
             FROM tenants WHERE tenant_id = ?",
            vec![Val::b(tenant_id)],
        )
        .await
    }

    /// Create a tenant (idempotent: ON CONFLICT DO NOTHING). Returns true if created.
    pub async fn create_tenant(&self, tenant_id: &[u8], tier: &str, now: i64) -> AppResult<bool> {
        let n = self
            .exec(
                "INSERT INTO tenants (tenant_id, tier, next_seq, created_at, status) \
                 VALUES (?, ?, 0, ?, 'active') ON CONFLICT (tenant_id) DO NOTHING",
                vec![Val::b(tenant_id), Val::t(tier), Val::I(now)],
            )
            .await?;
        Ok(n > 0)
    }

    pub async fn account_count(&self, tenant_id: &[u8]) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM accounts WHERE tenant_id = ?",
                vec![Val::b(tenant_id)],
            )
            .await?
            .unwrap_or(0))
    }

    /// Atomically fix genesis_owner_pubkey (CAS: only if NULL and there are no
    /// accounts). Returns true on success (a single winner in the bootstrap race).
    pub async fn set_genesis_owner_if_unset(
        &self,
        tenant_id: &[u8],
        owner_pubkey: &[u8],
    ) -> AppResult<bool> {
        let n = self
            .exec(
                "UPDATE tenants SET genesis_owner_pubkey = ? \
                 WHERE tenant_id = ? AND genesis_owner_pubkey IS NULL",
                vec![Val::b(owner_pubkey), Val::b(tenant_id)],
            )
            .await?;
        Ok(n == 1)
    }

    /// Instance-wide monotonic generation for whole-DB anti-rollback (§16):
    /// Σ next_seq across all tenants. Monotonic (next_seq only grows; tenants are not
    /// deleted; seq-bump only raises). A decrease = an old snapshot was restored.
    pub async fn instance_generation(&self) -> AppResult<i64> {
        Ok(self
            .fetch_scalar_i64("SELECT COALESCE(SUM(next_seq), 0) FROM tenants", vec![])
            .await?
            .unwrap_or(0))
    }

    /// List of all tenant_id (for bulk seq-bump operations after a restore).
    pub async fn list_tenant_ids(&self) -> AppResult<Vec<Vec<u8>>> {
        use super::models::BlobRow;
        Ok(self
            .fetch_all_as::<BlobRow>("SELECT tenant_id AS b FROM tenants", vec![])
            .await?
            .into_iter()
            .map(|r| r.b)
            .collect())
    }

    /// Raise `next_seq` by `delta` (>0) — anti-rollback runbook after a restore from
    /// an OLD backup (§14.3). Returns (old, new). Upward only.
    pub async fn bump_next_seq_by(&self, tid: &[u8], delta: i64) -> AppResult<(i64, i64)> {
        if delta < 0 {
            return Err(AppError::malformed("delta must be >= 0"));
        }
        let new = self
            .fetch_scalar_i64(
                "UPDATE tenants SET next_seq = next_seq + ? WHERE tenant_id = ? RETURNING next_seq",
                vec![Val::I(delta), Val::b(tid)],
            )
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        Ok((new - delta, new))
    }

    /// Raise `next_seq` to the floor `target`, if it is above the current value (NEVER
    /// lowers). Returns (old, new).
    pub async fn bump_next_seq_to(&self, tid: &[u8], target: i64) -> AppResult<(i64, i64)> {
        let cur = self
            .fetch_scalar_i64(
                "SELECT next_seq FROM tenants WHERE tenant_id = ?",
                vec![Val::b(tid)],
            )
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        if target > cur {
            self.exec(
                "UPDATE tenants SET next_seq = ? WHERE tenant_id = ?",
                vec![Val::I(target), Val::b(tid)],
            )
            .await?;
            Ok((cur, target))
        } else {
            Ok((cur, cur))
        }
    }

    /// Background TTL cleanup (§13): stale nonce/relay/sessions are deleted,
    /// pending invites are marked expired, old idempotency keys (older than
    /// `idem_cutoff`) are deleted. Expiry is also enforced at use-time — this is hygiene.
    pub async fn cleanup_expired(&self, now: i64, idem_cutoff: i64) -> AppResult<()> {
        self.exec(
            "DELETE FROM auth_nonces WHERE expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM pake_relay WHERE expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "UPDATE invites SET state = 'expired' WHERE state = 'pending' AND expires_at < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM sessions WHERE refresh_expires < ?",
            vec![Val::I(now)],
        )
        .await?;
        self.exec(
            "DELETE FROM idempotency_keys WHERE created_at < ?",
            vec![Val::I(idem_cutoff)],
        )
        .await?;
        Ok(())
    }

    /// ZK diagnostics (§15.3): concatenation of all of the tenant's opaque blobs. The test
    /// verifies that plaintext markers are absent there (the server stores only
    /// ciphertext + open metadata).
    pub async fn dump_blobs(&self, tenant_id: &[u8]) -> AppResult<Vec<u8>> {
        use super::models::BlobRow;
        let mut out = Vec::new();
        for sql in [
            "SELECT object_bytes AS b FROM objects WHERE tenant_id = ?",
            "SELECT keyset_bytes AS b FROM keyset_blobs WHERE tenant_id = ?",
            "SELECT manifest_blob AS b FROM membership_manifests WHERE tenant_id = ?",
            "SELECT wrapped_vk AS b FROM membership_grants WHERE tenant_id = ?",
            "SELECT entry_blob AS b FROM audit_log WHERE tenant_id = ?",
        ] {
            for r in self
                .fetch_all_as::<BlobRow>(sql, vec![Val::b(tenant_id)])
                .await?
            {
                out.extend_from_slice(&r.b);
            }
        }
        Ok(out)
    }

    pub async fn set_tenant_status(&self, tenant_id: &[u8], status: &str) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE tenants SET status = ? WHERE tenant_id = ?",
                vec![Val::t(status), Val::b(tenant_id)],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("tenant"));
        }
        Ok(())
    }

    /// Set/clear the human-readable name of a tenant (open metadata — a
    /// label for the ops-switcher). `None` clears it (→ NULL). Not found → 404.
    pub async fn set_tenant_display_name(
        &self,
        tenant_id: &[u8],
        display_name: Option<&str>,
    ) -> AppResult<()> {
        let n = self
            .exec(
                "UPDATE tenants SET display_name = ? WHERE tenant_id = ?",
                vec![
                    Val::OptT(display_name.map(str::to_string)),
                    Val::b(tenant_id),
                ],
            )
            .await?;
        if n == 0 {
            return Err(AppError::not_found("tenant"));
        }
        Ok(())
    }
}
