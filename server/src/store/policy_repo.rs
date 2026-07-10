//! Policy/membership repository (§4.4/§4.5/§4.6/§8/§9): vault claim, manifest/
//! grant reads, atomic grants_publish (revoke/add).

use super::models::{DeltaRow, GrantRow, ManifestRow};
use super::sync_repo::{PushObj, insert_object, materialize};
use super::{Store, Val};
use crate::codec::parse_open;
use crate::error::{AppError, AppResult};

const GRANT_COLS: &str = "vault_id, member_pubkey, key_epoch, role, wrapped_vk, signature, \
                          author_pubkey, not_after, revoked";

#[derive(sqlx::FromRow)]
struct OwnerOnly {
    owner_pubkey: Vec<u8>,
}

impl Store {
    /// Explicit claim of vault_id (§5.4/§8.2): reject-if-exists-different-owner.
    /// Returns true if the namespace was created, false if it already belongs to the author.
    pub async fn claim_vault(
        &self,
        tid: &[u8],
        vault_id: &[u8],
        owner: &[u8],
        now: i64,
    ) -> AppResult<bool> {
        let existing = self
            .fetch_optional_as::<OwnerOnly>(
                "SELECT owner_pubkey FROM vaults WHERE tenant_id = ? AND vault_id = ?",
                vec![Val::b(tid), Val::b(vault_id)],
            )
            .await?;
        match existing {
            Some(row) => {
                if row.owner_pubkey != owner {
                    Err(AppError::conflict(
                        "vault_id already claimed by a different owner",
                    ))
                } else {
                    Ok(false)
                }
            }
            None => {
                self.exec(
                    "INSERT INTO vaults (tenant_id, vault_id, owner_pubkey, latest_version, \
                     latest_epoch, sync_target, cache_policy, tombstone, created_at) \
                     VALUES (?, ?, ?, 0, 0, 1, 0, 0, ?)",
                    vec![Val::b(tid), Val::b(vault_id), Val::b(owner), Val::I(now)],
                )
                .await?;
                Ok(true)
            }
        }
    }

    pub async fn get_vault_owner(&self, tid: &[u8], vault_id: &[u8]) -> AppResult<Option<Vec<u8>>> {
        Ok(self
            .fetch_optional_as::<OwnerOnly>(
                "SELECT owner_pubkey FROM vaults WHERE tenant_id = ? AND vault_id = ?",
                vec![Val::b(tid), Val::b(vault_id)],
            )
            .await?
            .map(|r| r.owner_pubkey))
    }

    pub async fn get_manifest(
        &self,
        tid: &[u8],
        vault_id: &[u8],
        epoch: i64,
    ) -> AppResult<Option<ManifestRow>> {
        self.fetch_optional_as::<ManifestRow>(
            "SELECT vault_id, key_epoch, manifest_blob, signature, author_pubkey \
             FROM membership_manifests WHERE tenant_id = ? AND vault_id = ? AND key_epoch = ?",
            vec![Val::b(tid), Val::b(vault_id), Val::I(epoch)],
        )
        .await
    }

    pub async fn latest_manifest_epoch(
        &self,
        tid: &[u8],
        vault_id: &[u8],
    ) -> AppResult<Option<i64>> {
        // MAX returns NULL (None) when no rows; fetch_scalar_i64 maps that to None too.
        self.fetch_scalar_i64(
            "SELECT MAX(key_epoch) FROM membership_manifests WHERE tenant_id = ? AND vault_id = ?",
            vec![Val::b(tid), Val::b(vault_id)],
        )
        .await
    }

    pub async fn list_grants(
        &self,
        tid: &[u8],
        vault_id: &[u8],
        epoch: i64,
        non_revoked_only: bool,
    ) -> AppResult<Vec<GrantRow>> {
        let filter = if non_revoked_only {
            " AND revoked = 0"
        } else {
            ""
        };
        let sql = format!(
            "SELECT {GRANT_COLS} FROM membership_grants \
             WHERE tenant_id = ? AND vault_id = ? AND key_epoch = ?{filter} \
             ORDER BY member_pubkey ASC"
        );
        self.fetch_all_as::<GrantRow>(&sql, vec![Val::b(tid), Val::b(vault_id), Val::I(epoch)])
            .await
    }

    /// Whether the member has an active (not revoked, not expired) grant for the epoch.
    /// `not_after` is enforced here: a grant whose time has passed is no longer active
    /// (read-deny). The grant wire format (tag 4) CARRIES a per-grant `not_after` in the
    /// signed content, and `materialize` persists it (sentinel `<=0` → NULL =
    /// no expiry), so the condition `not_after IS NULL OR not_after > now`
    /// is actually honored and not silently ignored.
    pub async fn member_has_active_grant(
        &self,
        tid: &[u8],
        vault_id: &[u8],
        epoch: i64,
        member: &[u8],
        now: i64,
    ) -> AppResult<bool> {
        Ok(self
            .fetch_scalar_i64(
                "SELECT COUNT(*) FROM membership_grants \
                 WHERE tenant_id = ? AND vault_id = ? AND key_epoch = ? AND member_pubkey = ? \
                 AND revoked = 0 AND (not_after IS NULL OR not_after > ?)",
                vec![
                    Val::b(tid),
                    Val::b(vault_id),
                    Val::I(epoch),
                    Val::b(member),
                    Val::I(now),
                ],
            )
            .await?
            .unwrap_or(0)
            > 0)
    }

    /// Atomic publish (§9.3): accept the manifest + grants of the new epoch (append to
    /// the objects log + materialize the ACL), then read-deny the old revoke_epoch (mark
    /// revoked — the log is NOT touched). All in one transaction.
    pub async fn grants_publish(
        &self,
        tid: &[u8],
        vault_id: &[u8],
        manifest: &PushObj,
        grants: &[PushObj],
        revoke_epoch: Option<i64>,
        now: i64,
    ) -> AppResult<Vec<i64>> {
        let n = (1 + grants.len()) as i64;
        let mut tx = self.begin().await?;
        // Atomic seq allocation under a row write-lock (like push_objects): `UPDATE
        // ... RETURNING` serializes concurrent publishes on BOTH dialects.
        // Previously grants_publish did a deferred SELECT + absolute UPDATE — on SQLite
        // two writers read the same next_seq and the second INSERT failed on a PK conflict.
        let new_next = tx
            .fetch_scalar_i64(
                "UPDATE tenants SET next_seq = next_seq + ? WHERE tenant_id = ? RETURNING next_seq",
                vec![Val::I(n), Val::b(tid)],
            )
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        let base = new_next - n;

        let mut seqs = Vec::with_capacity(n as usize);
        // First the manifest of the new epoch, then the grants under VK' (§9.3).
        for (i, obj) in std::iter::once(manifest).chain(grants.iter()).enumerate() {
            let seq = base + 1 + i as i64;
            insert_object(&mut tx, tid, seq, &obj.parsed, &obj.bytes, now).await?;
            materialize(&mut tx, tid, seq, &obj.parsed, now).await?;
            seqs.push(seq);
        }

        // A1b: re-emit the CURRENT vault set (the vault record + manifests of epochs < E +
        // live items) on FRESH seqs. A member added LATER, whose cursor has already moved
        // past these objects (delta only returns seq > cursor), would otherwise not receive
        // them and the vault would look empty. We take the bytes verbatim from the objects log
        // (dedup: the latest seq per identity) → idempotent under client-LWW, and a fresh seq
        // lifts them above any cursor. manifest@E and grants@E have already been added above;
        // everything is within the SAME transaction — delivery is atomic with the grant publish.
        let new_epoch = manifest.parsed.key_epoch.unwrap_or(0) as i64;
        let reemit = tx
            .fetch_all_as::<DeltaRow>(
                "SELECT server_seq, object_bytes FROM objects o \
                 WHERE o.tenant_id = ? AND o.vault_id = ? AND ( \
                   (o.object_tag = 1 AND o.server_seq = (SELECT MAX(server_seq) FROM objects \
                      WHERE tenant_id=o.tenant_id AND vault_id=o.vault_id AND object_tag=1)) \
                   OR (o.object_tag = 3 AND o.key_epoch < ? AND o.server_seq = (SELECT MAX(server_seq) \
                      FROM objects WHERE tenant_id=o.tenant_id AND vault_id=o.vault_id \
                        AND object_tag=3 AND key_epoch=o.key_epoch)) \
                   OR (o.object_tag = 2 AND o.tombstone = 0 AND o.server_seq = (SELECT MAX(server_seq) \
                      FROM objects WHERE tenant_id=o.tenant_id AND vault_id=o.vault_id \
                        AND object_tag=2 AND item_id=o.item_id)) \
                 ) \
                 ORDER BY (CASE o.object_tag WHEN 1 THEN 0 WHEN 3 THEN 1 ELSE 2 END), o.server_seq ASC",
                vec![Val::b(tid), Val::b(vault_id), Val::I(new_epoch)],
            )
            .await?;
        if !reemit.is_empty() {
            let m = reemit.len() as i64;
            let rnext = tx
                .fetch_scalar_i64(
                    "UPDATE tenants SET next_seq = next_seq + ? WHERE tenant_id = ? RETURNING next_seq",
                    vec![Val::I(m), Val::b(tid)],
                )
                .await?
                .ok_or_else(|| AppError::not_found("tenant"))?;
            let rbase = rnext - m;
            for (i, row) in reemit.iter().enumerate() {
                let seq = rbase + 1 + i as i64;
                let parsed = parse_open(&row.object_bytes)?;
                insert_object(&mut tx, tid, seq, &parsed, &row.object_bytes, now).await?;
                materialize(&mut tx, tid, seq, &parsed, now).await?;
            }
        }

        // Then read-deny the old epoch in the ACL (idempotent, last).
        if let Some(re) = revoke_epoch {
            tx.exec(
                "UPDATE membership_grants SET revoked = 1 \
                 WHERE tenant_id = ? AND vault_id = ? AND key_epoch = ?",
                vec![Val::b(tid), Val::b(vault_id), Val::I(re)],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(seqs)
    }
}
