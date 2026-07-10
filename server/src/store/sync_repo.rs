//! Sync repository (spec §5.1/§7): atomic push (monotonic per-tenant
//! server_seq + idempotency + materialize of derived tables), delta, report_version.
//! The orchestration is written ONCE via dialect-agnostic `Tx` primitives.

use super::models::{DeltaRow, IdempotencyRow};
use super::{Store, Tx, Val};
use crate::codec::{ObjectTag, ParsedObject};
use crate::error::{AppError, AppResult};
use sqlx::FromRow;

/// One object as push input: raw bytes + parsed open columns.
pub struct PushObj {
    pub bytes: Vec<u8>,
    pub parsed: ParsedObject,
}

/// Push result: assigned seqs (in input order) + whether this was an idempotent replay.
#[derive(Debug)]
pub struct PushResult {
    pub server_seq: Vec<i64>,
    pub replayed: bool,
}

#[derive(FromRow)]
struct VaultOwner {
    owner_pubkey: Vec<u8>,
    latest_version: i64,
    latest_epoch: i64,
}

fn opt_u64(o: Option<u64>) -> AppResult<Val> {
    match o {
        None => Ok(Val::OptI(None)),
        Some(v) => {
            Ok(Val::OptI(Some(i64::try_from(v).map_err(|_| {
                AppError::malformed("integer exceeds i64")
            })?)))
        }
    }
}
fn opt_u32(o: Option<u32>) -> Val {
    Val::OptI(o.map(|v| v as i64))
}
fn opt_u8(o: Option<u8>) -> Val {
    Val::OptI(o.map(|v| v as i64))
}
fn opt_bool(o: Option<bool>) -> Val {
    Val::OptI(o.map(|b| b as i64))
}
fn opt_b(o: &Option<Vec<u8>>) -> Val {
    Val::OptB(o.clone())
}
fn idem_result(rec: &IdempotencyRow, req_hash: &[u8]) -> AppResult<PushResult> {
    if rec.request_hash == req_hash {
        let seqs: Vec<i64> = serde_json::from_slice(&rec.response_blob)
            .map_err(|_| AppError::internal("corrupt idempotency record"))?;
        Ok(PushResult {
            server_seq: seqs,
            replayed: true,
        })
    } else {
        Err(AppError::conflict(
            "idempotency key reused with a different request body",
        ))
    }
}

fn req_u64(o: Option<u64>, what: &str) -> AppResult<i64> {
    let v = o.ok_or_else(|| AppError::malformed(format!("missing {what}")))?;
    i64::try_from(v).map_err(|_| AppError::malformed(format!("{what} exceeds i64")))
}

impl Store {
    /// report_version: the maximum assigned server_seq == tenants.next_seq (§5.1).
    pub async fn report_version(&self, tenant_id: &[u8]) -> AppResult<i64> {
        self.fetch_scalar_i64(
            "SELECT next_seq FROM tenants WHERE tenant_id = ?",
            vec![Val::b(tenant_id)],
        )
        .await?
        .ok_or_else(|| AppError::not_found("tenant"))
    }

    /// delta_since: (server_seq, object_bytes) with server_seq > cursor, ASC, a page
    /// up to `limit` (§5.1), **filtered by membership (A1)**.
    ///
    /// The device `member` (its Ed25519 pubkey = canonical member-id) sees a vault
    /// object ONLY if it is the vault owner OR holds an active grant for the LATEST
    /// manifest epoch (`revoked=0` AND `not_after`). Instance-admin does NOT bypass
    /// (unlike `grants_get` read-deny). Non-vault objects are visible to all the
    /// tenant's devices, but ONLY for tag Audit(5)/Keyset(6): a vault-scoped tag
    /// (Vault/Item/Manifest/Grant) with an empty `vault_id` is NOT considered "non-vault"
    /// (otherwise it could be smuggled into the broadcast) — it falls through to the
    /// owner/grant branches, where an empty `vault_id` will not match any vault.
    ///
    /// CURSOR under DYNAMIC membership: the filter lives in SQL BEFORE `LIMIT`, so
    /// `has_more`/`next_cursor` (by the last returned seq) are correct for the CURRENT
    /// visible set. BUT membership changes over time: a device whose cursor has already
    /// moved past the objects of a vault it was ADDED TO LATER will not receive them
    /// incrementally (delta only returns seq > cursor). Backfill of such objects is task
    /// A1b (re-emit the vault set on fresh seqs when a grant is activated); until then
    /// a newly arrived member must re-anchor to cursor=0 for that vault. The bytes are not
    /// lost — the append-only log keeps them.
    ///
    /// TRUST: the filter is a read-side check that trusts the materialized
    /// `vaults`/`membership_grants`. Their integrity is held by the write-side RBAC
    /// (`write_accept`) when `validate_signatures=true` (the secure default). Hardening
    /// (mandatory verification of ACL objects regardless of the toggle; vault-admin
    /// authorship in `grants_publish`) is tracked as an A1 follow-up.
    pub async fn delta_since(
        &self,
        tenant_id: &[u8],
        cursor: i64,
        limit: i64,
        member: &[u8],
        now: i64,
    ) -> AppResult<Vec<DeltaRow>> {
        self.fetch_all_as::<DeltaRow>(
            "SELECT server_seq, object_bytes FROM objects \
             WHERE tenant_id = ? AND server_seq > ? \
               AND ( \
                 ((objects.vault_id IS NULL OR length(objects.vault_id) = 0) \
                    AND objects.object_tag IN (5, 6)) \
                 OR EXISTS (SELECT 1 FROM vaults v \
                            WHERE v.tenant_id = objects.tenant_id AND v.vault_id = objects.vault_id \
                              AND v.owner_pubkey = ?) \
                 OR EXISTS (SELECT 1 FROM membership_grants g \
                            WHERE g.tenant_id = objects.tenant_id AND g.vault_id = objects.vault_id \
                              AND g.member_pubkey = ? AND g.revoked = 0 \
                              AND (g.not_after IS NULL OR g.not_after > ?) \
                              AND g.key_epoch = (SELECT MAX(m.key_epoch) FROM membership_manifests m \
                                                 WHERE m.tenant_id = objects.tenant_id \
                                                   AND m.vault_id = objects.vault_id)) \
                 OR (objects.object_tag = 7 AND objects.author_pubkey = ?) \
               ) \
             ORDER BY server_seq ASC LIMIT ?",
            vec![
                Val::b(tenant_id),
                Val::I(cursor),
                Val::b(member),
                Val::b(member),
                Val::I(now),
                Val::b(member),
                Val::I(limit),
            ],
        )
        .await
    }

    /// Atomic push (§5.1/§7.2): idempotency-replay OR {assign monotonic
    /// seqs, insert objects verbatim, materialize derived, update next_seq,
    /// store the idem record} — all in one transaction.
    pub async fn push_objects(
        &self,
        tenant_id: &[u8],
        idem: Option<&[u8]>,
        req_hash: &[u8],
        items: Vec<PushObj>,
        now: i64,
    ) -> AppResult<PushResult> {
        // Fast path: sequential idempotent replay (a typical retry after a timeout).
        if let Some(k) = idem {
            if let Some(rec) = self
                .fetch_optional_as::<IdempotencyRow>(
                    "SELECT request_hash, response_blob, status_code FROM idempotency_keys \
                     WHERE tenant_id = ? AND idem_key = ?",
                    vec![Val::b(tenant_id), Val::b(k)],
                )
                .await?
            {
                return idem_result(&rec, req_hash);
            }
        }

        let n = items.len() as i64;
        let mut tx = self.begin().await?;

        // Atomic seq allocation: increment RELATIVE to the current value under a
        // row write-lock. `UPDATE ... RETURNING` serializes concurrent pushes
        // on BOTH dialects (no deferred-read-then-write lost-update, §7.2).
        let new_next = tx
            .fetch_scalar_i64(
                "UPDATE tenants SET next_seq = next_seq + ? WHERE tenant_id = ? RETURNING next_seq",
                vec![Val::I(n), Val::b(tenant_id)],
            )
            .await?
            .ok_or_else(|| AppError::not_found("tenant"))?;
        let base = new_next - n;

        let mut seqs = Vec::with_capacity(items.len());
        for (i, it) in items.iter().enumerate() {
            let seq = base + 1 + i as i64;
            insert_object(&mut tx, tenant_id, seq, &it.parsed, &it.bytes, now).await?;
            materialize(&mut tx, tenant_id, seq, &it.parsed, now).await?;
            seqs.push(seq);
        }

        if let Some(k) = idem {
            let resp = serde_json::to_vec(&seqs)
                .map_err(|_| AppError::internal("serialize idempotency response"))?;
            // ON CONFLICT DO NOTHING: the unique key is the race arbiter of concurrent
            // first pushes with the same idem key.
            let inserted = tx
                .exec(
                    "INSERT INTO idempotency_keys \
                     (tenant_id, idem_key, request_hash, response_blob, status_code, created_at) \
                     VALUES (?,?,?,?,?,?) ON CONFLICT (tenant_id, idem_key) DO NOTHING",
                    vec![
                        Val::b(tenant_id),
                        Val::b(k),
                        Val::b(req_hash),
                        Val::B(resp),
                        Val::I(200),
                        Val::I(now),
                    ],
                )
                .await?;
            if inserted == 0 {
                // A concurrent contender already claimed the key — roll back our work
                // (seq increment + objects) and return ITS result.
                tx.rollback().await?;
                if let Some(rec) = self
                    .fetch_optional_as::<IdempotencyRow>(
                        "SELECT request_hash, response_blob, status_code FROM idempotency_keys \
                         WHERE tenant_id = ? AND idem_key = ?",
                        vec![Val::b(tenant_id), Val::b(k)],
                    )
                    .await?
                {
                    return idem_result(&rec, req_hash);
                }
                return Err(AppError::conflict(
                    "concurrent push with the same idempotency key",
                ));
            }
        }

        tx.commit().await?;
        Ok(PushResult {
            server_seq: seqs,
            replayed: false,
        })
    }
}

/// Insert an `objects` row verbatim + the parsed open columns.
pub(crate) async fn insert_object(
    tx: &mut Tx<'_>,
    tenant_id: &[u8],
    seq: i64,
    p: &ParsedObject,
    bytes: &[u8],
    now: i64,
) -> AppResult<()> {
    tx.exec(
        "INSERT INTO objects \
         (tenant_id, server_seq, object_tag, object_bytes, vault_id, item_id, member_pubkey, \
          obj_version, key_epoch, tombstone, item_type, sync_target, cache_policy, role, \
          author_pubkey, received_at) \
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        vec![
            Val::b(tenant_id),
            Val::I(seq),
            Val::I(p.tag_u8 as i64),
            Val::b(bytes),
            opt_b(&p.vault_id),
            opt_b(&p.item_id),
            opt_b(&p.member_pubkey),
            opt_u64(p.obj_version)?,
            opt_u64(p.key_epoch)?,
            opt_bool(p.tombstone),
            opt_u32(p.item_type),
            opt_u8(p.sync_target),
            opt_u8(p.cache_policy),
            opt_u8(p.role),
            opt_b(&p.author_pubkey),
            Val::I(now),
        ],
    )
    .await?;
    Ok(())
}

/// Materialize the derived tables (vaults claim/update, manifests anti-equivoc,
/// grants ACL upsert). The append-only `objects` log has already been written above —
/// here only the denormalized latest snapshots. The single exception to append-only is
/// the tag-7 (account-state) compaction: strictly older self-authored versions are
/// pruned from the log (S3), since they have no history and will never win LWW.
pub(crate) async fn materialize(
    tx: &mut Tx<'_>,
    tenant_id: &[u8],
    seq: i64,
    p: &ParsedObject,
    now: i64,
) -> AppResult<()> {
    match p.tag() {
        Some(ObjectTag::Vault) => {
            let vault_id = p
                .vault_id
                .clone()
                .ok_or_else(|| AppError::malformed("vault: missing vault_id"))?;
            let author = p
                .author_pubkey
                .clone()
                .ok_or_else(|| AppError::malformed("vault: missing author"))?;
            let version = req_u64(p.obj_version, "vault.version")?;
            let epoch = req_u64(p.key_epoch, "vault.key_epoch")?;
            let st = p.sync_target.unwrap_or(1) as i64;
            let cp = p.cache_policy.unwrap_or(0) as i64;
            let tomb = p.tombstone.unwrap_or(false) as i64;

            let existing = tx
                .fetch_optional_as::<VaultOwner>(
                    "SELECT owner_pubkey, latest_version, latest_epoch FROM vaults \
                     WHERE tenant_id = ? AND vault_id = ?",
                    vec![Val::b(tenant_id), Val::b(vault_id.clone())],
                )
                .await?;
            match existing {
                None => {
                    tx.exec(
                        "INSERT INTO vaults (tenant_id, vault_id, owner_pubkey, latest_version, \
                         latest_epoch, sync_target, cache_policy, tombstone, created_at) \
                         VALUES (?,?,?,?,?,?,?,?,?)",
                        vec![
                            Val::b(tenant_id),
                            Val::b(vault_id),
                            Val::b(author),
                            Val::I(version),
                            Val::I(epoch),
                            Val::I(st),
                            Val::I(cp),
                            Val::I(tomb),
                            Val::I(now),
                        ],
                    )
                    .await?;
                }
                Some(row) => {
                    // Claim-rule: owner immutable. A different owner → conflict (§4.4/§8.2).
                    // (org-tier admin-override is applied in the policy layer, §9.3.)
                    if row.owner_pubkey != author {
                        return Err(AppError::conflict(
                            "vault_id owned by a different author (claim-rule)",
                        ));
                    }
                    let nv = row.latest_version.max(version);
                    let ne = row.latest_epoch.max(epoch);
                    tx.exec(
                        "UPDATE vaults SET latest_version = ?, latest_epoch = ?, sync_target = ?, \
                         cache_policy = ?, tombstone = ? WHERE tenant_id = ? AND vault_id = ?",
                        vec![
                            Val::I(nv),
                            Val::I(ne),
                            Val::I(st),
                            Val::I(cp),
                            Val::I(tomb),
                            Val::b(tenant_id),
                            Val::b(vault_id),
                        ],
                    )
                    .await?;
                }
            }
        }
        Some(ObjectTag::MembershipManifest) => {
            // Anti-equivocation: one manifest per (vault,epoch); the first one wins.
            let vault_id = p.vault_id.clone().unwrap_or_default();
            let epoch = req_u64(p.key_epoch, "manifest.key_epoch")?;
            let blob = p.manifest_blob.clone().unwrap_or_default();
            let sig = p.signature.clone().unwrap_or_default();
            let author = p.author_pubkey.clone().unwrap_or_default();
            tx.exec(
                "INSERT INTO membership_manifests \
                 (tenant_id, vault_id, key_epoch, manifest_blob, signature, author_pubkey, \
                  server_seq, received_at) VALUES (?,?,?,?,?,?,?,?) \
                 ON CONFLICT (tenant_id, vault_id, key_epoch) DO NOTHING",
                vec![
                    Val::b(tenant_id),
                    Val::b(vault_id),
                    Val::I(epoch),
                    Val::B(blob),
                    Val::B(sig),
                    Val::B(author),
                    Val::I(seq),
                    Val::I(now),
                ],
            )
            .await?;
        }
        Some(ObjectTag::MembershipGrant) => {
            // ACL upsert by (vault, member, epoch). We do NOT reset revoked on a
            // conflict (`revoked = membership_grants.revoked`): the revocation of an epoch
            // is PERMANENT (a re-grant goes under a new epoch, as a separate row), while
            // re-publishing the same grant would previously have resurrected the revoked
            // access for an offboarding member (#10). The initial insert is revoked=0 anyway.
            let vault_id = p.vault_id.clone().unwrap_or_default();
            let member = p.member_pubkey.clone().unwrap_or_default();
            let epoch = req_u64(p.key_epoch, "grant.key_epoch")?;
            let role = p.role.unwrap_or(0) as i64;
            let wrapped = p.wrapped_vk.clone().unwrap_or_default();
            let sig = p.signature.clone().unwrap_or_default();
            let author = p.author_pubkey.clone().unwrap_or_default();
            tx.exec(
                "INSERT INTO membership_grants \
                 (tenant_id, vault_id, member_pubkey, key_epoch, role, wrapped_vk, signature, \
                  author_pubkey, not_after, revoked, server_seq, received_at) \
                 VALUES (?,?,?,?,?,?,?,?,?,0,?,?) \
                 ON CONFLICT (tenant_id, vault_id, member_pubkey, key_epoch) DO UPDATE SET \
                  role = excluded.role, wrapped_vk = excluded.wrapped_vk, \
                  signature = excluded.signature, author_pubkey = excluded.author_pubkey, \
                  not_after = excluded.not_after, \
                  revoked = membership_grants.revoked, \
                  server_seq = excluded.server_seq, received_at = excluded.received_at",
                vec![
                    Val::b(tenant_id),
                    Val::b(vault_id),
                    Val::b(member),
                    Val::I(epoch),
                    Val::I(role),
                    Val::B(wrapped),
                    Val::B(sig),
                    Val::B(author),
                    // not_after (inside the signed content of the grant): sentinel
                    // <=0 = no expiry → NULL; >0 = unix deadline → enforced
                    // in member_has_active_grant.
                    match p.not_after {
                        Some(n) if n > 0 => Val::OptI(Some(n)),
                        _ => Val::OptI(None),
                    },
                    Val::I(seq),
                    Val::I(now),
                ],
            )
            .await?;
        }
        Some(ObjectTag::AccountState) => {
            // S3: compaction of self-authored account-state (tag 7). LWW semantics:
            // the client only needs the MAX version (equal versions are tiebroken by
            // the signature on the client — see process_account_state). Strictly older
            // versions from the same author in the append-only log will never win LWW —
            // we delete them so the log does not grow on every bump of {personal_vault_id,
            // default_username}. The current row is already inserted (insert_object above),
            // so `< version` does not touch it or its equals (equals are both kept —
            // the client resolves them by signature). Safe for delta: the cursor filters
            // `server_seq > cursor` (gaps in seq are allowed), a lagging device will still
            // receive the latest version. From the append-only log ONLY tag-7 is pruned
            // (self-authored, no history); other tags are immutable.
            if p.obj_version.is_some() {
                if let Some(author) = p.author_pubkey.clone() {
                    tx.exec(
                        "DELETE FROM objects WHERE tenant_id = ? AND object_tag = 7 \
                         AND author_pubkey = ? AND obj_version < ?",
                        vec![Val::b(tenant_id), Val::b(author), opt_u64(p.obj_version)?],
                    )
                    .await?;
                }
            }
        }
        // Item / Audit / Keyset — only the append-only log (no derived tables here).
        _ => {}
    }
    Ok(())
}
