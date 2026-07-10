//! Parse the `manifest_blob` member-set (spec §8.1) — mirror of
//! `crates/vault/src/membership.rs::canonical_member_payload`. Used by the
//! server for the author∈members@epoch predicate on write-accept (§9.4) and RBAC.
//!
//! Format: `"unissh-manifest-v1" || key_epoch:u64BE || count:u32BE ||
//! repeated{ role:u8, ed_len:u16BE, ed25519_pub }`, members sorted by
//! ed25519_pub ASC, no duplicates.

use crate::domain::rbac::Role;
use crate::error::AppError;

pub const MANIFEST_DOMAIN: &[u8] = b"unissh-manifest-v1";

/// Parsed manifest member-set.
#[derive(Debug, Clone)]
pub struct MemberSet {
    pub key_epoch: u64,
    pub members: Vec<(Vec<u8>, Role)>,
}

impl MemberSet {
    pub fn role_of(&self, ed25519_pub: &[u8]) -> Option<Role> {
        self.members
            .iter()
            .find(|(p, _)| p == ed25519_pub)
            .map(|(_, r)| *r)
    }
    pub fn contains(&self, ed25519_pub: &[u8]) -> bool {
        self.role_of(ed25519_pub).is_some()
    }
}

/// Strict parse of manifest_blob → member-set.
pub fn parse_member_set(blob: &[u8]) -> Result<MemberSet, AppError> {
    let err = || AppError::malformed("manifest: format error");
    let dl = MANIFEST_DOMAIN.len();
    if blob.len() < dl + 8 + 4 {
        return Err(err());
    }
    if &blob[..dl] != MANIFEST_DOMAIN {
        return Err(err());
    }
    let mut pos = dl;
    let key_epoch = u64::from_be_bytes(blob[pos..pos + 8].try_into().map_err(|_| err())?);
    pos += 8;
    let count = u32::from_be_bytes(blob[pos..pos + 4].try_into().map_err(|_| err())?) as usize;
    pos += 4;

    let mut members = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        if pos + 1 + 2 > blob.len() {
            return Err(err());
        }
        let role = Role::from_u8(blob[pos]).ok_or_else(err)?;
        pos += 1;
        let ed_len = u16::from_be_bytes(blob[pos..pos + 2].try_into().map_err(|_| err())?) as usize;
        pos += 2;
        if pos + ed_len > blob.len() {
            return Err(err());
        }
        let ed = blob[pos..pos + ed_len].to_vec();
        pos += ed_len;
        members.push((ed, role));
    }
    if pos != blob.len() {
        return Err(err()); // trailing bytes
    }
    Ok(MemberSet { key_epoch, members })
}
