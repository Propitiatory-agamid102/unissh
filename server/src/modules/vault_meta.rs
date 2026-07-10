//! backend-vault-metadata (spec §5.4/§8.2): claim vault_id namespace.
//! Vault/Item objects flow through /v1/sync/push (there are no separate endpoints).

use crate::error::{AppError, AppResult};
use crate::http::extract::AuthCtx;
use crate::ids;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/vaults/claim", post(claim))
}

#[derive(Deserialize)]
struct ClaimReq {
    vault_id: String,
}

#[derive(Serialize)]
struct ClaimResp {
    claimed: bool,
}

/// `POST /v1/vaults/claim` (§5.4): fixes owner=author on the first claim;
/// rejects if vault_id already belongs to another owner (claim-rule §8.2).
async fn claim(
    auth: AuthCtx,
    State(state): State<AppState>,
    Json(req): Json<ClaimReq>,
) -> AppResult<Json<ClaimResp>> {
    let vault_id = ids::unb64(&req.vault_id)?;
    if vault_id.is_empty() {
        return Err(AppError::malformed("empty vault_id"));
    }
    let claimed = state
        .store
        .claim_vault(
            auth.tenant_id(),
            &vault_id,
            auth.device_ed25519(),
            state.now(),
        )
        .await?;
    Ok(Json(ClaimResp { claimed }))
}
