//! Identity / session / device operations against the server `/v1` API.
//!
//! Every function is synchronous (`reqwest::blocking`) and must run inside a
//! blocking context. Signing is delegated to the core (`build_registration_request`,
//! `sign_server_challenge_raw`) — the private keyset never leaves the core.

use reqwest::blocking::Client;
use serde_json::{json, Value};
use unissh_ffi as ffi;

use crate::cloud::client;
use crate::dto;
use crate::error::{ApiError, ApiResult};

/// Client-chosen key identifier echoed in the auth challenge. The server stores
/// and echoes it verbatim (it never interprets it), and the device signs over the
/// echoed value, so any stable value works.
const KEY_ID: &[u8] = b"unissh-keyset-v1";

/// Result of `bootstrap`/`register` — the server-assigned identity.
pub struct RegisterOutcome {
    pub account_id: String,
    pub device_id: String,
    /// Server-reported: this keyset owns the space (genesis-owner). Absent on older
    /// servers → `false`. Lets `reconnect` restore the right `owned` flag.
    pub owned: bool,
}

/// Session tokens minted by `auth/verify` / `session/refresh`. (Token expiries are
/// also returned by the server and will be consumed by the Phase-5 auto-refresh.)
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl SessionTokens {
    fn from_value(v: &Value) -> ApiResult<Self> {
        Ok(SessionTokens {
            access_token: client::jstr(v, "access_token")?,
            refresh_token: client::jstr(v, "refresh_token")?,
        })
    }
}

fn outcome_from_value(v: &Value) -> ApiResult<RegisterOutcome> {
    Ok(RegisterOutcome {
        account_id: client::jstr(v, "account_id")?,
        device_id: client::jstr(v, "device_id")?,
        owned: v.get("owned").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// `POST /v1/bootstrap` — genesis device of a NEW tenant (becomes its genesis-owner
/// = instance-admin of that tenant). Used to create a Space you OWN (e.g. a personal
/// space for your identity), possibly on the same server as a company you joined.
/// The server gates this by config (`bootstrap.token` must match, or `allow_open`);
/// a closed server returns 403 and the caller falls back to "use another server".
#[allow(clippy::too_many_arguments)]
pub fn bootstrap(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    reg: ffi::RegistrationRequest,
    tier: Option<String>,
    display_name: Option<String>,
    handle: Option<String>,
    bootstrap_token: Option<String>,
) -> ApiResult<RegisterOutcome> {
    let body = json!({
        "tenant_bootstrap_token": bootstrap_token,
        "registration_payload": client::b64(&reg.payload),
        "registration_signature": client::b64(&reg.signature),
        "tier": tier,
        "display_name": display_name,
        "handle": handle,
    });
    let v = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/bootstrap")),
            tenant_b64,
            None,
        )
        .json(&body),
    )?;
    outcome_from_value(&v)
}

/// `POST /v1/register` — join an existing tenant with an invite token.
pub fn register(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    invite_token: &str,
    reg: ffi::RegistrationRequest,
    display_name: Option<String>,
    handle: Option<String>,
) -> ApiResult<RegisterOutcome> {
    let body = json!({
        "invite_token": invite_token,
        "registration_payload": client::b64(&reg.payload),
        "registration_signature": client::b64(&reg.signature),
        "display_name": display_name,
        "handle": handle,
    });
    let v = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/register")),
            tenant_b64,
            None,
        )
        .json(&body),
    )?;
    outcome_from_value(&v)
}

/// `POST /v1/invite/redeem` — read-only preview of an invite (does NOT consume it).
/// Returns `(role, scope)`.
pub fn invite_redeem_preview(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    invite_token: &str,
) -> ApiResult<(String, Option<String>)> {
    let body = json!({ "invite_token": invite_token });
    let v = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/invite/redeem")),
            tenant_b64,
            None,
        )
        .json(&body),
    )?;
    let role = client::jstr(&v, "role")?;
    let scope = v.get("scope").and_then(|s| s.as_str()).map(str::to_string);
    Ok((role, scope))
}

/// Full auth handshake: `auth/challenge` → core `sign_server_challenge_raw` →
/// `auth/verify`. Returns the session tokens. `account_id_b64`/`device_id_b64` are
/// the server-assigned ids (base64).
pub fn login(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    core: &ffi::Core,
    account_id_b64: &str,
    device_id_b64: &str,
) -> ApiResult<SessionTokens> {
    let chal_body = json!({
        "account_id": account_id_b64,
        "device_id": device_id_b64,
        "key_id": client::b64(KEY_ID),
    });
    let chal = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/auth/challenge")),
            tenant_b64,
            None,
        )
        .json(&chal_body),
    )?;

    // Sign over the RAW bytes of every field (the server reconstructs the
    // challenge from base64-decoded fields and verifies over those raw bytes).
    let host = client::unb64(&client::jstr(&chal, "host")?)?;
    let account_id = client::unb64(&client::jstr(&chal, "account_id")?)?;
    let device_id = client::unb64(&client::jstr(&chal, "device_id")?)?;
    let key_id = client::unb64(&client::jstr(&chal, "key_id")?)?;
    let nonce = client::unb64(&client::jstr(&chal, "nonce")?)?;
    let expiry = client::ju64(&chal, "expiry")?;
    let sig = core
        .sign_server_challenge_raw(host, account_id, device_id, key_id, nonce, expiry)
        .map_err(ApiError::from)?;

    // Echo the challenge object verbatim — its field names/values must match what
    // the server issued, byte-for-byte, or verification fails.
    let verify_body = json!({ "challenge": chal, "signature": client::b64(&sig) });
    let tokens = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/auth/verify")),
            tenant_b64,
            None,
        )
        .json(&verify_body),
    )?;
    SessionTokens::from_value(&tokens)
}

/// `POST /v1/session/refresh` — rotate access+refresh (same session). No Bearer.
pub fn refresh(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    refresh_token: &str,
) -> ApiResult<SessionTokens> {
    let body = json!({ "refresh_token": refresh_token });
    let v = client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/session/refresh")),
            tenant_b64,
            None,
        )
        .json(&body),
    )?;
    SessionTokens::from_value(&v)
}

/// `POST /v1/session/logout` (Bearer) — revoke the calling session. 204.
pub fn logout(http: &Client, base_url: &str, tenant_b64: &str, access: &str) -> ApiResult<()> {
    client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/session/logout")),
        tenant_b64,
        Some(access),
    ))?;
    Ok(())
}

/// `POST /v1/session/device-revoke` (Bearer). Own device, or another's if admin. 204.
pub fn device_revoke(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
    device_id_b64: &str,
) -> ApiResult<()> {
    let body = json!({ "device_id": device_id_b64 });
    client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/session/device-revoke")),
            tenant_b64,
            Some(access),
        )
        .json(&body),
    )?;
    Ok(())
}

/// `POST /v1/devices/add` (Bearer) — add a sibling device under the caller's
/// account (shared keyset). Returns the new `device_id` (base64).
pub fn device_add(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
) -> ApiResult<String> {
    let v = client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/devices/add")),
        tenant_b64,
        Some(access),
    ))?;
    client::jstr(&v, "device_id")
}

/// `GET /v1/devices` (Bearer) — list the caller's own account devices.
pub fn device_list(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
) -> ApiResult<Vec<dto::DeviceInfo>> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/devices")),
        tenant_b64,
        Some(access),
    ))?;
    let devices = v["devices"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "devices response missing 'devices'".into(),
    })?;
    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        out.push(dto::DeviceInfo {
            device_id: client::jstr(d, "device_id")?,
            status: d
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            registered_at: d.get("registered_at").and_then(|x| x.as_i64()).unwrap_or(0),
            active_sessions: d.get("active_sessions").and_then(|x| x.as_i64()).unwrap_or(0),
        });
    }
    Ok(out)
}

/// `POST /v1/account/profile` (Bearer) — set display_name / handle. 204.
pub fn account_profile(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
    display_name: Option<String>,
    handle: Option<String>,
) -> ApiResult<()> {
    let body = json!({ "display_name": display_name, "handle": handle });
    client::send_json(
        client::headers(
            http.post(client::url(base_url, "/v1/account/profile")),
            tenant_b64,
            Some(access),
        )
        .json(&body),
    )?;
    Ok(())
}

/// `GET /v1/accounts` (Bearer-admin) — list accounts with their member-id pubkeys
/// (Ed25519 + X25519), converted from the server's base64 to the hex form the
/// core's `add_member`/`rotate_vk` expect. Non-admin callers get `forbidden`.
pub fn list_accounts(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
) -> ApiResult<Vec<dto::AccountInfo>> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/accounts")),
        tenant_b64,
        Some(access),
    ))?;
    let accounts = v["accounts"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "accounts response missing 'accounts'".into(),
    })?;
    let to_hex_field = |a: &Value, key: &str| -> Option<String> {
        a.get(key)
            .and_then(|x| x.as_str())
            .and_then(|s| client::unb64(s).ok())
            .map(|b| client::to_hex(&b))
    };
    let mut out = Vec::with_capacity(accounts.len());
    for a in accounts {
        out.push(dto::AccountInfo {
            account_id: client::jstr(a, "account_id")?,
            display_name: a
                .get("display_name")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            handle: a.get("handle").and_then(|x| x.as_str()).map(str::to_string),
            is_admin: a.get("is_admin").and_then(|x| x.as_bool()).unwrap_or(false),
            ed25519_pub_hex: to_hex_field(a, "member_pubkey"),
            x25519_pub_hex: to_hex_field(a, "x25519_pub"),
            status: a
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            device_count: a.get("device_count").and_then(|x| x.as_i64()).unwrap_or(0),
        });
    }
    Ok(out)
}

// ---- keyset escrow (Path A) ----

/// `PUT /v1/keyset` (Bearer) — escrow this device's already-encrypted keyset blob
/// (no-downgrade on generation). Returns the stored generation.
pub fn keyset_put(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
    keyset_blob: &[u8],
) -> ApiResult<i64> {
    let body = json!({ "keyset_blob": client::b64(keyset_blob) });
    let v = client::send_json(
        client::headers(
            http.put(client::url(base_url, "/v1/keyset")),
            tenant_b64,
            Some(access),
        )
        .json(&body),
    )?;
    client::ji64(&v, "generation")
}

/// `GET /v1/keyset` (Bearer) — pull the escrowed keyset blob. Returns `(blob, generation)`.
pub fn keyset_get(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
) -> ApiResult<(Vec<u8>, i64)> {
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, "/v1/keyset")),
        tenant_b64,
        Some(access),
    ))?;
    let blob = client::unb64(&client::jstr(&v, "keyset_blob")?)?;
    let generation = client::ji64(&v, "generation")?;
    Ok((blob, generation))
}

// ---- PAKE relay (Path B) ----

/// `POST /v1/relay/open` (Bearer) — open a device-to-device PAKE relay channel.
/// Returns the channel id (base64).
pub fn relay_open(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
) -> ApiResult<String> {
    let v = client::send_json(client::headers(
        http.post(client::url(base_url, "/v1/relay/open")),
        tenant_b64,
        Some(access),
    ))?;
    client::jstr(&v, "channel_id")
}

/// `POST /v1/relay/{slot}` (tenant only, NO bearer) — put a PAKE message into a
/// slot (`msg1`/`msg2`/`msg3`). The slot name is also the body field name.
pub fn relay_post(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    channel_id_b64: &str,
    slot: &str,
    msg: &[u8],
) -> ApiResult<()> {
    let mut body = serde_json::Map::new();
    body.insert(
        "channel_id".to_string(),
        Value::String(channel_id_b64.to_string()),
    );
    body.insert(slot.to_string(), Value::String(client::b64(msg)));
    client::send_json(
        client::headers(
            http.post(client::url(base_url, &format!("/v1/relay/{slot}"))),
            tenant_b64,
            None,
        )
        .json(&Value::Object(body)),
    )?;
    Ok(())
}

/// `GET /v1/relay/poll` (tenant only) — fetch a slot. `Some(bytes)` if present,
/// `None` on 204 (not posted yet).
pub fn relay_poll(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    channel_id_b64: &str,
    want: &str,
) -> ApiResult<Option<Vec<u8>>> {
    let path = format!(
        "/v1/relay/poll?channel_id={}&want={}",
        client::enc_query(channel_id_b64),
        client::enc_query(want)
    );
    let rb = client::headers(http.get(client::url(base_url, &path)), tenant_b64, None);
    let v = client::send_json(rb)?;
    if v.is_null() {
        return Ok(None);
    }
    match v.get(want).and_then(|x| x.as_str()) {
        Some(s) => Ok(Some(client::unb64(s)?)),
        None => Ok(None),
    }
}

// ---- audit (read-only) ----

/// `GET /v1/audit` (Bearer-admin) — read the server's audit log of observed events
/// (logins, etc.). The opaque blobs are dropped; the UI-useful fields are surfaced.
pub fn audit_query(
    http: &Client,
    base_url: &str,
    tenant_b64: &str,
    access: &str,
    since_seq: Option<i64>,
) -> ApiResult<Vec<dto::AuditEntry>> {
    let path = match since_seq {
        Some(s) => format!("/v1/audit?since_seq={s}"),
        None => "/v1/audit".to_string(),
    };
    let v = client::send_json(client::headers(
        http.get(client::url(base_url, &path)),
        tenant_b64,
        Some(access),
    ))?;
    let entries = v["entries"].as_array().ok_or_else(|| ApiError::Server {
        code: "malformed".into(),
        message: "audit response missing 'entries'".into(),
    })?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(dto::AuditEntry {
            seq: client::ji64(e, "seq")?,
            source: e
                .get("source")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            recorded_at: e.get("recorded_at").and_then(|x| x.as_i64()).unwrap_or(0),
            author_pubkey: e
                .get("author_pubkey")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        });
    }
    Ok(out)
}
