//! Admin/ops surface (`/v1/admin/*`): overview, tenant suspend/activate, account
//! disable (+ auth enforcement, anti-lockout), devices/sessions/invites/vaults/
//! objects/relay/keysets listings, read-only config (masked), seq-bump, migrations.
//! All require instance-admin (AdminCtx). ZK: metadata, not content.

mod common;

use common::{Identity, TestApp, make_identity, spawn_with};
use serde_json::{Value, json};
use unissh_server::ids::b64;
use unissh_storage::{CachePolicy, SyncTarget, VaultRecord};
use unissh_sync::{AuditObject, SyncObject};

const TID: &[u8] = b"tenant-admin-ops";

struct Admin {
    bearer: String,
    account_id: String,
}

async fn bootstrap_admin(app: &TestApp, tier: &str) -> (Identity, Admin) {
    let id = make_identity();
    let b: Value = app
        .client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "tier": tier, "display_name": "Genesis", "handle": "genesis"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let account_id = b["account_id"].as_str().unwrap().to_string();
    let bearer = app
        .login(TID, &id, &account_id, b["device_id"].as_str().unwrap())
        .await;
    (id, Admin { bearer, account_id })
}

/// Invite + register + login an editor member; returns (account_id, bearer).
async fn add_editor(app: &TestApp, admin_bearer: &str, handle: &str) -> (String, String) {
    let inv: Value = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "role": "editor" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let m = make_identity();
    let r: Value = app
        .client
        .post(format!("{}/v1/register", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "invite_token": inv["token"], "registration_payload": m.payload_b64,
            "registration_signature": m.sig_b64, "handle": handle,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let acct = r["account_id"].as_str().unwrap().to_string();
    let bearer = app
        .login(TID, &m, &acct, r["device_id"].as_str().unwrap())
        .await;
    (acct, bearer)
}

async fn get_json(app: &TestApp, path: &str, bearer: &str) -> Value {
    get_q(app, path, &[], bearer).await
}

/// Percent-encode a query value (base64 ids contain `+`/`/`/`=`).
fn pe(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// GET with URL-encoded query params.
async fn get_q(app: &TestApp, path: &str, query: &[(&str, &str)], bearer: &str) -> Value {
    let mut url = format!("{}{}", app.base, path);
    if !query.is_empty() {
        let qs: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{k}={}", pe(v)))
            .collect();
        url.push('?');
        url.push_str(&qs.join("&"));
    }
    app.client
        .get(url)
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Audit object authored by `author` (must equal genesis_owner to be accepted).
fn audit_obj(tag: u8, author: &[u8]) -> String {
    b64(&SyncObject::Audit(AuditObject {
        vault_id: vec![],
        entry_blob: vec![tag],
        signature: vec![1u8; 67],
        author_pubkey: author.to_vec(),
    })
    .to_bytes()
    .unwrap())
}

#[allow(dead_code)]
fn vault_b64(owner: u8, version: u64) -> String {
    b64(&SyncObject::Vault(VaultRecord {
        vault_id: b"vault-1".to_vec(),
        sync_target: SyncTarget::Cloud,
        name_blob: vec![1, 2, 3],
        wrapped_vk: vec![4, 5, 6],
        version,
        tombstone: false,
        signature: vec![9u8; 67],
        author_pubkey: vec![owner; 32],
        key_epoch: 1,
        cache_policy: CachePolicy::OfflineAllowed,
        sync_tenant: Vec::new(),
    })
    .to_bytes()
    .unwrap())
}

// ---- overview + tenant lifecycle ----

#[tokio::test]
async fn suspend_blocks_then_admin_reactivates() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let ov = get_json(&app, "/v1/admin/overview", &a.bearer).await;
    assert_eq!(ov["status"], "active");
    assert_eq!(ov["admins"], 1);
    assert_eq!(ov["devices"], 1);

    let suspend = |suspended: bool| {
        app.client
            .post(format!("{}/v1/admin/tenant/status", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "suspended": suspended }))
            .send()
    };
    assert_eq!(suspend(true).await.unwrap().status(), 204);

    // a normal AuthCtx endpoint is now blocked (tenant_suspended)
    let v = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 403);

    // AdminCtx bypasses the suspended-gate → can reactivate
    assert_eq!(suspend(false).await.unwrap().status(), 204);

    let v2 = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    assert_eq!(v2.status(), 200, "sync works again after reactivate");
}

#[tokio::test]
async fn non_admin_cannot_reach_admin() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;
    let (_acct, editor_bearer) = add_editor(&app, &a.bearer, "ed").await;

    let r = app
        .client
        .get(format!("{}/v1/admin/overview", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {editor_bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "editor is not instance-admin");
}

// ---- account disable + enforcement + anti-lockout ----

#[tokio::test]
async fn disable_account_blocks_sessions_with_anti_lockout() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;
    let (bob_acct, bob_bearer) = add_editor(&app, &a.bearer, "bob").await;

    let bob_version = |bearer: &str| {
        app.client
            .get(format!("{}/v1/sync/version", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {bearer}"))
            .send()
    };
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 200);

    let set_status = |acct: &str, disabled: bool| {
        app.client
            .post(format!("{}/v1/admin/account/status", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "account_id": acct, "disabled": disabled }))
            .send()
    };
    assert_eq!(set_status(&bob_acct, true).await.unwrap().status(), 204);

    // bob's existing session is now rejected
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 401);

    // re-enable → works again
    assert_eq!(set_status(&bob_acct, false).await.unwrap().status(), 204);
    assert_eq!(bob_version(&bob_bearer).await.unwrap().status(), 200);

    // cannot disable the genesis owner
    assert_eq!(
        set_status(&a.account_id, true).await.unwrap().status(),
        403,
        "genesis owner cannot be disabled"
    );
}

// ---- devices / sessions ----

#[tokio::test]
async fn devices_sessions_list_and_revoke() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let devs = get_q(
        &app,
        "/v1/admin/devices",
        &[("account_id", &a.account_id)],
        &a.bearer,
    )
    .await;
    let darr = devs["devices"].as_array().unwrap();
    assert_eq!(darr.len(), 1);
    assert_eq!(darr[0]["status"], "active");
    assert_eq!(darr[0]["active_sessions"], 1);

    let sess = get_json(&app, "/v1/admin/sessions", &a.bearer).await;
    let sarr = sess["sessions"].as_array().unwrap();
    assert_eq!(sarr.len(), 1);
    let sid = sarr[0]["session_id"].as_str().unwrap().to_string();

    // revoke that session
    let r = app
        .client
        .post(format!("{}/v1/admin/session/revoke", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "session_id": sid }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // that bearer is now dead, and the active-sessions list is empty
    let dead = app
        .client
        .get(format!("{}/v1/admin/overview", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    assert_eq!(
        dead.status(),
        401,
        "revoked session can no longer authenticate"
    );
}

// ---- invites ----

#[tokio::test]
async fn invites_list_and_revoke() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let inv: Value = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "role": "editor", "scope": "team-a" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = inv["token"].as_str().unwrap().to_string();
    let invite_id = inv["invite_id"].as_str().unwrap().to_string();

    let list = get_json(&app, "/v1/admin/invites", &a.bearer).await;
    let arr = list["invites"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["state"], "pending");
    assert_eq!(arr[0]["role"], "editor");
    assert_eq!(arr[0]["scope"], "team-a");

    // revoke
    let rv = app
        .client
        .post(format!("{}/v1/admin/invite/revoke", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "invite_id": invite_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(rv.status(), 204);

    let list2 = get_json(&app, "/v1/admin/invites", &a.bearer).await;
    assert_eq!(list2["invites"][0]["state"], "revoked");

    // redeeming the revoked token now fails (gone)
    let redeem = app
        .client
        .post(format!("{}/v1/invite/redeem", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({ "invite_token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(redeem.status(), 410);
}

// ---- vaults ----

#[tokio::test]
async fn vaults_listing() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let vault_id = b64(b"vault-x");
    let claim = app
        .client
        .post(format!("{}/v1/vaults/claim", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "vault_id": vault_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(claim.status(), 200);

    let list = get_json(&app, "/v1/admin/vaults", &a.bearer).await;
    let arr = list["vaults"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["vault_id"], vault_id);

    let detail = get_q(
        &app,
        "/v1/admin/vault",
        &[("vault_id", &vault_id)],
        &a.bearer,
    )
    .await;
    assert_eq!(detail["vault_id"], vault_id);
    assert_eq!(detail["tombstone"], false);
}

// ---- objects metadata (ZK: no content leak) ----

#[tokio::test]
async fn objects_metadata_no_content_leak() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (id, a) = bootstrap_admin(&app, "personal").await;

    // push 2 objects through the real sync path (audit author == genesis owner)
    let author = id.ed.to_vec();
    let push = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "objects": [audit_obj(1, &author), audit_obj(2, &author)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 200);

    // page 1: limit 1
    let p1 = get_q(&app, "/v1/admin/objects", &[("limit", "1")], &a.bearer).await;
    let items = p1["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["server_seq"], 1);
    assert!(items[0]["blob_len"].as_i64().unwrap() > 0);
    assert_eq!(p1["has_more"], true);
    assert_eq!(p1["next_cursor"], 1);
    // ZK: NO raw bytes
    assert!(items[0].get("object").is_none());
    assert!(items[0].get("object_bytes").is_none());

    // page 2: follow cursor
    let p2 = get_q(
        &app,
        "/v1/admin/objects",
        &[("limit", "1"), ("cursor", "1")],
        &a.bearer,
    )
    .await;
    assert_eq!(p2["items"][0]["server_seq"], 2);
}

// ---- relay / keysets observation ----

#[tokio::test]
async fn relay_and_keysets_observation() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    // open a relay channel
    let resp = app
        .client
        .post(format!("{}/v1/relay/open", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .send()
        .await
        .unwrap();
    let st = resp.status();
    let open: Value = resp.json().await.unwrap();
    assert_eq!(st, 200, "relay/open failed: {open}");
    let chan = open["channel_id"].as_str().unwrap().to_string();

    let relay = get_json(&app, "/v1/admin/relay", &a.bearer).await;
    let chans = relay["channels"].as_array().unwrap();
    assert_eq!(chans.len(), 1);
    assert_eq!(chans[0]["channel_id"], chan);
    assert!(
        chans[0].get("msg1").is_none(),
        "ZK: relay messages not exposed"
    );

    // fresh account has no keyset generations
    let ks = get_q(
        &app,
        "/v1/admin/keysets",
        &[("account_id", &a.account_id)],
        &a.bearer,
    )
    .await;
    assert_eq!(ks["keysets"].as_array().unwrap().len(), 0);
}

// ---- config (read-only, masked) ----

#[tokio::test]
async fn config_masks_secrets() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.server.tls_key = "PRIVATEKEY".into();
    })
    .await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let cfg = get_json(&app, "/v1/admin/config", &a.bearer).await;
    assert_eq!(cfg["server"]["tls_key"], "***", "secret masked");
    assert_eq!(cfg["bootstrap"]["token"], "", "empty secret stays empty");
    assert_eq!(cfg["db"]["url"], "***", "db url (may carry creds) masked");
    assert_eq!(
        cfg["limits"]["max_objects_per_push"], 1000,
        "non-secret visible"
    );
}

// ---- seq-bump over HTTP ----

#[tokio::test]
async fn seq_bump_http_raises_only() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let bump = |body: Value| {
        app.client
            .post(format!("{}/v1/admin/seq-bump", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&body)
            .send()
    };

    let r1: Value = bump(json!({ "by": 1000 }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r1["old"], 0);
    assert_eq!(r1["new"], 1000);

    let v = get_json(&app, "/v1/sync/version", &a.bearer).await;
    assert_eq!(v["report_version"], 1000);

    // `to` below current never lowers
    let r2: Value = bump(json!({ "to": 1 }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2["old"], 1000);
    assert_eq!(r2["new"], 1000);
}

// ---- migrations ----

#[tokio::test]
async fn migrations_listed() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let m = get_json(&app, "/v1/admin/migrations", &a.bearer).await;
    let arr = m["migrations"].as_array().unwrap();
    assert!(
        arr.len() >= 2,
        "at least 0001_init + 0002_accounts_identity"
    );
    assert!(arr[0]["version"].as_i64().unwrap() <= arr[1]["version"].as_i64().unwrap());
}

// ---- audit tamper-evident hash-chain ----

#[tokio::test]
async fn audit_chain_verifies_and_detects_tampering() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (id, a) = bootstrap_admin(&app, "personal").await;

    // generate a few audit rows: bootstrap_admin + login already wrote 2;
    // a client-signed audit append adds one more (author == genesis).
    let obj = audit_obj(7, &id.ed);
    let ap = app
        .client
        .post(format!("{}/v1/audit", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "audit_object": obj }))
        .send()
        .await
        .unwrap();
    assert_eq!(ap.status(), 201);

    let v = get_json(&app, "/v1/admin/audit/verify", &a.bearer).await;
    assert_eq!(v["ok"], true, "intact chain verifies");
    assert!(v["count"].as_i64().unwrap() >= 3);
    assert!(v["broken_at"].is_null());
    assert!(v["head_hash"].is_string());

    // tamper a row directly in the store → chain must break at that seq
    app.state
        .store
        .exec(
            "UPDATE audit_log SET entry_blob = ? WHERE tenant_id = ? AND seq = 1",
            vec![
                unissh_server::store::Val::B(b"TAMPERED".to_vec()),
                unissh_server::store::Val::b(TID),
            ],
        )
        .await
        .unwrap();

    let v2 = get_json(&app, "/v1/admin/audit/verify", &a.bearer).await;
    assert_eq!(v2["ok"], false, "tampering detected");
    assert_eq!(v2["broken_at"], 1);
}

// ---- config hot-reload (validate_signatures) + metrics summary ----

#[tokio::test]
async fn config_hot_reload_toggles_signature_validation() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;

    let push_forged = || {
        // org-tier Vault with a bogus signature — rejected only when validate is on
        app.client
            .post(format!("{}/v1/sync/push", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "objects": [vault_b64(0xAA, 1)] }))
            .send()
    };

    let put_validate = |on: bool| {
        app.client
            .put(format!("{}/v1/admin/config", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {}", a.bearer))
            .json(&json!({ "validate_signatures": on }))
            .send()
    };

    // harness default: validate_signatures = false → forged push accepted
    assert_eq!(push_forged().await.unwrap().status(), 200);

    // hot-enable validation → forged push now rejected (no restart)
    let p = put_validate(true).await.unwrap();
    assert_eq!(p.status(), 200);
    let body: Value = p.json().await.unwrap();
    assert_eq!(body["validate_signatures"], true);
    assert!(push_forged().await.unwrap().status().is_client_error());

    // GET reflects the live value
    let cfg = get_json(&app, "/v1/admin/config", &a.bearer).await;
    assert_eq!(cfg["sync"]["validate_signatures"], true);

    // hot-disable again → accepted
    assert_eq!(put_validate(false).await.unwrap().status(), 200);
    assert_eq!(push_forged().await.unwrap().status(), 200);
}

#[tokio::test]
async fn metrics_summary_reports_disabled_in_harness() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (_id, a) = bootstrap_admin(&app, "org").await;
    let m = get_json(&app, "/v1/admin/metrics", &a.bearer).await;
    // harness builds state with metrics=None
    assert_eq!(m["enabled"], false);
    assert!(m["prometheus"].is_null());
}

// ---- whole-DB-snapshot anti-rollback generation (§16) ----

#[tokio::test]
async fn instance_generation_tracks_writes() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let (id, a) = bootstrap_admin(&app, "personal").await;

    let ov0 = get_json(&app, "/v1/admin/overview", &a.bearer).await;
    assert_eq!(ov0["instance_generation"], 0);

    // push 2 objects → next_seq 0→2 → instance generation 2
    let author = id.ed.to_vec();
    let push = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {}", a.bearer))
        .json(&json!({ "objects": [audit_obj(1, &author), audit_obj(2, &author)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(push.status(), 200);

    let inst = get_json(&app, "/v1/admin/instance", &a.bearer).await;
    assert_eq!(inst["generation"], 2);
    assert_eq!(inst["min_floor"], 0);

    let ov1 = get_json(&app, "/v1/admin/overview", &a.bearer).await;
    assert_eq!(ov1["instance_generation"], 2);
}
