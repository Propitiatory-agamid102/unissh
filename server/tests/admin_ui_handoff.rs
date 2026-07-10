//! Server-side changes backing the admin-panel handoff (P1.2/P1.3/P1.4/P1.5/P2.6/
//! P2.8): /v1/admin/health, /v1/admin/metrics/summary, display_name in
//! /v1/ops/tenants, /v1/ops/account discoverability, CORS, hot-reload limits.

mod common;

use common::{Identity, TestApp, make_identity, spawn_with};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use unissh_server::Config;
use unissh_server::ids::b64;

const TID: &[u8] = b"tenant-handoff-xx";

async fn bootstrap_admin(app: &TestApp, handle: &str) -> (Identity, String, String) {
    let id = make_identity();
    let b: Value = app
        .client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "tier": "org", "display_name": "Genesis", "handle": handle,
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
    (id, account_id, bearer)
}

fn open_bootstrap(c: &mut Config) {
    c.bootstrap.allow_open = true;
}

// ---- P1.2 health ----

#[tokio::test]
async fn admin_health_reports_uptime_pool_janitor_tls() {
    let app = spawn_with(open_bootstrap).await;
    let (_id, _acct, bearer) = bootstrap_admin(&app, "genesis").await;

    // uptime grows with the clock; janitor last_run is wired to the atomic.
    app.clock.advance(50);
    app.state
        .last_janitor_run
        .store(app.now(), Ordering::Relaxed);

    let h: Value = app
        .client
        .get(format!("{}/v1/admin/health", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(h["status"], "ok");
    assert_eq!(h["uptime_seconds"], 50);
    assert_eq!(h["db"]["reachable"], true);
    assert_eq!(h["db"]["backend"], "sqlite");
    assert!(h["db"]["pool"]["max"].as_i64().unwrap() >= 1);
    assert!(h["db"]["pool"]["in_use"].as_i64().is_some());
    assert_eq!(h["janitor"]["last_run"], app.now());
    assert_eq!(h["tls"], "proxy"); // no in-process cert/key → terminated upstream
    assert!(h["version"].is_string());
}

#[tokio::test]
async fn admin_health_requires_admin() {
    let app = spawn_with(open_bootstrap).await;
    // Tenant exists, but no Authorization → 401 (AdminCtx checks tenant first,
    // then bearer).
    let _ = bootstrap_admin(&app, "genesis").await;
    let r = app
        .client
        .get(format!("{}/v1/admin/health", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

// ---- P1.3 metrics/summary (disabled path; recorder not installed in tests) ----

#[tokio::test]
async fn admin_metrics_summary_disabled_without_recorder() {
    let app = spawn_with(open_bootstrap).await;
    let (_id, _acct, bearer) = bootstrap_admin(&app, "genesis").await;
    let m: Value = app
        .client
        .get(format!("{}/v1/admin/metrics/summary", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["enabled"], false);
    assert!(m["series"].is_null());
}

// ---- P1.4 display_name in /v1/ops/tenants ----

async fn ops_set_profile(app: &TestApp, display_name: &str) -> reqwest::Response {
    app.client
        .post(format!("{}/v1/ops/tenant/profile", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .json(&json!({ "tenant_id": b64(TID), "display_name": display_name }))
        .send()
        .await
        .unwrap()
}

async fn ops_tenant0(app: &TestApp) -> Value {
    let list: Value = app
        .client
        .get(format!("{}/v1/ops/tenants", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    list["tenants"][0].clone()
}

#[tokio::test]
async fn ops_tenant_profile_sets_and_clears_display_name() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.ops.token = "opssecret".into();
    })
    .await;
    let _ = bootstrap_admin(&app, "genesis").await;

    // Initially null (no populate path until renamed).
    assert!(ops_tenant0(&app).await["display_name"].is_null());

    // Set via the real ops endpoint → reflected in /v1/ops/tenants.
    assert_eq!(ops_set_profile(&app, "Acme Org").await.status(), 204);
    let t = ops_tenant0(&app).await;
    assert_eq!(t["tenant_id"], b64(TID));
    assert_eq!(t["display_name"], "Acme Org");

    // Empty string clears it back to null.
    assert_eq!(ops_set_profile(&app, "   ").await.status(), 204);
    assert!(ops_tenant0(&app).await["display_name"].is_null());
}

#[tokio::test]
async fn ops_tenant_profile_auth_and_not_found() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.ops.token = "opssecret".into();
    })
    .await;
    let _ = bootstrap_admin(&app, "genesis").await;

    // Missing ops token → 401.
    let no_tok = app
        .client
        .post(format!("{}/v1/ops/tenant/profile", app.base))
        .json(&json!({ "tenant_id": b64(TID), "display_name": "X" }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_tok.status(), 401);

    // Unknown tenant → 404.
    let unknown = app
        .client
        .post(format!("{}/v1/ops/tenant/profile", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .json(&json!({ "tenant_id": b64(b"no-such-tenant!!"), "display_name": "X" }))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}

// ---- P1.5 /v1/ops/account?handle= discoverability ----

#[tokio::test]
async fn ops_account_lookup_by_handle() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.ops.token = "opssecret".into();
    })
    .await;
    let (_id, account_id, _bearer) = bootstrap_admin(&app, "chief").await;

    let r: Value = app
        .client
        .get(format!("{}/v1/ops/account?handle=chief", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let matches = r["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m["account_id"], account_id);
    assert_eq!(m["tenant_id"], b64(TID));
    assert_eq!(m["handle"], "chief");
    assert_eq!(m["is_admin"], true);
    // bootstrap registers exactly one device.
    assert_eq!(m["devices"].as_array().unwrap().len(), 1);
    assert!(m["devices"][0]["device_id"].is_string());

    // unknown handle → empty matches (not an error).
    let none: Value = app
        .client
        .get(format!("{}/v1/ops/account?handle=ghost", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(none["matches"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn ops_account_lookup_requires_ops_token() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.ops.token = "opssecret".into();
    })
    .await;
    let r = app
        .client
        .get(format!("{}/v1/ops/account?handle=chief", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

// ---- P2.6 CORS ----

#[tokio::test]
async fn cors_preflight_allowed_for_configured_origin() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.server.cors_allowed_origins = vec!["https://admin.example.com".into()];
    })
    .await;

    let resp = app
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/accounts", app.base),
        )
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "GET")
        .header(
            "Access-Control-Request-Headers",
            "authorization,unissh-tenant",
        )
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "preflight should short-circuit 2xx"
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "https://admin.example.com"
    );
    let allow_headers = resp
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allow_headers.contains("authorization"));
    assert!(allow_headers.contains("unissh-tenant"));
}

#[tokio::test]
async fn cors_absent_when_unconfigured() {
    let app = spawn_with(open_bootstrap).await;
    let resp = app
        .client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/v1/accounts", app.base),
        )
        .header("Origin", "https://admin.example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    // No CORS layer → no allow-origin header (preflight not honored).
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

// ---- P2.8 hot-reload object limits ----

#[tokio::test]
async fn config_hot_reload_object_limits_enforced() {
    let app = spawn_with(open_bootstrap).await;
    let (_id, _acct, bearer) = bootstrap_admin(&app, "genesis").await;
    let auth = || format!("Bearer {bearer}");

    // Shrink max_object_bytes via hot-reload.
    let put: Value = app
        .client
        .put(format!("{}/v1/admin/config", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", auth())
        .json(&json!({ "max_object_bytes": 10 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(put["max_object_bytes"], 10);

    // config_get reflects the live value.
    let cfg: Value = app
        .client
        .get(format!("{}/v1/admin/config", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", auth())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["limits"]["max_object_bytes"], 10);

    // A 100-byte object now exceeds the live cap → 413 (size checked before parse).
    let big = b64(&[0u8; 100]);
    let r = app
        .client
        .post(format!("{}/v1/sync/push", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", auth())
        .json(&json!({ "objects": [big] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        413,
        "object over hot-reloaded cap must be rejected"
    );

    // Zero is rejected as invalid.
    let bad = app
        .client
        .put(format!("{}/v1/admin/config", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", auth())
        .json(&json!({ "max_object_bytes": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
}
