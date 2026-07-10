//! Cross-tenant ops surface (`/v1/ops/*`): token auth (`X-UniSSH-Ops-Token`),
//! list/suspend tenants across the instance, instance overview, cross-tenant
//! seq-bump. Server-trusted, not keyset, not per-tenant.

mod common;

use common::{TestApp, make_identity, spawn_with};
use serde_json::{Value, json};
use unissh_server::ids::b64;

const TID_A: &[u8] = b"tenant-ops-aaa";
const TID_B: &[u8] = b"tenant-ops-bbb";

async fn bootstrap(app: &TestApp, tid: &[u8]) {
    let id = make_identity();
    let r = app
        .client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(tid))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "tier": "org", "handle": "genesis"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
}

async fn ops_get(app: &TestApp, path: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = app.client.get(format!("{}{}", app.base, path));
    if let Some(t) = token {
        req = req.header("X-UniSSH-Ops-Token", t);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn ops_token_gates_cross_tenant_console() {
    let app = spawn_with(|c| {
        c.bootstrap.allow_open = true;
        c.ops.token = "opssecret".into();
    })
    .await;
    bootstrap(&app, TID_A).await;
    bootstrap(&app, TID_B).await;

    // missing token → 401; wrong token → 401
    assert_eq!(ops_get(&app, "/v1/ops/tenants", None).await.status(), 401);
    assert_eq!(
        ops_get(&app, "/v1/ops/tenants", Some("nope"))
            .await
            .status(),
        401
    );

    // correct token → both tenants listed
    let list: Value = ops_get(&app, "/v1/ops/tenants", Some("opssecret"))
        .await
        .json()
        .await
        .unwrap();
    let arr = list["tenants"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let ids: Vec<&str> = arr
        .iter()
        .map(|t| t["tenant_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&b64(TID_A).as_str()));
    assert!(ids.contains(&b64(TID_B).as_str()));

    // instance overview
    let ov: Value = ops_get(&app, "/v1/ops/overview", Some("opssecret"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ov["tenants"], 2);
    assert_eq!(ov["accounts"], 2);
    assert_eq!(ov["objects"], 0);

    // suspend tenant B cross-tenant
    let s = app
        .client
        .post(format!("{}/v1/ops/tenant/status", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .json(&json!({ "tenant_id": b64(TID_B), "suspended": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(s.status(), 204);

    // reflected in the listing
    let list2: Value = ops_get(&app, "/v1/ops/tenants", Some("opssecret"))
        .await
        .json()
        .await
        .unwrap();
    let b = list2["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tenant_id"] == b64(TID_B))
        .unwrap();
    assert_eq!(b["status"], "suspended");

    // cross-tenant seq-bump on B
    let bump: Value = app
        .client
        .post(format!("{}/v1/ops/seq-bump", app.base))
        .header("X-UniSSH-Ops-Token", "opssecret")
        .json(&json!({ "tenant_id": b64(TID_B), "by": 5 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bump["bumped"][0]["new"], 5);
}

#[tokio::test]
async fn ops_disabled_when_no_token_configured() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await; // ops.token empty
    bootstrap(&app, TID_A).await;
    // any token presented → still disabled (403)
    assert_eq!(
        ops_get(&app, "/v1/ops/tenants", Some("anything"))
            .await
            .status(),
        403
    );
}
