//! Account identity §6.1: human identifiers (display_name/handle),
//! instance-admin (promote/demote + anti-lockout), invite role=admin,
//! shared-keyset multi-device (devices/add + auth with a new device).

mod common;

use common::{Identity, make_identity, spawn_with};
use serde_json::{Value, json};
use unissh_server::ids::b64;

const TID: &[u8] = b"tenant-accts-001";

async fn bootstrap(
    app: &common::TestApp,
    id: &Identity,
    tier: &str,
    display_name: Option<&str>,
    handle: Option<&str>,
) -> Value {
    app.client
        .post(format!("{}/v1/bootstrap", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "registration_payload": id.payload_b64,
            "registration_signature": id.sig_b64,
            "tier": tier,
            "display_name": display_name,
            "handle": handle,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn accounts(app: &common::TestApp, bearer: &str) -> reqwest::Response {
    app.client
        .get(format!("{}/v1/accounts", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn bootstrap_carries_human_identity() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let admin = make_identity();
    let b = bootstrap(&app, &admin, "org", Some("Вася (admin)"), Some("vasya")).await;
    assert_eq!(b["role"], "admin");
    let bearer = app
        .login(
            TID,
            &admin,
            b["account_id"].as_str().unwrap(),
            b["device_id"].as_str().unwrap(),
        )
        .await;

    let list: Value = accounts(&app, &bearer).await.json().await.unwrap();
    let arr = list["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["display_name"], "Вася (admin)");
    assert_eq!(arr[0]["handle"], "vasya");
    assert_eq!(arr[0]["is_admin"], true);
    assert_eq!(arr[0]["member_pubkey"], b64(&admin.ed));
    // x25519_pub — open metadata, needed by the UI for HPKE re-wrap of the VK on grant rotation.
    assert_eq!(arr[0]["x25519_pub"], b64(&admin.x));
    assert_eq!(arr[0]["device_count"], 1);
}

#[tokio::test]
async fn invite_admin_then_promote_demote() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let admin = make_identity();
    let b = bootstrap(&app, &admin, "org", Some("Genesis"), None).await;
    let admin_bearer = app
        .login(
            TID,
            &admin,
            b["account_id"].as_str().unwrap(),
            b["device_id"].as_str().unwrap(),
        )
        .await;

    // admin issues an ADMIN invite → registered member becomes instance-admin
    let inv: Value = app
        .client
        .post(format!("{}/v1/invite", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let bob = make_identity();
    let r: Value = app
        .client
        .post(format!("{}/v1/register", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "invite_token": inv["token"], "registration_payload": bob.payload_b64,
            "registration_signature": bob.sig_b64, "display_name": "Bob", "handle": "bob",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["role"], "admin");
    let bob_acct = r["account_id"].as_str().unwrap().to_string();
    let bob_bearer = app
        .login(TID, &bob, &bob_acct, r["device_id"].as_str().unwrap())
        .await;

    // bob is instance-admin via invite → can list accounts
    assert_eq!(accounts(&app, &bob_bearer).await.status(), 200);

    // admin demotes bob
    let set = |bearer: &str, acct: &str, is_admin: bool| {
        app.client
            .post(format!("{}/v1/admin/set", app.base))
            .header("UniSSH-Tenant", b64(TID))
            .header("Authorization", format!("Bearer {bearer}"))
            .json(&json!({ "account_id": acct, "is_admin": is_admin }))
            .send()
    };
    assert_eq!(
        set(&admin_bearer, &bob_acct, false).await.unwrap().status(),
        204
    );
    assert_eq!(
        accounts(&app, &bob_bearer).await.status(),
        403,
        "demoted → not admin"
    );

    // re-promote
    assert_eq!(
        set(&admin_bearer, &bob_acct, true).await.unwrap().status(),
        204
    );
    assert_eq!(accounts(&app, &bob_bearer).await.status(), 200);

    // cannot demote the genesis admin
    let self_demote = set(&admin_bearer, b["account_id"].as_str().unwrap(), false)
        .await
        .unwrap();
    assert_eq!(self_demote.status(), 403, "genesis cannot be demoted");
}

#[tokio::test]
async fn second_device_shares_keyset_and_authenticates() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let acct = make_identity();
    let b = bootstrap(&app, &acct, "personal", Some("Игорь"), Some("igor")).await;
    let acct_id = b["account_id"].as_str().unwrap().to_string();
    let dev1 = b["device_id"].as_str().unwrap().to_string();
    let bearer1 = app.login(TID, &acct, &acct_id, &dev1).await;

    // add a second device under the same account (shares the keyset)
    let add: Value = app
        .client
        .post(format!("{}/v1/devices/add", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer1}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dev2 = add["device_id"].as_str().unwrap().to_string();
    assert_ne!(dev2, dev1);

    // the NEW device authenticates with the SAME keyset (shared identity)
    let bearer2 = app.login(TID, &acct, &acct_id, &dev2).await;
    let v = app
        .client
        .get(format!("{}/v1/sync/version", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {bearer2}"))
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), 200, "second device (shared keyset) can act");

    // device_count now 2 under one account (one member-id)
    let list: Value = accounts(&app, &bearer1).await.json().await.unwrap();
    assert_eq!(list["accounts"][0]["device_count"], 2);
    assert_eq!(
        list["accounts"].as_array().unwrap().len(),
        1,
        "still one account/identity"
    );
}

#[tokio::test]
async fn profile_update_and_handle_conflict() {
    let app = spawn_with(|c| c.bootstrap.allow_open = true).await;
    let admin = make_identity();
    let b = bootstrap(&app, &admin, "org", None, None).await;
    let admin_bearer = app
        .login(
            TID,
            &admin,
            b["account_id"].as_str().unwrap(),
            b["device_id"].as_str().unwrap(),
        )
        .await;

    // set own profile
    let upd = app
        .client
        .post(format!("{}/v1/account/profile", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "display_name": "Renamed", "handle": "chief" }))
        .send()
        .await
        .unwrap();
    assert_eq!(upd.status(), 204);
    let list: Value = accounts(&app, &admin_bearer).await.json().await.unwrap();
    assert_eq!(list["accounts"][0]["display_name"], "Renamed");
    assert_eq!(list["accounts"][0]["handle"], "chief");

    // another member takes a handle; admin trying to grab it → 409
    let bob = make_identity();
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
    app.client
        .post(format!("{}/v1/register", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .json(&json!({
            "invite_token": inv["token"], "registration_payload": bob.payload_b64,
            "registration_signature": bob.sig_b64, "handle": "bob",
        }))
        .send()
        .await
        .unwrap();

    let clash = app
        .client
        .post(format!("{}/v1/account/profile", app.base))
        .header("UniSSH-Tenant", b64(TID))
        .header("Authorization", format!("Bearer {admin_bearer}"))
        .json(&json!({ "handle": "bob" }))
        .send()
        .await
        .unwrap();
    assert_eq!(clash.status(), 409, "handle already taken");
}
