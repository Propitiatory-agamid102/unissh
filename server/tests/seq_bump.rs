//! Anti-rollback restore runbook (§14.3): seq-bump raises next_seq and NEVER
//! lowers it — otherwise clients get report_version < cursor → TransportRollback.

use unissh_server::store::Store;

async fn store() -> Store {
    let s = Store::connect_sqlite(":memory:", 1).await.unwrap();
    s.migrate().await.unwrap();
    s
}

const T1: &[u8] = b"tenant-bump-aaaa";
const T2: &[u8] = b"tenant-bump-bbbb";

#[tokio::test]
async fn bump_by_raises_all_tenants() {
    let s = store().await;
    s.create_tenant(T1, "personal", 100).await.unwrap();
    s.create_tenant(T2, "personal", 100).await.unwrap();
    // advance T1 to 42 via pushes is overkill; set directly through bump_to
    s.bump_next_seq_to(T1, 42).await.unwrap();

    let ids = s.list_tenant_ids().await.unwrap();
    assert_eq!(ids.len(), 2);

    for id in &ids {
        s.bump_next_seq_by(id, 100_000).await.unwrap();
    }
    assert_eq!(s.report_version(T1).await.unwrap(), 100_042);
    assert_eq!(s.report_version(T2).await.unwrap(), 100_000);
}

#[tokio::test]
async fn bump_to_never_lowers() {
    let s = store().await;
    s.create_tenant(T1, "personal", 100).await.unwrap();
    s.bump_next_seq_to(T1, 500).await.unwrap();
    assert_eq!(s.report_version(T1).await.unwrap(), 500);

    // target below current → no change (monotonic)
    let (old, new) = s.bump_next_seq_to(T1, 50).await.unwrap();
    assert_eq!((old, new), (500, 500));
    assert_eq!(
        s.report_version(T1).await.unwrap(),
        500,
        "must never lower next_seq"
    );

    // target above current → raised
    let (old, new) = s.bump_next_seq_to(T1, 900).await.unwrap();
    assert_eq!((old, new), (500, 900));
}
