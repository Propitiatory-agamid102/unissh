//! Регрессия BLOCKER (data-loss): записи, созданные ПОСЛЕ перехода волта в
//! membership-режим, должны нести актуальную `key_epoch` (>= пол, manifest@epoch),
//! иначе `verify_record_authority` отвергает их как downgrade (`EpochInvalid`) и
//! item навсегда нечитаем. До фикса `put_item`/`put_item_keep_history`/
//! `tombstone_record` штамповали жёстко `key_epoch=0`.

use unissh_keychain::{create_account, KdfParams, UnlockedKeyset};
use unissh_storage::{MemberRole, Storage};
use unissh_vault::{Member, Vault};

fn keyset() -> UnlockedKeyset {
    let (_sk, _rec, unlocked) = create_account(None, KdfParams::recommended()).unwrap();
    unlocked
}
fn storage() -> Storage {
    Storage::open_in_memory(&[7u8; 32]).unwrap()
}
fn ed_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.signing.verifying.to_bytes().to_vec()
}
fn x_of(ks: &UnlockedKeyset) -> Vec<u8> {
    ks.encryption.public.to_bytes().to_vec()
}

/// BLOCKER: после установления членства (owner=Admin) и переоткрытия волта новый
/// `put_item` обязан round-trip'иться через `get_item`. До фикса возвращал
/// `EpochInvalid` (item на key_epoch=0 при membership@1).
#[test]
fn put_item_after_membership_roundtrips() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let owner_x = x_of(&owner);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    let vid = v.vault_id().to_vec();

    let members = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let xkeys = vec![(owner_ed.clone(), owner_x.clone())];
    let epoch = v
        .establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();
    assert_eq!(epoch, 1);
    drop(v);

    // Переоткрываем волт и кладём НОВЫЙ item — он должен попасть на актуальную
    // эпоху и читаться обратно.
    let v2 = Vault::open(&st, &owner, &vid).unwrap();
    v2.put_item(b"secret", 1, b"top-secret").unwrap();
    let got = v2
        .get_item(b"secret")
        .expect("get_item must not error")
        .expect("item must exist");
    assert_eq!(got.content.as_slice(), b"top-secret");

    // put_item_keep_history тоже.
    v2.put_item_keep_history(b"pwd", 2, b"hunter2").unwrap();
    let pwd = v2.get_item(b"pwd").unwrap().unwrap();
    assert_eq!(pwd.content.as_slice(), b"hunter2");

    // tombstone (delete_item) тоже должен быть авторизован (verify_chain зелёный).
    v2.delete_item(b"secret").unwrap();
    let report = v2.verify_chain().unwrap();
    assert!(report.ok, "verify_chain должен быть зелёным: {:?}", report);
}

/// После `rotate_vk` НОВЫЙ `put_item` (на переоткрытом под VK' волте) обязан
/// round-trip'иться. До фикса записывался на key_epoch=0 < пол → EpochInvalid.
#[test]
fn put_item_after_rotate_vk_roundtrips() {
    let st = storage();
    let owner = keyset();
    let owner_ed = ed_of(&owner);
    let owner_x = x_of(&owner);

    let v = Vault::create(&st, &owner, b"mv".to_vec(), b"shared").unwrap();
    let vid = v.vault_id().to_vec();

    let members = vec![Member {
        ed25519_pub: owner_ed.clone(),
        role: MemberRole::Admin,
    }];
    let xkeys = vec![(owner_ed.clone(), owner_x.clone())];
    v.establish_or_extend_membership(&owner, &members, &xkeys)
        .unwrap();

    let grants = vec![(owner_x.clone(), owner_ed.clone(), MemberRole::Admin)];
    let new_epoch = v.rotate_vk(&owner, &members, &grants).unwrap();
    assert_eq!(new_epoch, 2);
    drop(v);

    // Переоткрываем под VK' (текущая обёртка владельца на эпохе 2) и кладём новый
    // item — должен встать на эпоху 2 (>= пол=2, manifest@2) и читаться.
    let v2 = Vault::open(&st, &owner, &vid).unwrap();
    v2.put_item(b"fresh", 1, b"after-rotation").unwrap();
    let got = v2.get_item(b"fresh").unwrap().unwrap();
    assert_eq!(got.content.as_slice(), b"after-rotation");

    // Записанный item несёт key_epoch=2 (актуальная эпоха волта), не 0.
    let rec = st.get_item(&vid, b"fresh").unwrap().unwrap();
    assert_eq!(rec.key_epoch, 2);

    let report = v2.verify_chain().unwrap();
    assert!(report.ok, "verify_chain должен быть зелёным: {:?}", report);
}
