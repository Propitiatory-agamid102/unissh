# unissh-ffi

FFI-граница ядра UniSSH (ТЗ 4) на **UniFFI**. Фасад `Core` связывает `keychain`,
`storage`, `vault`, `ssh-agent`, `ssh-transport` в стабильный контракт для UI
(Swift/Kotlin/…).

## Жёсткое ограничение

**UI/FFI никогда не получает plaintext-ключи.** Приватные SSH-ключи
генерируются и живут в ядре; наружу отдаётся только **публичный** ключ. Нет ни
одного метода, возвращающего приватный ключ или секрет keyset. Проверяется
тестом `tests/e2e.rs::private_key_never_stored_in_plaintext` (на диске — только
шифротекст; приватник не утекает).

Секреты, пересекающие границу по явному запросу, — **пароль сервера**
(`get_password`) и **текст заметки** (`get_note`), reveal для показа/копирования
в UI. Это пользовательские секреты уровня менеджера паролей, не ключевой
материал; каждый reveal строго type-gated — для item другого типа (в т.ч.
приватного ключа) вызов отказывает (тесты `get_password_refuses_non_password_items`,
`get_note_is_type_gated`).

## Контракт (основное)

```text
Core::new(db_path, keyset_path)
create_account(password?) -> SecretKeyHex      // Emergency Kit (один раз)
unlock(password?, secret_key_hex)
lock() / is_unlocked()
change_password(old_password?, new_password?, secret_key_hex)  // re-wrap keyset; не требует unlock

// волты
create_vault(vault_id, name) / list_vaults()
rename_vault(vault_id, new_name) / delete_vault(vault_id)

// ключи/items
generate_ssh_key(vault_id, item_id) -> public  // приватник в волт, наружу публичный
import_ssh_key(vault_id, item_id, openssh_private) -> public   // Ed25519/ECDSA/RSA
import_ssh_certificate(vault_id, key_item_id, cert_openssh)    // cert-auth (CA)
get_public_key(vault_id, item_id) -> {openssh, fingerprint}    // перечитать публичный ключ
rename_item(vault_id, item_id, new_item_id) / delete_item(vault_id, item_id)
list_items(vault_id) -> [{item_id, item_type, version, created_at, updated_at, has_certificate}]

// пароли серверов (item-ы типа 4; контент — UTF-8 байты пароля)
save_password(vault_id, item_id, password)
get_password(vault_id, item_id) -> password    // reveal; только для item типа «пароль»

// зашифрованные заметки (item-ы типа 6; произвольный UTF-8)
save_note(vault_id, item_id, text)
get_note(vault_id, item_id) -> text            // reveal; только для item типа «заметка»

// known_hosts (TOFU)
list_known_hosts() / forget_host(host, port)
trust_host(host, port, expected_fingerprint) -> fingerprint  // доверять новому ключу (со сверкой)

// auth: AuthMethod::Agent{key_item_id} | Password{password} | VaultPassword{password_item_id}
//   VaultPassword: ядро само расшифровывает пароль-item при коннекте (plaintext не идёт через FFI)
//   jumps[]: JumpHost{host, port, user, auth} — на каждом хопе свой способ
ssh_exec(host, port, user, vault_id, auth, command, jumps[]) -> {stdout, stderr, exit}
// multi-exec: max_concurrency (0=без лимита), timeout_secs (0=без таймаута, per-host)
ssh_exec_multi(targets[], command, max_concurrency, timeout_secs)
    -> [{host, stdout, stderr, exit, error?, duration_ms, timed_out}]  // конкурентно
open_session(host, port, user, vault_id, auth, jumps[], term, cols, rows, observer)
    -> SshSession            // интерактивный PTY; вывод в observer (callback). cols,rows > 0
SshSession::{write(data), resize(cols, rows), close()}  // resize — best-effort (без ack сервера)
SessionObserver::{on_data(bytes), on_close(exit)}   // реализует UI

// группы хостов (item-ы типа 5; только ссылки на профили/вложенные группы)
// ServerGroup{group_id, label, member_ids[], parent_id?} — parent_id для дерева папок в UI
save_group(vault_id, group) / list_groups(vault_id) / get_group(vault_id, group_id)
delete_group(vault_id, group_id)
ssh_exec_group(vault_id, group_id, command, max_concurrency, timeout_secs) -> [MultiExecResult]
    // раскрывает вложенные группы (visited-set + лимит глубины); висячие/цикл/prompt → error-маркер
dry_run_group(vault_id, group_id) -> [{member_id, host, port, user, status}]
    // резолв БЕЗ коннекта/ключей/паролей; status: Ok|Dangling|PromptPassword|CycleSkipped

// теги профилей (ConnectionProfile.tags[]; внутри зашифрованного профиля) — выборка, не RBAC
select_targets_by_tags(vault_id, tags[], match_all) -> [MultiExecTarget]
ssh_exec_by_tags(vault_id, tags[], match_all, command, max_concurrency, timeout_secs) -> [MultiExecResult]

// туннели (живут до close)
open_local_forward(.., local_bind, remote_host, remote_port) -> SshTunnel
open_dynamic_forward(.., local_bind) -> SshTunnel       // SOCKS5 (только loopback!)
open_remote_forward(.., remote_bind, remote_port, local_host, local_port) -> SshTunnel
SshTunnel::{bind_address(), close()}

// SFTP (живёт до close)
open_sftp(host, port, user, vault_id, auth, jumps[]) -> SftpFfi
SftpFfi::{list_dir, read_file, write_file, remove, mkdir, rmdir, rename, stat, realpath, close}
// возобновляемые передачи с прогрессом/отменой (CancelToken, SftpProgressObserver)
SftpFfi::sftp_download(remote, local, offset, progress?, cancel?) -> completed: bool
SftpFfi::sftp_upload(local, remote, offset, progress?, cancel?) -> completed: bool   // без TRUNC при докачке
sftp_put_multi(targets[], remote_path, data, make_parent_dirs, max_concurrency, timeout_secs)
    -> [{host, error?}]   // fleet push: один blob на много хостов

// потоковый exec (раздельные stdout/stderr) и broadcast (cluster-ssh)
ssh_exec_stream(host, port, user, vault_id, auth, command, jumps[], ExecObserver) -> ExecHandleFfi
ExecHandleFfi::{write_stdin, wait_exit(timeout_ms), close}   // ExecObserver: on_stdout/on_stderr/on_exit
open_broadcast(targets[], term, cols, rows, BroadcastObserver) -> BroadcastSession
BroadcastSession::{write_all, resize_all, close, statuses}   // один ввод → N PTY; вывод тегирован индексом
open_reconnecting_session(.., max_retries, backoff_ms, observer) -> ReconnectingSession
ReconnectingSession::{write, resize, reconnect, close, is_connected}  // авто-reconnect; HostKeyMismatch не реконнектится

// история версий секретов (пароль/заметка): хранится в item_history (V3), ретеншн 20, чистится при удалении
list_item_versions(vault_id, item_id) -> [version]   // только номера, без секретов
get_password_version(vault_id, item_id, version) -> password   // type-gated reveal версии
get_note_version(vault_id, item_id, version) -> text

// аудит и интероп
verify_vault_integrity(vault_id) -> {ok, checked, issues[{item_id, version, tombstone, failure}]}  // подписи всех items
check_consistency() -> {ok, integrity_ok, issues[]}   // integrity_check + орфаны + инварианты, без секретов
export_ssh_config(vault_id) -> text                   // инверс import_ssh_config
import_known_hosts(text) -> {imported, skipped_hashed, skipped_invalid}   // канонизация ключа как у пиннинга
import_putty_sessions(vault_id, reg_text) -> {created_ids[], skipped}     // .reg → профили

// зашифрованный бэкап волта (портативный файл, НЕ синк; passphrase+Argon2id)
export_vault(vault_id, passphrase) -> bytes
import_vault(bytes, passphrase, new_vault_id)   // items пере-шифровываются под новый VK; неверная passphrase → ошибка

// профили соединений («хосты»; хранятся зашифрованными item-ами типа 3)
// ConnectionProfile.auth: ProfileAuth::Key{key_item_id} | VaultPassword{password_item_id}
//   | PromptPassword (спросить при коннекте); ConnectionProfile.tags[] — метки выборки.
//   В JSON профиля — только ссылки; jump-хост с inline-паролем сохранить нельзя
//   (ошибка). Легаси-формат (без tags/password_item_id) читается без миграции.
save_connection(vault_id, profile) / list_connections(vault_id)
get_connection(vault_id, profile_id) / delete_connection(vault_id, profile_id)
import_ssh_config(vault_id, config_text) -> [created_profile_ids]

// ошибки: HostKeyMismatch{host, port, fingerprint} выделена для UI-предупреждения о MITM
```

### Веха-2 (cloud-волты, членство, identity, синк)

Эти методы открывают наружу операции Веха-2 (server-tz §2–§9, §13). **Граница
приватных ключей не меняется:** наружу идут только публичные ключи + fingerprints,
непрозрачные подписанные/зашифрованные блобы (`Vec<u8>`) и типизированные отчёты;
VK, per-item-ключи и приватные ключи keyset границу не пересекают. **cloud
`vault_id` — hex** (UUIDv4 — не-UTF8 байты; local-методы оставляют UTF-8 id).

```text
// === Веха-2 (cloud-волты, членство, identity, синк) ===
// cloud-волты (vault_id — hex UUIDv4)
create_cloud_vault(name) -> vault_id_hex                 // SyncTarget::Cloud
get_cache_policy(vault_id) / set_cache_policy(vault_id, policy)   // server-tz §6.6

// членство/гранты (ключи членов — hex, ПУБЛИЧНЫЕ; VK наружу не идёт)
add_member(vault_id, member_ed25519_pub, member_x25519_pub, role)
list_members(vault_id) -> [{ed25519_pub_hex, role, fingerprint}]
member_fingerprint(ed25519_pub) -> hex(SHA-256)          // OOB-confirm
confirm_member_pin(account_id, ed25519_pub)              // TOFU-пиннинг
rotate_vk(vault_id, [remaining]) -> new_epoch            // eager VK-ротация (отзыв)
purge_vault(vault_id)                                    // кооперативный hard-delete
verify_chain(vault_id) -> {ok, checked, issues}          // member-aware аудит

// identity/auth (наружу — публичные ключи/подписи/блобы, НЕ секреты)
account_id() -> hex                                      // server-tz §2.1
build_registration() -> bytes                            // self-attested блоб
sign_server_challenge(host, account_id, device_id, key_id, nonce, expiry) -> sig

// онбординг устройства
unlock_from_server_blob(keyset_blob, password?, secret_key_hex)   // Path A
OnboardInitiatorHandle::start(code) -> handle; handle.msg() -> msg1   // Path B (initiator)
Core::onboard_confirm_and_seal(handle, msg2) -> msg3
OnboardResponderHandle::respond(code, msg1) -> handle; handle.msg() -> msg2   // Path B (responder)
Core::onboard_finish_install(handle, msg3, password?)

// аудит (server-tz §8) — блобы непрозрачны, подпись делает слой выше
audit_append(vault_id, entry_blob, signature, author_pubkey) -> seq
audit_query(since_seq) -> [{seq, entry_blob, signature, author_pubkey_hex, recorded_at}]

// синк (server-tz §3) — коллбэк-интерфейс (приложение релеит непрозрачные блобы)
trait FfiSyncTransport { push_objects(objects)->[seq]; delta_since(cursor)->[item]; report_version()->u64 }
sync_now(transport) -> {applied, skipped_stale, conflicts, rejected, pushed}
```

#### Синк: коллбэк-интерфейс (решение)

`FfiSyncTransport` — UniFFI **callback interface** (foreign-реализуется
приложением, которое и ходит в сеть). Объекты синка пересекают границу как
непрозрачные байты (сериализованный `SyncObject`); ядро держит адаптер к
`unissh_sync::SyncTransport` и **верифицирует каждый объект перед применением**
(транспорт недоверенный — ни порядку, ни `server_seq`, ни содержимому веры нет).
Вариант «голые blob-операции без трейта» не используется — коллбэк точнее
отражает модель «сервер релеит блобы» и переиспользует уже принятый в крейте
механизм foreign-коллбэков (как `SessionObserver`).

#### Онбординг Path B: форма хэндлов (uniffi 0.31)

`#[uniffi::constructor]` в uniffi 0.31 возвращает только `Self`/`Arc<Self>`, не
произвольный Record. Поэтому `OnboardInitiatorHandle::start`/
`OnboardResponderHandle::respond` сразу выполняют PAKE-шаг и кладут исходящий
релей-блоб (`msg1`/`msg2`) **внутрь хэндла**; блоб берётся отдельным геттером
`handle.msg()`. Семантика плановой пары «handle + bytes» сохранена; состояние
одноразовое (повторный consume → типизированная ошибка).

**Аутентификация:** приватный ключ не покидает встроенный агент — подпись делает
агент (`russh::auth::Signer`); наружу из агента только публичный ключ.

**Локи:** Core держит внутренний лок только на время коннекта; `exec` и время
жизни интерактивной сессии — без него. Стриминг сессии полностью асинхронный
(фоновая задача → `SessionObserver`).

## Модель

Локальный инстанс = файл зашифрованной БД (`storage`, SQLCipher) + сайдкар с
зашифрованным keyset. Ключ SQLCipher выводится из секретов **распакованного**
keyset (HKDF) — открыть БД нельзя без разблокировки. SSH-сессии идут через
встроенный агент (ключ в агенте, не в UI). Async-операции russh выполняются на
внутреннем tokio-рантайме (методы синхронные/блокирующие — удобно для FFI).

## Генерация биндингов

UniFFI-фасад (`uniffi::setup_scaffolding!`) генерирует биндинги для
Swift/Kotlin/Python на лету; готовые артефакты в репозитории не хранятся:

```bash
cargo build -p unissh-ffi                      # собирает cdylib
cargo run -p unissh-ffi --bin uniffi-bindgen -- \
    generate --library target/debug/libunissh_ffi.so --language swift --out-dir <out-dir>
```

Контракт включает `Core`, `sshExec`, `generateSshKey`, `JumpHost`,
`SshExecResult` … UniFFI также умеет Kotlin/Python.

## CLI-харнесс

Крейт [`unissh-cli`](../cli) (бинарь `unissh`) использует этот фасад для сквозного
сценария из терминала: `init → create-vault → gen-key → exec` (с `--jump` для
ProxyJump).
