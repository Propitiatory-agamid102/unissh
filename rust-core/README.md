# UniSSH Core (Rust)

Универсальное Rust-ядро UniSSH — опенсорсного self-hosted
кроссплатформенного SSH-клиента с zero-knowledge шифрованными волтами.
**Этот репозиторий — только ядро** (библиотека): без сервера, без UI. Собирается
и тестируется автономно (без сети).

## Карта крейтов (Веха 1, шаги 1–7)

```
crates/
  crypto         примитивы, envelope-обёртки, AEAD+associated data, подписи,
                 версионирование блобов (crypto agility)            [ТЗ 5.4–5.5]
  keychain       Secret Key, Argon2id, Unlock Key, личный keyset    [ТЗ 5.1]
  storage        SQLite+SQLCipher, изоляция инстансов, модель синка  [ТЗ 2A, 9]
  vault          local-волт, Vault Key, per-item ключи              [ТЗ 5.2–5.3]
  ssh-agent      встроенный in-memory агент, mlock/zeroize           [ТЗ 10.1]
  ssh-transport  russh: ProxyJump, форварды, TOFU, ssh-config        [ТЗ 10.4]
  ffi            UniFFI-контракт для UI (без plaintext-ключей)       [ТЗ 4]
  cli            временный CLI-харнесс «пощупать ядро»
```

Каждый крейт — со своим README, документированным публичным API и тестами
(включая негативные). Зависимости снизу вверх; верхние переиспользуют нижние.

Веха 1 (шаги 1–7, Definition of Done из ТЗ) **выполнена**; поверх неё ядро
расширено набором локальных возможностей (см. ниже) — без сервера, сети и
нарушения жёстких правил.

## Возможности ядра

Всё — локально, на существующих крейтах, в sync-ready формате блобов.

- **Секреты в волте** (item-типы): SSH-ключи (генерация/импорт) и user-сертификаты,
  профили соединений («хосты»), **пароли серверов**, **зашифрованные заметки**,
  **группы хостов** (вложенные). Reveal паролей/заметок — строго type-gated
  (приватный ключ через него не достать).
- **История версий секретов** — прошлые версии пароля/заметки архивируются
  (ретеншн на item), reveal любой версии; история чистится при удалении.
- **Аутентификация:** ключом (через встроенный агент, приватник не покидает ядро),
  паролем (inline / из волта) с фолбэком на `keyboard-interactive`, сертификатом.
- **SSH-сессии:** интерактивный PTY с ресайзом; **потоковый exec** (раздельные
  stdout/stderr); **авто-reconnect** (backoff, MITM-стоп).
- **Fleet-операции:** мульти-хост exec с лимитом конкуренции и per-host таймаутом;
  запуск по **группе**, по **тегам**, dry-run; **broadcast** (один ввод → N PTY,
  cluster-ssh); **fleet-push** файла на много хостов по SFTP.
- **SFTP:** полный набор + **возобновляемые** download/upload с прогрессом и отменой.
- **Туннели:** local / remote / dynamic (SOCKS5), ProxyJump-цепочки.
- **Целостность/аудит:** `verify_chain` (проверка подписей всех версий, вкл.
  историю и tombstones) и `check_consistency` (структурная проверка БД) — без
  утечки секретов в отчёт.
- **Интероп:** импорт/экспорт `~/.ssh/config`, импорт `~/.ssh/known_hosts` и
  сессий **PuTTY** (`.reg`).
- **Бэкап:** портативный зашифрованный **экспорт/импорт волта** (passphrase +
  Argon2id), пере-шифрование под ключи целевого инстанса при импорте.

## Сборка и тесты

```bash
cargo build --workspace
cargo test  --workspace          # ~194 теста (вкл. интеграционные против sshd)
```

Требования: Rust 1.74+, C-тулчейн и системный OpenSSL (для bundled SQLCipher).
Интеграционные тесты `ssh-transport`/`ffi` поднимают локальный `sshd`
(нужны `sshd`/`ssh-keygen`).

## Сборка и CI

Часть монорепо [`goduni/unissh`](https://github.com/goduni/unissh): корневой
Cargo-workspace собирает ядро вместе с сервером, задачи оркеструет `just`
(`just build`, `just test`, `just lint`). CI в корне репозитория на каждый push/PR
прогоняет rustfmt, clippy и тесты (Linux, с локальным `sshd` для интеграционных)
плюс cargo-deny.

## Сквозной сценарий (локально, без сервера)

```bash
SK=$(cargo run -p unissh-cli -- init --password pw | tail -1)   # Secret Key (Emergency Kit)
cargo run -p unissh-cli -- create-vault --secret-key $SK --password pw --id default --name Default
cargo run -p unissh-cli -- gen-key      --secret-key $SK --password pw --vault default --item id_ed25519
cargo run -p unissh-cli -- exec --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy --command "uname -a" --jump bastion:22:admin:id_ed25519
# интерактивный терминал (PTY):
cargo run -p unissh-cli -- shell --secret-key $SK --password pw --vault default --item id_ed25519 \
    --host 10.0.0.5 --user deploy
```

Аутентификация идёт через `russh::auth::Signer` поверх встроенного агента —
приватный ключ не покидает агент. Интерактивная сессия (`open_session`/`SshSession`)
стримит вывод через callback `SessionObserver`.

## Гарантии безопасности

Своя крипта не пишется (RustCrypto/`hpke`/SQLCipher). Секреты зануляются;
plaintext приватных ключей на диск не пишется; страницы с ключом по возможности
`mlock`. Граница ядро↔UI **не отдаёт plaintext-ключи** — единственное
согласованное исключение — reveal паролей/заметок (пользовательские секреты, не
ключевой материал), строго type-gated. Версионирование блобов, подписанные
монотонные версии, tombstones и associated-data привязка заложены сразу под
будущий синк; те же подписи проверяет локальный аудит целостности (`verify_chain`).
Зашифрованный бэкап волта — портативный файл под passphrase (Argon2id), не синк.
Подробности — в README крейтов.

## Что НЕ здесь

Сервер-инстанс, сетевой синк, UI и всё ⏳ ПОТОМ из ТЗ (CA, relay, шеринг между
людьми, ротация VK, device-bound/FIDO2, key transparency, PQ-гибрид, CRDT,
P2P) — отдельные вехи. Точки расширения под них заложены, реализация — нет.

## Лицензия

Двойная лицензия — на выбор пользователя:

- MIT ([`LICENSE-MIT`](./LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE))

`SPDX-License-Identifier: MIT OR Apache-2.0`. Любой вклад принимается на условиях
этой двойной лицензии без дополнительных оговорок (Apache-2.0 §5).
