-- UniSSH Server schema (SQLite dialect). Mirrors spec §4.
-- Conventions: ids/pubkeys/blobs = BLOB; all integers (seq/version/epoch/enum/
-- bool/ts) = INTEGER (i64 semantics); text = TEXT. Booleans stored as 0/1.

CREATE TABLE tenants (
  tenant_id            BLOB PRIMARY KEY,
  tier                 TEXT    NOT NULL,                 -- 'personal' | 'org'
  display_name         TEXT,
  next_seq             INTEGER NOT NULL DEFAULT 0,       -- monotonic server_seq counter (§4.3/§7.2)
  genesis_owner_pubkey BLOB,                             -- 32B Ed25519, fixed at /v1/bootstrap, immutable
  created_at           INTEGER NOT NULL,
  status               TEXT    NOT NULL DEFAULT 'active' -- 'active' | 'suspended'
);

CREATE TABLE accounts (
  tenant_id  BLOB    NOT NULL,
  account_id BLOB    NOT NULL,
  created_at INTEGER NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'active',          -- 'active' | 'disabled'
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE device_pubkeys (
  tenant_id     BLOB    NOT NULL,
  account_id    BLOB    NOT NULL,
  device_id     BLOB    NOT NULL,
  ed25519_pub   BLOB    NOT NULL,                         -- 32B canonical member-id
  x25519_pub    BLOB    NOT NULL,                         -- 32B for HPKE wraps
  registered_at INTEGER NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'active',        -- 'active' | 'revoked'
  PRIMARY KEY (tenant_id, device_id),
  UNIQUE (tenant_id, ed25519_pub),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, account_id)
);
CREATE INDEX idx_devpub_account ON device_pubkeys(tenant_id, account_id);

-- Append-only log of versioned blobs (§4.3). object_bytes verbatim; open columns derived.
CREATE TABLE objects (
  tenant_id     BLOB    NOT NULL,
  server_seq    INTEGER NOT NULL,                         -- per-tenant monotonic, server-assigned
  object_tag    INTEGER NOT NULL,                         -- 1=Vault..6=Keyset
  object_bytes  BLOB    NOT NULL,                         -- SyncObject::to_bytes(), verbatim
  vault_id      BLOB,
  item_id       BLOB,
  member_pubkey BLOB,
  obj_version   INTEGER,                                  -- signed version (NOT server_seq)
  key_epoch     INTEGER,
  tombstone     INTEGER,
  item_type     INTEGER,
  sync_target   INTEGER,
  cache_policy  INTEGER,
  role          INTEGER,
  author_pubkey BLOB,
  received_at   INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, server_seq),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX idx_obj_seq     ON objects(tenant_id, server_seq);
CREATE INDEX idx_obj_vault   ON objects(tenant_id, vault_id, obj_version);
CREATE INDEX idx_obj_logical ON objects(tenant_id, object_tag, vault_id, item_id, obj_version);

-- Denormalized latest vault snapshot for ownership/claim (§4.4).
CREATE TABLE vaults (
  tenant_id      BLOB    NOT NULL,
  vault_id       BLOB    NOT NULL,
  owner_pubkey   BLOB    NOT NULL,                         -- Ed25519 genesis creator (immutable)
  latest_version INTEGER NOT NULL,
  latest_epoch   INTEGER NOT NULL,
  sync_target    INTEGER NOT NULL,
  cache_policy   INTEGER NOT NULL,
  tombstone      INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, vault_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

-- Admin-signed membership manifests; one per (vault_id, key_epoch) — anti-equivocation (§4.5).
CREATE TABLE membership_manifests (
  tenant_id     BLOB    NOT NULL,
  vault_id      BLOB    NOT NULL,
  key_epoch     INTEGER NOT NULL,
  manifest_blob BLOB    NOT NULL,                          -- signed plaintext member-set (opaque)
  signature     BLOB    NOT NULL,
  author_pubkey BLOB    NOT NULL,
  server_seq    INTEGER NOT NULL,
  received_at   INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, vault_id, key_epoch),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

-- Per-member wrapped-VK grants (materialized ACL, §4.6).
CREATE TABLE membership_grants (
  tenant_id     BLOB    NOT NULL,
  vault_id      BLOB    NOT NULL,
  member_pubkey BLOB    NOT NULL,
  key_epoch     INTEGER NOT NULL,
  role          INTEGER NOT NULL,                          -- 0=Viewer 1=Editor 2=Admin
  wrapped_vk    BLOB    NOT NULL,                          -- HPKE seal VK (opaque)
  signature     BLOB    NOT NULL,
  author_pubkey BLOB    NOT NULL,
  not_after     INTEGER,                                   -- §9.7 live-grant; UNauthenticated server metadata
  revoked       INTEGER NOT NULL DEFAULT 0,                -- read-deny mark (§9.1); log stays intact
  server_seq    INTEGER NOT NULL,
  received_at   INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, vault_id, member_pubkey, key_epoch),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX idx_grants_epoch  ON membership_grants(tenant_id, vault_id, key_epoch);
CREATE INDEX idx_grants_member ON membership_grants(tenant_id, member_pubkey);

-- Append-only audit (§4.7). prev_hash reserved seam (§16 tamper-evident hash-chain).
CREATE TABLE audit_log (
  tenant_id     BLOB    NOT NULL,
  seq           INTEGER NOT NULL,                          -- server monotonic per-tenant
  source        TEXT    NOT NULL,                          -- 'client-signed' | 'server-observed'
  entry_blob    BLOB    NOT NULL,
  signature     BLOB,                                      -- NULL for server-observed
  author_pubkey BLOB,                                      -- NULL for server-observed
  vault_id      BLOB,
  recorded_at   INTEGER NOT NULL,
  server_seq    INTEGER,                                   -- link to objects log (client-signed)
  prev_hash     BLOB,                                      -- reserved (§16), unused in v1
  PRIMARY KEY (tenant_id, seq),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

-- Path A keyset blobs (§4.8). EncryptedKeyset verbatim; no-downgrade generation.
CREATE TABLE keyset_blobs (
  tenant_id    BLOB    NOT NULL,
  account_id   BLOB    NOT NULL,
  generation   INTEGER NOT NULL,
  keyset_bytes BLOB    NOT NULL,
  ed25519_pub  BLOB    NOT NULL,
  x25519_pub   BLOB    NOT NULL,
  uploaded_at  INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, account_id, generation),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, account_id)
);

-- Invites (§4.9). Only SHA-256(token) stored.
CREATE TABLE invites (
  tenant_id   BLOB    NOT NULL,
  invite_id   BLOB    NOT NULL,
  token_hash  BLOB    NOT NULL,
  role        INTEGER NOT NULL,
  scope       TEXT,
  expires_at  INTEGER NOT NULL,
  redeemed_by BLOB,
  redeemed_at INTEGER,
  state       TEXT    NOT NULL DEFAULT 'pending',          -- pending|redeemed|expired|revoked
  created_by  BLOB,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, invite_id),
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

-- Sessions (§4.10). Only SHA-256(token) hashes stored.
CREATE TABLE sessions (
  tenant_id       BLOB    NOT NULL,
  session_id      BLOB    NOT NULL,
  account_id      BLOB    NOT NULL,
  device_id       BLOB    NOT NULL,
  access_hash     BLOB    NOT NULL,
  refresh_hash    BLOB    NOT NULL,
  access_expires  INTEGER NOT NULL,
  refresh_expires INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  revoked         INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, session_id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES device_pubkeys(tenant_id, device_id)
);
CREATE INDEX idx_sessions_device ON sessions(tenant_id, device_id);

-- Single-use auth challenge nonces (§4.11). Server enforces single-use + expiry.
CREATE TABLE auth_nonces (
  tenant_id  BLOB    NOT NULL,
  nonce      BLOB    NOT NULL,
  device_id  BLOB,
  expires_at INTEGER NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, nonce)
);

-- PAKE blind relay (§4.12). Server relays verbatim; sees nothing.
CREATE TABLE pake_relay (
  tenant_id  BLOB    NOT NULL,
  channel_id BLOB    NOT NULL,
  msg1       BLOB,
  msg2       BLOB,
  msg3       BLOB,
  state      TEXT    NOT NULL DEFAULT 'open',              -- open|msg1|msg2|msg3|done|expired
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, channel_id)
);

-- Idempotency keys (§4.13). Written in same tx as the mutation.
CREATE TABLE idempotency_keys (
  tenant_id     BLOB    NOT NULL,
  idem_key      BLOB    NOT NULL,
  request_hash  BLOB    NOT NULL,
  response_blob BLOB    NOT NULL,
  status_code   INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, idem_key),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
