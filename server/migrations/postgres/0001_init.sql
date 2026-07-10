-- UniSSH Server schema (Postgres dialect). Mirrors spec §4 / sqlite/0001_init.sql.
-- ids/pubkeys/blobs = BYTEA; all integers (seq/version/epoch/enum/bool/ts) =
-- BIGINT (decoded uniformly as i64); text = TEXT. Booleans stored as 0/1 BIGINT
-- for cross-dialect decode uniformity.

CREATE TABLE tenants (
  tenant_id            BYTEA PRIMARY KEY,
  tier                 TEXT   NOT NULL,
  display_name         TEXT,
  next_seq             BIGINT NOT NULL DEFAULT 0,
  genesis_owner_pubkey BYTEA,
  created_at           BIGINT NOT NULL,
  status               TEXT   NOT NULL DEFAULT 'active'
);

CREATE TABLE accounts (
  tenant_id  BYTEA  NOT NULL,
  account_id BYTEA  NOT NULL,
  created_at BIGINT NOT NULL,
  status     TEXT   NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE device_pubkeys (
  tenant_id     BYTEA  NOT NULL,
  account_id    BYTEA  NOT NULL,
  device_id     BYTEA  NOT NULL,
  ed25519_pub   BYTEA  NOT NULL,
  x25519_pub    BYTEA  NOT NULL,
  registered_at BIGINT NOT NULL,
  status        TEXT   NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, device_id),
  UNIQUE (tenant_id, ed25519_pub),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, account_id)
);
CREATE INDEX idx_devpub_account ON device_pubkeys(tenant_id, account_id);

CREATE TABLE objects (
  tenant_id     BYTEA  NOT NULL,
  server_seq    BIGINT NOT NULL,
  object_tag    BIGINT NOT NULL,
  object_bytes  BYTEA  NOT NULL,
  vault_id      BYTEA,
  item_id       BYTEA,
  member_pubkey BYTEA,
  obj_version   BIGINT,
  key_epoch     BIGINT,
  tombstone     BIGINT,
  item_type     BIGINT,
  sync_target   BIGINT,
  cache_policy  BIGINT,
  role          BIGINT,
  author_pubkey BYTEA,
  received_at   BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, server_seq),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX idx_obj_seq     ON objects(tenant_id, server_seq);
CREATE INDEX idx_obj_vault   ON objects(tenant_id, vault_id, obj_version);
CREATE INDEX idx_obj_logical ON objects(tenant_id, object_tag, vault_id, item_id, obj_version);

CREATE TABLE vaults (
  tenant_id      BYTEA  NOT NULL,
  vault_id       BYTEA  NOT NULL,
  owner_pubkey   BYTEA  NOT NULL,
  latest_version BIGINT NOT NULL,
  latest_epoch   BIGINT NOT NULL,
  sync_target    BIGINT NOT NULL,
  cache_policy   BIGINT NOT NULL,
  tombstone      BIGINT NOT NULL DEFAULT 0,
  created_at     BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, vault_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE membership_manifests (
  tenant_id     BYTEA  NOT NULL,
  vault_id      BYTEA  NOT NULL,
  key_epoch     BIGINT NOT NULL,
  manifest_blob BYTEA  NOT NULL,
  signature     BYTEA  NOT NULL,
  author_pubkey BYTEA  NOT NULL,
  server_seq    BIGINT NOT NULL,
  received_at   BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, vault_id, key_epoch),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE membership_grants (
  tenant_id     BYTEA  NOT NULL,
  vault_id      BYTEA  NOT NULL,
  member_pubkey BYTEA  NOT NULL,
  key_epoch     BIGINT NOT NULL,
  role          BIGINT NOT NULL,
  wrapped_vk    BYTEA  NOT NULL,
  signature     BYTEA  NOT NULL,
  author_pubkey BYTEA  NOT NULL,
  not_after     BIGINT,
  revoked       BIGINT NOT NULL DEFAULT 0,
  server_seq    BIGINT NOT NULL,
  received_at   BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, vault_id, member_pubkey, key_epoch),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX idx_grants_epoch  ON membership_grants(tenant_id, vault_id, key_epoch);
CREATE INDEX idx_grants_member ON membership_grants(tenant_id, member_pubkey);

CREATE TABLE audit_log (
  tenant_id     BYTEA  NOT NULL,
  seq           BIGINT NOT NULL,
  source        TEXT   NOT NULL,
  entry_blob    BYTEA  NOT NULL,
  signature     BYTEA,
  author_pubkey BYTEA,
  vault_id      BYTEA,
  recorded_at   BIGINT NOT NULL,
  server_seq    BIGINT,
  prev_hash     BYTEA,
  PRIMARY KEY (tenant_id, seq),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE keyset_blobs (
  tenant_id    BYTEA  NOT NULL,
  account_id   BYTEA  NOT NULL,
  generation   BIGINT NOT NULL,
  keyset_bytes BYTEA  NOT NULL,
  ed25519_pub  BYTEA  NOT NULL,
  x25519_pub   BYTEA  NOT NULL,
  uploaded_at  BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, account_id, generation),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, account_id)
);

CREATE TABLE invites (
  tenant_id   BYTEA  NOT NULL,
  invite_id   BYTEA  NOT NULL,
  token_hash  BYTEA  NOT NULL,
  role        BIGINT NOT NULL,
  scope       TEXT,
  expires_at  BIGINT NOT NULL,
  redeemed_by BYTEA,
  redeemed_at BIGINT,
  state       TEXT   NOT NULL DEFAULT 'pending',
  created_by  BYTEA,
  created_at  BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, invite_id),
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

CREATE TABLE sessions (
  tenant_id       BYTEA  NOT NULL,
  session_id      BYTEA  NOT NULL,
  account_id      BYTEA  NOT NULL,
  device_id       BYTEA  NOT NULL,
  access_hash     BYTEA  NOT NULL,
  refresh_hash    BYTEA  NOT NULL,
  access_expires  BIGINT NOT NULL,
  refresh_expires BIGINT NOT NULL,
  created_at      BIGINT NOT NULL,
  revoked         BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, session_id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES device_pubkeys(tenant_id, device_id)
);
CREATE INDEX idx_sessions_device ON sessions(tenant_id, device_id);

CREATE TABLE auth_nonces (
  tenant_id  BYTEA  NOT NULL,
  nonce      BYTEA  NOT NULL,
  device_id  BYTEA,
  expires_at BIGINT NOT NULL,
  consumed   BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, nonce)
);

CREATE TABLE pake_relay (
  tenant_id  BYTEA  NOT NULL,
  channel_id BYTEA  NOT NULL,
  msg1       BYTEA,
  msg2       BYTEA,
  msg3       BYTEA,
  state      TEXT   NOT NULL DEFAULT 'open',
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, channel_id)
);

CREATE TABLE idempotency_keys (
  tenant_id     BYTEA  NOT NULL,
  idem_key      BYTEA  NOT NULL,
  request_hash  BYTEA  NOT NULL,
  response_blob BYTEA  NOT NULL,
  status_code   BIGINT NOT NULL,
  created_at    BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, idem_key),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
