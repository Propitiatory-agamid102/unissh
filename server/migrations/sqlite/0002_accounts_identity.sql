-- Account identity: canonical keyset on the account (= member-id, shared across
-- devices), human identifiers, instance-admin flag (§6.1/§6.7).

-- sessions are ephemeral; we clear them so the device_pubkeys rebuild below doesn't hit an FK.
DELETE FROM sessions;

ALTER TABLE accounts ADD COLUMN display_name TEXT;
ALTER TABLE accounts ADD COLUMN handle       TEXT;
ALTER TABLE accounts ADD COLUMN is_admin     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN ed25519_pub  BLOB;   -- canonical member-id keyset
ALTER TABLE accounts ADD COLUMN x25519_pub   BLOB;

-- backfill keyset from the account's first device (for existing data)
UPDATE accounts SET
  ed25519_pub = (SELECT d.ed25519_pub FROM device_pubkeys d
                 WHERE d.tenant_id = accounts.tenant_id AND d.account_id = accounts.account_id LIMIT 1),
  x25519_pub  = (SELECT d.x25519_pub  FROM device_pubkeys d
                 WHERE d.tenant_id = accounts.tenant_id AND d.account_id = accounts.account_id LIMIT 1);

-- identity uniqueness is now on the account; handle is unique within the tenant
CREATE UNIQUE INDEX idx_acct_ed     ON accounts(tenant_id, ed25519_pub);
CREATE UNIQUE INDEX idx_acct_handle ON accounts(tenant_id, handle);

-- relax device_pubkeys: drop UNIQUE(tenant_id, ed25519_pub) (devices share the keyset).
-- SQLite can't DROP CONSTRAINT → table-rebuild.
CREATE TABLE device_pubkeys_new (
  tenant_id     BLOB    NOT NULL,
  account_id    BLOB    NOT NULL,
  device_id     BLOB    NOT NULL,
  ed25519_pub   BLOB    NOT NULL,
  x25519_pub    BLOB    NOT NULL,
  registered_at INTEGER NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, device_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES accounts(tenant_id, account_id)
);
INSERT INTO device_pubkeys_new
  SELECT tenant_id, account_id, device_id, ed25519_pub, x25519_pub, registered_at, status
  FROM device_pubkeys;
DROP TABLE device_pubkeys;
ALTER TABLE device_pubkeys_new RENAME TO device_pubkeys;
CREATE INDEX idx_devpub_account ON device_pubkeys(tenant_id, account_id);
CREATE INDEX idx_devpub_ed      ON device_pubkeys(tenant_id, ed25519_pub);
