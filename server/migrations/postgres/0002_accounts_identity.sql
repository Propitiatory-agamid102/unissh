-- Account identity: canonical keyset on the account (= member-id, shared by
-- devices), human identifiers, instance-admin flag (§6.1/§6.7).

ALTER TABLE accounts ADD COLUMN display_name TEXT;
ALTER TABLE accounts ADD COLUMN handle       TEXT;
ALTER TABLE accounts ADD COLUMN is_admin     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN ed25519_pub  BYTEA;
ALTER TABLE accounts ADD COLUMN x25519_pub   BYTEA;

UPDATE accounts SET
  ed25519_pub = (SELECT d.ed25519_pub FROM device_pubkeys d
                 WHERE d.tenant_id = accounts.tenant_id AND d.account_id = accounts.account_id LIMIT 1),
  x25519_pub  = (SELECT d.x25519_pub  FROM device_pubkeys d
                 WHERE d.tenant_id = accounts.tenant_id AND d.account_id = accounts.account_id LIMIT 1);

CREATE UNIQUE INDEX idx_acct_ed     ON accounts(tenant_id, ed25519_pub);
CREATE UNIQUE INDEX idx_acct_handle ON accounts(tenant_id, handle);

-- relax device_pubkeys uniqueness (devices share the account keyset). Drop the
-- auto-named UNIQUE(tenant_id, ed25519_pub) constraint robustly.
DO $$
DECLARE c text;
BEGIN
  SELECT con.conname INTO c
  FROM pg_constraint con
  WHERE con.conrelid = 'device_pubkeys'::regclass AND con.contype = 'u'
    AND con.conkey = (
      SELECT array_agg(att.attnum ORDER BY att.attnum)
      FROM pg_attribute att
      WHERE att.attrelid = 'device_pubkeys'::regclass
        AND att.attname IN ('tenant_id', 'ed25519_pub')
    );
  IF c IS NOT NULL THEN
    EXECUTE 'ALTER TABLE device_pubkeys DROP CONSTRAINT ' || quote_ident(c);
  END IF;
END $$;

CREATE INDEX idx_devpub_ed ON device_pubkeys(tenant_id, ed25519_pub);
