-- Enrollment grants: per-engineer single-use revocable bootstrap credentials.
-- INSTANCE-level (they CREATE tenants) — NOT tenant-scoped, no FK on tenants.
-- Only sha256(secret) is stored; the secret itself is shown to the operator once at issuance.
CREATE TABLE enrollment_grants (
  grant_id        BYTEA   NOT NULL,
  token_hash      BYTEA   NOT NULL,
  label           TEXT    NOT NULL,                     -- attribution (who it was issued to); open metadata
  tier            TEXT,                                 -- pinned tier personal|org; NULL → server default
  state           TEXT    NOT NULL DEFAULT 'pending',   -- pending|redeemed|revoked
  expires_at      BIGINT,                               -- optional TTL (unix s); NULL → no expiry
  redeemed_tenant BYTEA,                                -- tenant created by this grant (set on redeem)
  redeemed_at     BIGINT,
  created_at      BIGINT  NOT NULL,
  PRIMARY KEY (grant_id),
  UNIQUE (token_hash)
);
