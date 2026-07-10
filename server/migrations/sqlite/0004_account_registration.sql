-- M14: persist the self-attested registration (payload + signature) so the admin
-- panel can verify that an account's x25519 encryption key is cryptographically
-- BOUND to its ed25519 identity (verify_registration), instead of trusting the
-- server's (vault_id, x25519) pairing. Both columns are NULLABLE: pre-existing
-- accounts were created before the signature was stored and CANNOT be backfilled
-- (only the keyset owner could re-sign) — the panel treats NULL as
-- "unverifiable/legacy", not "failed".
ALTER TABLE accounts ADD COLUMN reg_payload BLOB;
ALTER TABLE accounts ADD COLUMN reg_signature BLOB;
