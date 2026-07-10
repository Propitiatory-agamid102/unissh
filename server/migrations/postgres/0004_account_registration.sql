-- M14: persist the self-attested registration (payload + signature) so the admin
-- panel can verify that an account's x25519 encryption key is cryptographically
-- BOUND to its ed25519 identity (verify_registration). Both columns are NULLABLE:
-- pre-existing accounts predate the stored signature and CANNOT be backfilled —
-- the panel treats NULL as "unverifiable/legacy", not "failed".
ALTER TABLE accounts ADD COLUMN reg_payload BYTEA;
ALTER TABLE accounts ADD COLUMN reg_signature BYTEA;
