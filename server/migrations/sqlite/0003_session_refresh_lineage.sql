-- Refresh-token reuse detection (§4): remember the immediately-previous refresh
-- hash on each rotation. Presenting a token whose hash matches no live session
-- but matches a session's prev_refresh_hash is a reuse/theft signal → the whole
-- session is revoked. Combined with the compare-and-swap rotation, this bounds a
-- stolen refresh token's window.
ALTER TABLE sessions ADD COLUMN prev_refresh_hash BLOB;
CREATE INDEX idx_sessions_prev_refresh ON sessions(tenant_id, prev_refresh_hash);
