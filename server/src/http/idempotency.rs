//! Idempotency-Key helper (spec §5.0): lookup-or-store in the same transaction as
//! the mutation; a repeat → the same response verbatim; a different body under the same key → 409.
//! Implemented in Phase 3/4.
