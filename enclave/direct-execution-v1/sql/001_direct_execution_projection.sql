-- Public, append-only projection for the clean runtime.
-- This schema never holds a private balance and is never used to restore one.
BEGIN;

CREATE TABLE IF NOT EXISTS direct_execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    terminal_status TEXT NOT NULL CHECK (terminal_status IN ('APPLIED', 'REJECTED_EFFECT_NONE')),
    effect TEXT NOT NULL,
    custody_reference TEXT,
    receipt_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, auth_subject_hash, request_id)
);

CREATE TABLE IF NOT EXISTS direct_execution_writer_fence (
    epoch_id TEXT PRIMARY KEY,
    old_writer_fence_evidence_sha256 TEXT NOT NULL CHECK (length(old_writer_fence_evidence_sha256) = 64),
    target_writer_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    activation_id TEXT UNIQUE,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
