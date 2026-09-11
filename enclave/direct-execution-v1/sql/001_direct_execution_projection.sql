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

CREATE TABLE IF NOT EXISTS direct_execution_epoch_balances (
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    asset TEXT NOT NULL,
    bucket TEXT NOT NULL,
    amount_atomic NUMERIC(78, 0) NOT NULL,
    PRIMARY KEY (epoch_id, identity_commitment, asset, bucket)
);

CREATE TABLE IF NOT EXISTS direct_execution_privy_wallets (
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    PRIMARY KEY (epoch_id, auth_subject_hash, wallet_address)
);

CREATE TABLE IF NOT EXISTS direct_execution_sessions (
    epoch_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    expires_at_unix BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch_id, session_id)
);

CREATE TABLE IF NOT EXISTS direct_execution_custody_events (
    epoch_id TEXT NOT NULL,
    custody_reference TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('DEPOSIT', 'WITHDRAWAL')),
    state TEXT NOT NULL CHECK (state IN ('OBSERVED', 'CONFIRMED', 'FINAL')),
    chain_id BIGINT NOT NULL,
    tx_hash TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    amount_atomic NUMERIC(78, 0) NOT NULL,
    PRIMARY KEY (epoch_id, custody_reference)
);

CREATE TABLE IF NOT EXISTS direct_execution_accounting_events (
    receipt_id TEXT PRIMARY KEY REFERENCES direct_execution_receipts(receipt_id),
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    effect TEXT NOT NULL,
    amount_atomic NUMERIC(78, 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS direct_execution_writer_fence (
    epoch_id TEXT PRIMARY KEY,
    old_writer_fence_evidence_sha256 TEXT NOT NULL CHECK (length(old_writer_fence_evidence_sha256) = 64),
    old_writer_authorized BOOLEAN NOT NULL DEFAULT TRUE,
    target_writer_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    activation_id TEXT UNIQUE,
    CHECK (NOT (old_writer_authorized AND target_writer_enabled)),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS direct_execution_writer_grants (
    activation_id TEXT PRIMARY KEY,
    epoch_id TEXT NOT NULL,
    old_writer_fence_evidence_sha256 TEXT NOT NULL,
    expires_at_unix BIGINT NOT NULL,
    grant_json JSONB NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, old_writer_fence_evidence_sha256)
);

COMMIT;
