-- Auditable projection for the clean runtime. Balance rows contain the latest
-- signed receipt-derived read model but are never used to restore private state.
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
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch_id, identity_commitment, asset, bucket)
);
ALTER TABLE direct_execution_epoch_balances
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS direct_execution_identities (
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    admitted_post_genesis BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (epoch_id, identity_commitment),
    UNIQUE (epoch_id, auth_subject_hash, identity_commitment)
);

CREATE TABLE IF NOT EXISTS direct_execution_privy_wallets (
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    PRIMARY KEY (epoch_id, auth_subject_hash, wallet_address)
);
CREATE UNIQUE INDEX IF NOT EXISTS direct_execution_privy_wallet_epoch_unique
    ON direct_execution_privy_wallets(epoch_id, wallet_address);

CREATE TABLE IF NOT EXISTS direct_execution_identity_admissions (
    receipt_id TEXT PRIMARY KEY REFERENCES direct_execution_receipts(receipt_id),
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, auth_subject_hash),
    UNIQUE (epoch_id, identity_commitment),
    UNIQUE (epoch_id, wallet_address)
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

CREATE TABLE IF NOT EXISTS direct_execution_order_events (
    receipt_id TEXT PRIMARY KEY REFERENCES direct_execution_receipts(receipt_id),
    epoch_id TEXT NOT NULL,
    order_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    market_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('UP','DOWN')),
    action TEXT NOT NULL CHECK (action IN ('BUY','SELL')),
    status TEXT NOT NULL,
    limit_price_micros BIGINT NOT NULL,
    quantity_micros NUMERIC(78,0) NOT NULL,
    executed_quantity_micros NUMERIC(78,0) NOT NULL,
    remaining_quantity_micros NUMERIC(78,0) NOT NULL,
    fee_atomic NUMERIC(78,0) NOT NULL,
    resulting_position_micros NUMERIC(78,0) NOT NULL,
    resulting_available_atomic NUMERIC(78,0) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (epoch_id, order_id)
);

CREATE TABLE IF NOT EXISTS direct_execution_trade_events (
    trade_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL REFERENCES direct_execution_receipts(receipt_id),
    epoch_id TEXT NOT NULL,
    market_id TEXT NOT NULL,
    maker_order_id TEXT NOT NULL,
    taker_order_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('UP','DOWN')),
    match_type TEXT NOT NULL CHECK (match_type IN ('NORMAL','MINT','MERGE')),
    executed_quantity_micros NUMERIC(78,0) NOT NULL,
    execution_price_micros BIGINT NOT NULL,
    fee_atomic NUMERIC(78,0) NOT NULL,
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
