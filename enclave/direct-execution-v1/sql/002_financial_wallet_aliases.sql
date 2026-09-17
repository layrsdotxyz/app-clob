-- Additive projection only: never derives or restores balances or identity.
-- Existing canonical authentication wallets remain unchanged for rollback.
BEGIN;
SET LOCAL search_path TO layrs_direct_v1, pg_catalog;
CREATE UNIQUE INDEX IF NOT EXISTS direct_receipt_wallet_link_owner
    ON direct_execution_receipts(receipt_id, epoch_id, auth_subject_hash, identity_commitment);
CREATE TABLE IF NOT EXISTS direct_execution_financial_wallet_aliases (
    epoch_id TEXT NOT NULL,
    auth_subject_hash TEXT NOT NULL,
    identity_commitment TEXT NOT NULL,
    wallet_address TEXT NOT NULL CHECK (wallet_address ~ '^0x[0-9a-f]{40}$'
        AND wallet_address <> '0x0000000000000000000000000000000000000000'),
    receipt_id TEXT NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch_id, wallet_address),
    UNIQUE (receipt_id),
    FOREIGN KEY (receipt_id, epoch_id, auth_subject_hash, identity_commitment)
        REFERENCES direct_execution_receipts(receipt_id, epoch_id, auth_subject_hash, identity_commitment),
    FOREIGN KEY (epoch_id, auth_subject_hash, identity_commitment)
        REFERENCES direct_execution_identities(epoch_id, auth_subject_hash, identity_commitment)
);
GRANT SELECT, INSERT ON direct_execution_financial_wallet_aliases TO layrsv2_worker_role;
GRANT SELECT ON direct_execution_financial_wallet_aliases
    TO layrsv2_api_role, layrsv2_auditor_role, layrsv2_operator;
COMMIT;
