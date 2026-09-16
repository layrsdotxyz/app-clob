-- Canonical cash effects that are NOT a second authorized customer withdrawal.
-- No synthetic private receipt and no second customer debit is created.
BEGIN;
CREATE TABLE IF NOT EXISTS layrs_direct_v1.direct_execution_extra_payouts (
    epoch_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL CHECK (length(intent_hash)=64),
    original_receipt_id TEXT NOT NULL REFERENCES layrs_direct_v1.direct_execution_receipts(receipt_id),
    transaction_hash TEXT NOT NULL,
    amount_atomic NUMERIC(78,0) NOT NULL CHECK (amount_atomic>0),
    evidence_sha256 TEXT NOT NULL CHECK (length(evidence_sha256)=64),
    evidence_json JSONB NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition='PROTOCOL_OVERPAYMENT_UNRECOVERED'),
    customer_debit_atomic NUMERIC(78,0) NOT NULL DEFAULT 0 CHECK (customer_debit_atomic=0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch_id,intent_hash),
    UNIQUE (epoch_id,transaction_hash)
);
GRANT SELECT,INSERT ON layrs_direct_v1.direct_execution_extra_payouts TO layrsv2_worker_role;
GRANT SELECT ON layrs_direct_v1.direct_execution_extra_payouts TO layrsv2_api_role,layrsv2_auditor_role,layrsv2_operator;
COMMIT;
