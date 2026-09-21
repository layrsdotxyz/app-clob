-- Projection ordering metadata only. No balance or private-state mutation.
BEGIN;
ALTER TABLE layrs_direct_v1.direct_execution_epoch_balances
    ADD COLUMN IF NOT EXISTS projection_sequence BIGINT NOT NULL DEFAULT 0
    CHECK (projection_sequence >= 0);
COMMIT;
