-- Migration: 0004_rename_starknet_to_evm.sql
--
-- Purpose: Rename all database columns that carry "starknet" in their name to
-- EVM-neutral equivalents.  The project is expanding beyond Starknet and the
-- column names no longer reflect the real meaning of the data.
--
-- Columns renamed:
--   users.starknet_address              → users.evm_address
--   private_transitions.starknet_tx_hash → private_transitions.chain_tx_hash
--   commitment_roots.starknet_tx_hash   → commitment_roots.chain_tx_hash
--
-- The associated index on commitment_roots is also recreated under its new name.
--
-- Idempotency: PostgreSQL does not support IF EXISTS on ALTER TABLE …
-- RENAME COLUMN directly.  Each rename is therefore wrapped in a DO block that
-- checks information_schema.columns before executing, making the migration safe
-- to run more than once (subsequent runs are no-ops).

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. users.starknet_address → users.evm_address
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name  = 'users'
          AND column_name = 'starknet_address'
    ) THEN
        ALTER TABLE users RENAME COLUMN starknet_address TO evm_address;
    END IF;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. private_transitions.starknet_tx_hash → private_transitions.chain_tx_hash
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name  = 'private_transitions'
          AND column_name = 'starknet_tx_hash'
    ) THEN
        ALTER TABLE private_transitions RENAME COLUMN starknet_tx_hash TO chain_tx_hash;
    END IF;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. commitment_roots.starknet_tx_hash → commitment_roots.chain_tx_hash
--    Also recreate the covering index under the new name.
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name  = 'commitment_roots'
          AND column_name = 'starknet_tx_hash'
    ) THEN
        ALTER TABLE commitment_roots RENAME COLUMN starknet_tx_hash TO chain_tx_hash;
    END IF;
END;
$$;

-- Drop the old index (references the old column name; idempotent via IF EXISTS).
DROP INDEX IF EXISTS idx_commitment_roots_starknet_tx;

-- Recreate under the new name (idempotent via IF NOT EXISTS).
CREATE INDEX IF NOT EXISTS idx_commitment_roots_chain_tx ON commitment_roots(chain_tx_hash);
