-- Migration: 0005_order_vault_fields.sql
--
-- Purpose: Add vault_address and collateral_currency columns to the orders table
-- to support multi-vault routing (USDC vault vs ZEN vault).
--
-- vault_address      — EVM address of the vault contract that holds collateral
--                      for this order. Empty string = use the global
--                      PM_VAULT_ADDRESS env-var fallback (backward compat).
-- collateral_currency — "USDC" or "ZEN". Defaults to "USDC" for existing rows.
--
-- Idempotent: each ALTER is wrapped in a DO block that checks
-- information_schema.columns before executing.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Add vault_address column to orders table
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name  = 'orders'
          AND column_name = 'vault_address'
    ) THEN
        ALTER TABLE orders
            ADD COLUMN vault_address TEXT NOT NULL DEFAULT '';
    END IF;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Add collateral_currency column to orders table
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name  = 'orders'
          AND column_name = 'collateral_currency'
    ) THEN
        ALTER TABLE orders
            ADD COLUMN collateral_currency TEXT NOT NULL DEFAULT 'USDC';
    END IF;
END;
$$;

-- Optional index to filter/query by currency efficiently.
CREATE INDEX IF NOT EXISTS idx_orders_collateral_currency ON orders(collateral_currency);
