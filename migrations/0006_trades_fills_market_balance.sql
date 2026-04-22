-- Migration: 0006_trades_fills_market_balance.sql
--
-- Purpose: Add durable storage for the data currently living exclusively in
-- Redis (trades, fills) and wire up the existing orphaned tables (markets,
-- balances, orders) so the application actually writes to them.
--
-- New tables:
--   trades   — one row per matched trade
--   fills    — one row per order-side fill (two per trade: maker + taker)
--
-- Existing tables that were already migrated but never written to:
--   markets  — add strike_price, currency, vault_address, source columns
--   balances — add reserved column; primary key changed to (user_id, token_address)
--   orders   — already has the right shape; no schema changes needed here
--
-- All operations are idempotent (IF NOT EXISTS / DO blocks).

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. trades
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trades (
    id               UUID        PRIMARY KEY,
    market_id        TEXT        NOT NULL,
    maker_order_id   UUID        NOT NULL,
    taker_order_id   UUID        NOT NULL,
    maker_user_id    TEXT        NOT NULL,
    taker_user_id    TEXT        NOT NULL,
    side             TEXT        NOT NULL,   -- 'buy' | 'sell'  (taker side)
    price            NUMERIC(28, 18) NOT NULL,
    size             NUMERIC(28, 18) NOT NULL,
    settlement_tx    TEXT,                   -- EVM tx hash once settled on-chain, NULL until then
    created_at       TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trades_market_id      ON trades(market_id);
CREATE INDEX IF NOT EXISTS idx_trades_maker_user_id  ON trades(maker_user_id);
CREATE INDEX IF NOT EXISTS idx_trades_taker_user_id  ON trades(taker_user_id);
CREATE INDEX IF NOT EXISTS idx_trades_created_at     ON trades(created_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. fills
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fills (
    id          UUID        PRIMARY KEY,
    order_id    UUID        NOT NULL,
    trade_id    UUID        NOT NULL REFERENCES trades(id),
    price       NUMERIC(28, 18) NOT NULL,
    size        NUMERIC(28, 18) NOT NULL,
    fee         NUMERIC(28, 18) NOT NULL DEFAULT 0,
    is_maker    BOOLEAN     NOT NULL,
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fills_order_id  ON fills(order_id);
CREATE INDEX IF NOT EXISTS idx_fills_trade_id  ON fills(trade_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. markets — extend existing table with columns needed by oracle services
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'strike_price'
    ) THEN
        ALTER TABLE markets ADD COLUMN strike_price NUMERIC(28, 18);
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'currency'
    ) THEN
        ALTER TABLE markets ADD COLUMN currency TEXT;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'vault_address'
    ) THEN
        ALTER TABLE markets ADD COLUMN vault_address TEXT;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'source'
    ) THEN
        ALTER TABLE markets ADD COLUMN source TEXT;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'on_chain_market_id'
    ) THEN
        ALTER TABLE markets ADD COLUMN on_chain_market_id BIGINT;
    END IF;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. balances — add reserved column for order locking
-- ─────────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'balances' AND column_name = 'reserved'
    ) THEN
        ALTER TABLE balances ADD COLUMN reserved NUMERIC(78, 0) NOT NULL DEFAULT 0;
    END IF;
END;
$$;

-- Ensure we can upsert on (user_id, token_address) — add unique constraint if missing.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'balances'
          AND constraint_type = 'UNIQUE'
          AND constraint_name = 'balances_user_id_token_address_key'
    ) THEN
        -- Drop the existing PK sequence-based primary key and add a composite unique index
        -- so we can ON CONFLICT (user_id, token_address) DO UPDATE.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_balances_user_token
            ON balances(user_id, token_address);
    END IF;
END;
$$;
