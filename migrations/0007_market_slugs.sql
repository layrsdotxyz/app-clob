-- Migration: 0007_market_slugs.sql
--
-- Purpose: persist canonical public slugs for market pages, backfill existing
-- market rows, and enforce uniqueness for any slugged market record.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'markets' AND column_name = 'slug'
    ) THEN
        ALTER TABLE markets ADD COLUMN slug TEXT;
    END IF;
END;
$$;

WITH computed AS (
    SELECT
        id,
        TRIM(BOTH '-' FROM REGEXP_REPLACE(
            REGEXP_REPLACE(
                LOWER(COALESCE(NULLIF(description, ''), market_id)),
                '[^a-z0-9]+',
                '-',
                'g'
            ),
            '-+',
            '-',
            'g'
        )) AS base_slug,
        TRIM(BOTH '-' FROM REGEXP_REPLACE(
            REGEXP_REPLACE(
                LOWER(COALESCE(on_chain_market_id::text, market_id)),
                '[^a-z0-9]+',
                '-',
                'g'
            ),
            '-+',
            '-',
            'g'
        )) AS suffix_slug
    FROM markets
)
UPDATE markets AS markets_to_update
SET slug = CASE
    WHEN computed.base_slug = '' THEN computed.suffix_slug
    WHEN computed.base_slug = computed.suffix_slug THEN computed.base_slug
    ELSE computed.base_slug || '-' || computed.suffix_slug
END
FROM computed
WHERE markets_to_update.id = computed.id
  AND (markets_to_update.slug IS NULL OR markets_to_update.slug = '');

CREATE UNIQUE INDEX IF NOT EXISTS idx_markets_slug_unique
    ON markets(slug)
    WHERE slug IS NOT NULL;