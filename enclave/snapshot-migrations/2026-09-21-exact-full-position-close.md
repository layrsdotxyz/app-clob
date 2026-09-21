# Exact full-position close below minimum notional

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: f69df5bff6fc17e517e54e4186ae757fea1d29e4
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

Release owner: Layrs protocol owner, who explicitly required an open position
to remain closable irrespective of its remaining value.

## Change

The private order validator permits a SELL below the market minimum notional
only when its quantity exactly equals the seller's entire remaining position
for that market and outcome. Partial below-minimum sells and all below-minimum
buys remain rejected. Quantity bounds, tick size, maximum notional, market
hours, expiry, balance, hold, matching, fee and settlement checks are unchanged.

## State compatibility

This release changes no persisted field or serialization. The encrypted journal
format, snapshot schema, state-root material, ledger accounts, order-book
representation, session state, replay keys, receipt shape, withdrawal state,
market configuration, matching algorithm, fee calculation and settlement logic
remain unchanged.

Existing snapshots and journals restore without transformation. Historical
orders retain their original validation result and are not reprocessed. The new
rule applies only to a future exact full-position SELL submitted after the
candidate becomes active.

## Production replay plan

1. Fence candidate mutations and retain the active production AMI, EIF, PCR
   allowlist, immutable snapshot, journal boundary, sequence, state root and
   writer-fence evidence.
2. Restore the latest production snapshot and replay the complete encrypted
   journal into the measured candidate.
3. Require equality of sequence, journal head, state root, aggregate asset
   totals, balances, holds, positions, open orders, fills, markets, sessions,
   withdrawals and replay keys before admitting traffic.
4. Run the regression suite proving that only an exact full-position SELL may
   bypass the minimum notional and that a partial SELL and a BUY cannot.
5. Through the normal authenticated UI, close the already authorized funded
   canary position whose remaining mark value is below the minimum. Verify one
   order result, the expected position reduction, balance reconciliation,
   signed receipt and idempotent replay before continuing the E2E.

## Rollback plan

Before the candidate accepts any command, restore the retained launch-template
version, AMI, EIF, PCR allowlist, snapshot and journal boundary for
`f69df5bff6fc17e517e54e4186ae757fea1d29e4`.

After the candidate accepts a command, stop new mutations and reconcile that
command from its signed result and archived journal evidence before changing
the writer. Because the persisted schema is unchanged, a rollback requires no
snapshot rewrite, balance edit or journal truncation. Never discard a committed
order or fill to force compatibility.
