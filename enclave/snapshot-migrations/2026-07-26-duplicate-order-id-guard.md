# 2026-07-26 — duplicate order-id guard

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: a0730c180788c691631597931c323d62270be85e
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

The private price-time order book now rejects a submitted order if its
`order_id` already exists in the live book. The rejection happens immediately
after normal order validation and before FOK executable-quantity checks,
matching, resting, depth updates or hold-accounting side effects.

## Reason

Order holds are aggregate per private user, market and outcome rather than keyed
by public order id. Reusing a live resting `order_id` with a different
idempotency key could replace the `orders` map entry while leaving the prior
depth/hold semantics ambiguous. Rejecting duplicate live order IDs fail-closed
and preserves the invariant that one live order ID maps to exactly one resting
order.

## State compatibility

This does not change the encrypted journal format, snapshot schema, ledger
accounts, order-book representation, settlement math, fee math, withdrawal
authorization schema, replay cache format, resolution state, market id format or
public audit payload format.

Existing snapshots and journals replay without reinterpretation. If an old
snapshot already contains a live order ID, it remains valid. The new rule only
affects future submissions attempting to introduce another live order with that
same ID.

## Production replay plan

Restore the latest immutable snapshot and encrypted journal exactly as with the
current production release. During replay, existing orders are loaded as-is. New
duplicate live order submissions are rejected before any mutation. After
activation, rerun the private CLOB duplicate-order E2E against the measured
enclave and confirm:

- first unique order rests or fills normally;
- second submission with the same order ID returns `invalid order: duplicate
  order id`;
- aggregate depth and locked balances remain unchanged after the rejected
  duplicate.

## Rollback plan

If provisioning, replay or live duplicate-order validation fails, drain traffic,
restore the previous `a0730c180788c691631597931c323d62270be85e` release/PCR
allowlist, and keep the scheduler/markets running on the prior enclave while the
new release is rebuilt. No journal rewrite or database migration is required.
