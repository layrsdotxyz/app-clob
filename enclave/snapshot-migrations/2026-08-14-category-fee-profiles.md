# Category fee profiles

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 048c3370e533c32dc82e04efe17ee200b11c4a89
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

The private-core market configuration now accepts an immutable `fee_profile_id`
selected by the signed market release. Historical market records and snapshots
that omit this field deserialize to `LEGACY_PROFIT_V1`; that legacy value is
also omitted during serialization so previously committed snapshot bytes and
state roots remain unchanged.

Newly registered markets serialize their explicit versioned profile. The
profile is therefore committed by the encrypted journal, snapshot state root,
and signed release envelope. An existing registered market cannot be migrated
to another profile in place.

Settlement applies the profile only to profitable non-push claims. The fee is
computed with integer arithmetic, bounded by the profile's stake floor and cap,
and capped at five percent of realized gross profit. Taker fees remain the
separate existing execution-time debit.

Rollback is safe only before a market carrying a non-legacy profile has been
registered. After such registration, rollback requires retaining a reader for
the new field; silently interpreting the market as legacy would change payout
semantics and is prohibited.

## Production replay plan

Before activation, drain private mutations and retain the exact production
snapshot, journal sequence, journal head and state root produced by release
`048c3370e533c32dc82e04efe17ee200b11c4a89`. Restore that snapshot and replay
the retained journal through the candidate EIF. Existing markets must decode as
`LEGACY_PROFIT_V1`, their serialized `MarketConfig` bytes must remain unchanged,
and the candidate must reproduce the same sequence, journal head, state root,
balances, holds, positions, orders and resolutions. Registration of one new
profiled market is permitted only after that parity check succeeds.

## Rollback plan

Before the first profiled market is registered, restore the retained parent AMI,
EIF, signed release manifest, PCR policy, snapshot and journal directly. After a
profiled market is registered or used, do not restore a binary that cannot read
`fee_profile_id`; drain mutations and deploy a forward-compatible repair EIF
that preserves the selected profile and exact settlement arithmetic. Never
reinterpret a profiled market as legacy and never rewrite the append-only
journal or snapshot to force rollback.
