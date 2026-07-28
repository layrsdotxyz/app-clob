# 2026-07-29 — complete-set CLOB matching

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: df3c45d582a2d3cabdaf64353fab6a6476213af1
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

The private price-time book adds `MINT` and `MERGE` complementary matches while
retaining the existing `NORMAL` transfer match. `Fill` gains a backward
compatible `match_type` field whose deserialization default is `NORMAL`.

The ledger schema and sole collateral primitive are unchanged. Complementary
matches orchestrate existing balanced transfers around
`Ledger::apply_complete_set(Mint|Burn)` on the command-local cloned ledger.

## State compatibility

Snapshots produced before this release contain no `match_type`, so they restore
as `NORMAL`. NORMAL-only order commands retain the previous single-ledger-
transaction path and ledger sequence behavior. Existing market, order, hold,
position, collateral, fee, withdrawal, resolution and reward accounts are not
reinterpreted.

New snapshots may contain processed command results with explicit `MINT` or
`MERGE` fill types. Serde ignores unknown fields when an older binary reads the
wire shape, but an older matching engine cannot safely replay complementary
commands from their original plaintext command stream.

## Production replay plan

Before cutover:

1. freeze new order submission and let in-flight commands drain;
2. anchor and retain the final immutable pre-cutover snapshot and journal head;
3. restore that snapshot into the candidate EIF;
4. verify its state root and all existing NORMAL open orders/holds;
5. run deterministic MINT and MERGE canaries with controlled users;
6. verify complete-set collateral, both outcome positions, fee revenue, signed
   audit artifacts and replayed state roots;
7. enable capped traffic only after PCR0, release manifest and KMS attestation
   policy are rotated together.

The release suite includes exact-boundary/non-cross tests, cross-outcome
self-trade prevention, FOK/FAK/partial behavior, unified effective-price
priority, randomized determinism, end-to-end MINT/MERGE conservation and
identical replayed state-root checks.

## Rollback plan

Before the first accepted complementary fill, rollback may restore the immutable
pre-cutover snapshot and the `df3c45d582a2d3cabdaf64353fab6a6476213af1`
release/PCR allowlist.

After a complementary fill is committed, do not replay that command with the
old matcher. Freeze trading, retain the new EIF for state export/reconciliation,
and either repair forward with a newly measured compatible EIF or restore the
pre-cutover snapshot and explicitly reconcile all post-snapshot external
custody movements before reopening. No silent journal truncation is permitted.

## Approval

This is an intentional, additive private-core release requested for binary
market cold-start liquidity. It must use the normal measured EIF, signed release
manifest, PCR rotation, replay canary and capped activation process.
