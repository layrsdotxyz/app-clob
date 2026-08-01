# 2026-08-01 — native exact-condition event markets

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: fcfdbd5e47f8fec63fe5ff9eadb9dbb91b4bff7d
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly required every event market
to remain a native private-CLOB market and made external-venue execution an
optional, separately funded liquidity adapter rather than an order-acceptance
dependency.

## Change

The private core adds the `layrs:v5:{SPORTS|ESPORTS|POLITICS}:*` namespace and
an immutable `NativeExactCondition` execution configuration. Orders in these
markets use the existing private price-time book, including NORMAL, MINT and
MERGE matching and the existing complete-set collateral primitive.

Resolution adds a signed exact-condition statement. The enclave verifies the
configured condition identifier, selected outcome index, observation time,
evidence commitment and Ed25519 resolver signature before committing the same
UP/DOWN/PUSH settlement transition used by the native CLOB. It introduces no
external redemption and no external collateral inflow.

Existing `PolymarketExactCondition` markets and command variants remain
decodable for historical replay. This release does not reinterpret them or
make their venue path a dependency of a v5 native market.

## State compatibility

No existing market, book, order, hold, ledger account, position, fill, fee,
withdrawal, receipt or replay-cache record changes meaning. Existing snapshots
and journals retain their prior enum encodings and replay deterministically.

The new execution and resolution variants can occur only after a new v5 market
is registered through the authenticated operator release path. New v5 market
IDs create independent market, book and position buckets. Older binaries do not
understand these variants and therefore must not replay commands accepted after
v5 activation.

The accounting invariant is unchanged: a complementary BUY cross debits
genuinely funded user holds and mints exactly one complete set per matched unit.
Resolution redistributes only that pre-existing complete-set collateral and
fees. No venue wallet balance, synthetic credit or unbacked external value is
introduced by this release.

## Production replay plan

1. Freeze new private commands and retain the running release's immutable
   snapshot, encrypted journal head, sequence and state root.
2. Restore and replay that exact state in the candidate EIF. Require equality
   of sequence, journal head, state root, balances, positions and open orders
   before accepting a command.
3. Register isolated v5 fixtures for Sports, Esports and Politics and verify
   that unsupported categories, malformed conditions, wrong settlement chain
   and expired releases fail before state mutation.
4. Run owner-isolated NORMAL and complementary MINT canaries using funded
   balances. Verify holds, complete-set collateral, both positions, maker/taker
   fees, signed receipts and deterministic replay roots.
5. Resolve a funded canary with a signed exact-condition statement. Verify the
   condition and evidence commitments, payout conservation, zero external
   redemption/inflow, Horizen settlement publication and owner balances.
6. Disable the optional external-liquidity capability and prove that native v5
   order acceptance, crossing and resolution remain operational.
7. Rotate PCR0, signed release manifest and KMS attestation policy together,
   then enable capped traffic only after API, database, on-chain registry,
   reconciliation, DLQ and alarm checks agree.

## Rollback plan

Before any v5 command is accepted, fence the candidate and restore release
`fcfdbd5e47f8fec63fe5ff9eadb9dbb91b4bff7d` with its prior PCR allowlist.

After any v5 command is accepted, stop v5 order intake, cancel and reconcile
all v5 orders and holds through authenticated commands, retain the candidate
snapshot and journal, and repair forward. Do not replay a v5 command with the
older binary and never truncate the encrypted journal silently. Historical v1
through v4 state requires no transformation.

## Approval

This is an intentional additive private-core release. It must use the normal
measured EIF build, signed manifest, exact snapshot replay, PCR rotation,
funded conservation canaries, public settlement reconciliation and capped
activation process.
