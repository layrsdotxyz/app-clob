# 2026-08-03 — native macro market namespace

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: a9c5c2e544e594118429d27f987cd67058ec976a
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly approved FRED-backed macro
markets as native private-CLOB markets using the existing exact-condition
execution and resolution path.

## Change

The private-core market-namespace validator now admits `MACRO` alongside the
existing `SPORTS`, `ESPORTS`, and `POLITICS` categories for v5 native
exact-condition markets. No command, snapshot, journal, ledger, order, fill,
position, fee, receipt, or resolution type changes. Macro markets use the same
`NativeExactCondition` configuration and signed exact-condition settlement
logic already present in the deployed release.

## State compatibility

This is not a serialized-state schema change. Existing snapshots and journals
decode and replay without transformation, and every existing market retains
its original identifier and execution configuration. The change only affects
admission of a new market identifier namespace after an authenticated operator
registration command.

The snapshot guard treats `engine.rs` as schema-sensitive, so this approval is
recorded even though no stored field or encoding changes. An older binary will
reject registration of a new `MACRO` market; therefore rollback after macro
activation must fence new macro commands and repair forward rather than replay
accepted macro registrations through the older binary.

## Production replay plan

1. Freeze new private commands and retain the running release's immutable
   encrypted snapshot, journal head, sequence, and state root.
2. Restore and replay that exact state in the candidate EIF. Require equality
   of sequence, journal head, state root, balances, positions, holds, and open
   orders before accepting a command.
3. Register one isolated native macro canary whose metadata contains a frozen
   FRED series, vintage, baseline, strike, comparison rule, close time, and
   resolution timeout. Verify that malformed and unsupported namespaces fail
   before state mutation.
4. Submit funded NORMAL and complementary MINT orders in the canary and verify
   collateral conservation, deterministic receipts, journal replay, and owner
   balances.
5. Resolve the canary through the existing signed exact-condition path and
   verify evidence commitment, payout conservation, Horizen publication, and
   API/database reconciliation.
6. Rotate PCR0, signed release manifest, KMS attestation policy, and backend
   approved measurements together. Enable macro imports only after attestation,
   replay, DLQ, alarm, and reconciliation checks are green.

## Rollback plan

Before any macro registration is accepted, fence the candidate and restore the
deployed `a9c5c2e544e594118429d27f987cd67058ec976a` release, PCR allowlist, and
signed manifest.

After a macro registration is accepted, pause macro intake and trading, cancel
and reconcile any macro orders and holds through authenticated commands, retain
the candidate snapshot and journal, and repair forward. Do not replay accepted
macro commands with the older binary and do not truncate the encrypted journal.
All pre-existing markets remain replay-compatible without transformation.

## Approval

This additive namespace release must use the normal measured EIF build, signed
manifest, exact snapshot replay, PCR rotation, funded conservation canary, and
capped production activation process.
