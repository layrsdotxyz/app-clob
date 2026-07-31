# 2026-07-30 — aggregate settlement readiness diagnostic

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 69b6752b34f2fe966a41c4131fda556d4a2c16d6
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly authorized repair of the
principal-bearing production settlement and permanent prevention of recurrence.

## Change

The enclave adds a read-only operator command that simulates deterministic
market-wide order cancellation against cloned state and returns only aggregate
settlement readiness: collateral, UP/DOWN/PUSH liabilities, active-order count,
cancellation success and outcome solvency.

It also makes cancellation release the actual residual balance of each
owner/market/outcome hold bucket after reserving the deterministic requirement
for orders still active in that bucket. This fixes ceil-rounding
non-additivity after a partial fill: independently rounded filled and remaining
notional can exceed the original rounded reservation by one micro-unit.

No owner, order, balance, position, fill or other private identity mapping is
returned.

## State compatibility

This release does not add or modify any persisted field. It does not change the
encrypted journal format, snapshot wire schema, state-root material, replay
cache, ledger accounts, matching, fee math, withdrawal
authorization, market registration or public audit payloads. Existing snapshots
and journals therefore replay byte-for-byte without transformation.

The diagnostic clones the current ledger and books, applies the same
cancellation-transfer construction used by resolution, and discards the clone.
It cannot mutate the live state or journal.

New cancel and resolution commands use the corrected residual-hold calculation.
They remain balanced ledger transfers and preserve all custody; no balance is
created, destroyed or reassigned between owners.

## Production replay plan

Restore the latest immutable snapshot and replay every encrypted journal entry
on the candidate EIF. Require the restored sequence, journal head and state root
to equal the running release before sending any command. Query readiness for a
resolved zero-exposure market and the affected pending MINT market, then compare
the returned aggregates with deterministic native regression vectors. Keep
trading frozen during replacement and release it only after coordinator
provisioning and state-root reconciliation pass.

## Rollback plan

If replay, attestation, readiness or reconciliation differs, fence the candidate
and restore release `69b6752b34f2fe966a41c4131fda556d4a2c16d6`
with its prior PCR allowlist. Because this release has no persisted-state change,
rollback requires no journal or snapshot rewrite.
