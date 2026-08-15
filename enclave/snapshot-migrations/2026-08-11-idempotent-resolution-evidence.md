# 2026-08-11 - idempotent resolution evidence recovery

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: db229d524ad4dff9f3c7e236a93f5196c39f381b
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly authorized repairing the
production resolution path before controlled funded access resumes.

## Change

Permit an exact, cryptographically valid resolution-evidence statement to be
returned after its matching market outcome has already been committed. This is
an idempotent recovery path for the case where the enclave commits resolution
but the caller does not durably receive the response.

The recovery path requires both the committed outcome and the complete typed
resolution statement to match. A different outcome, market, close time,
resolver, source, evidence hash, deadline, nonce, key version or signature is
rejected. Evidence is still verified before the committed-resolution check.

No snapshot, journal, market, ledger, balance, hold, position, order, fill,
fee, receipt, withdrawal, reward, root or serialized schema changes. The
approval marker is present because the guarded private-core engine is changed;
it does not represent a wire-format migration.

## Production replay plan

1. Preserve the latest immutable production snapshot and journal head from
   release `db229d524ad4dff9f3c7e236a93f5196c39f381b`.
2. Build and measure the candidate EIF from the reviewed commit, then rotate
   the signed manifest and PCR allowlist as one release.
3. Restore the production snapshot in the candidate and require equality of
   sequence, journal head, state root, balances, holds, positions, open orders,
   registered markets and committed resolutions.
4. Replay an exact already-committed resolution-evidence request and require an
   identical signed response without any state mutation.
5. Replay conflicting evidence and require deterministic fail-closed rejection.
6. Run the focused private-core suite, full enclave gates and one controlled
   production resolution canary before restoring normal scheduler throughput.

## Rollback plan

Before the candidate accepts a command, restore the prior AMI, EIF, parent
binary, signed manifest and PCR allowlist for release
`db229d524ad4dff9f3c7e236a93f5196c39f381b`.

After a candidate command, stop intake and repair forward from the retained
encrypted snapshot and journal. Do not truncate or rewrite the journal. Since
the change introduces no serialized state, the retained prior release remains
wire-compatible, but custody and ledger reconciliation is still mandatory
before reopening.

## Approval

This guarded engine change is intentional. Activation requires measured EIF
release controls, production replay parity, conflict-rejection tests, a funded
resolution canary and zero new resolution/DLQ alarms during the soak.
