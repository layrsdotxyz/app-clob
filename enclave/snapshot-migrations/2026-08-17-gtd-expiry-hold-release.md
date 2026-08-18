# 2026-08-17 — deterministic GTD expiry hold release

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b682c9384a8d0c45d6b10992547e65afa9efb1b5
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, through the approved E10 private-CLOB
certification work. Deployment, EIF promotion and funded activation remain
separate release gates and are not authorized by this document.

## Change

The native private CLOB now deterministically expires elapsed GTD orders at the
next valid journalled write for the same market. It marks those orders
cancelled, removes them from the active book and releases their grouped cash or
claim holds in the same command-local atomic transition before position-limit
validation and matching.

Wall-clock passage alone still cannot mutate enclave state. An invalid command,
a command for a closed market, or any command that later fails does not commit
the candidate expiry sweep.

## Reason

The prior matcher excluded an expired GTD order from executable liquidity and
public depth but left its persisted status `OPEN`. Its grouped hold remained
locked and the order continued to count toward the owner position limit until
explicit cancellation or market resolution. A user could therefore be unable
to place a valid replacement after the signed GTD deadline.

## State compatibility

This release adds no snapshot, journal, ledger, market, order, fill, receipt,
session, replay-cache or state-root field. It reuses the existing `Cancelled`
order status, active-order set, balanced hold-release transfers and encrypted
journal envelope. Historical snapshots and records deserialize without a
transformation and reproduce the exact pre-command sequence, journal head and
state root.

An old snapshot may contain an elapsed GTD order that is still marked open.
Restore preserves that state exactly. Only the next successful valid write to
that market applies the new deterministic expiry transition. Because that
post-activation command has different intended semantics, an older matcher
must not replay candidate-era commands after the first committed expiry sweep.

## Production replay plan

1. Drain private mutations and retain the immutable base parent binary, EIF,
   measurements, signed manifest, snapshot, journal sequence, journal head and
   state root for the base commit above.
2. Restore the retained snapshot in the candidate EIF and replay the retained
   encrypted journal. Before accepting a command, require exact equality of
   sequence, journal head, state root, balances, holds, orders, positions,
   fees, rewards and resolutions.
3. From an isolated copy of that restored state, exercise a GTD order before
   and at its expiry. Require no mutation from time passage alone and require
   the next valid same-market write to cancel it and release exactly its unused
   grouped hold before accepting the replacement.
4. Replay the replacement command and require the archived response and state
   root without a second release. Restore the encrypted candidate snapshot and
   repeat the transition to the same semantic receipt and state root.
5. Run GTC, GTD, FAK, FOK, partial/cancel, close, rollover and signed-resolution
   lockout vectors plus the complete private-core, snapshot, proof and enclave
   runtime suites.
6. Treat measured EIF build, attestation, PCR/manifest rotation, funded canary
   and soak as later deployment gates. They are not performed by this story.

## Rollback plan

Before any candidate command is accepted, restore the retained base parent,
EIF, PCR policy, signed manifest, snapshot and journal directly.

After the first successful candidate expiry sweep, do not replay its command
with the older matcher. Freeze new mutations, retain the candidate snapshot and
encrypted journal, reconcile every affected order and grouped hold, and repair
forward with this binary or a compatible measured successor. Never truncate or
rewrite the journal, reopen a cancelled GTD order, or synthesize a compensating
balance outside the double-entry ledger.

## Approval

This is an intentional behavioral correction to prevent expired GTD orders
from locking user collateral or position capacity. The serialized schema is
unchanged, but the private-core transition is snapshot-sensitive and therefore
uses the full replay/rollback release gate.
