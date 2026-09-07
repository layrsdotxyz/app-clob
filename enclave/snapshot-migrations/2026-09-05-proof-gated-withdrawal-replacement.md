# Proof-gated stale prepared-withdrawal replacement

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b10db52f969d28d5c159f1aa15e4003661ee2307
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration covers only the cumulative enclave release that already
contains the lifecycle-read and positive split-deposit fixes. It does not
authorize an EIF build, PCR/KMS allowlist change, production state mutation,
traffic cutover, or bulk withdrawal recovery.

## Persisted-state delta

No field is added to `CoreStateSnapshot`, `LedgerWire`, a balance record, a
session, or a user command. Old encrypted snapshots therefore decode without a
transform and must restore to the exact pre-transition sequence, state root and
journal head.

The candidate adds one `JournaledSystemCommand` variant and, only after all
proof gates pass, atomically replaces one existing
`prepared-withdrawal:<id>:<commitment>:<raw>` system key with a new exact raw
transaction and adds one
`replaced-withdrawal:<id>:<old>:<new>:<chain-observation>` marker. The marker is
bounded to one per withdrawal and survives encrypted snapshot export/restore.
No available balance, withdrawal hold, order, position, market, fill, reward,
fee, or custody bucket is changed by this command.

The command accepts only a valid terminal-journal recovery authorization for
the original committed withdrawal. It re-proves the original idempotency key,
receipt, state root, session, chain, asset, amount, destination commitment and
current withdrawal hold. It also binds the exact decoded old raw transaction
hash and nonce to fresh chain-absence, block and current-pending-nonce evidence.

## Production replay plan

Before activation, restore the exact latest production snapshot in a passive
dark candidate using the existing VersionId-pinned incident restore boundary.
Require byte equality for sequence, root and journal head and equality of all
privacy-safe aggregate custody totals. Exercise the replacement only on a
synthetic copy whose withdrawal ID, receipt, terminal record and raw
transaction were created inside that copy; prove positive replacement, wrong
receipt/root/destination/hash/nonce rejection, stale/present chain evidence
rejection, concurrent second-replacement rejection and exact replay after an
encrypted snapshot restart. The dark candidate must have no live writer lease,
route, queue consumer, RPC broadcaster or traffic target.

Production recovery is strictly one direct Base-USDC withdrawal at a time.
After each replacement, the normal worker must broadcast the exact replacement
hash, persist the append-only broadcast observation and finalize the existing
hold before the next candidate is considered. Relay withdrawals are excluded
and must use their existing release/requote path.

## Rollback plan

Before the first replacement transition, rollback is the retained cumulative
EIF/AMI, original snapshot, journal and PCR policy. After the first replacement
marker or journal record is committed, rollback to an EIF that does not know
the new journal variant is prohibited. Freeze further recovery and continue
forward with this candidate or a separately governed compatible successor.
Never delete a marker, rewrite a raw transaction, edit a nonce, truncate the
journal, or modify a user balance to make rollback appear possible.
