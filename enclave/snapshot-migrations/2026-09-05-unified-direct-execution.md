# Unified direct-execution state and deposit replay index

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: b487d94737b11e9a77b9f195877f19a62f8733ad
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration covers the scope-locked direct-execution candidate rooted at
`9fb4417b13ea7f33b8e589abb5777f7563d9950b`. It records an intentional private
state change; it is not permission to deploy, rotate the accepted PCR, start a
second writer, or send production traffic before the green and production
replay gates below pass.

The release is approved by the Layrs operator under the unified production
release checklist dated 2026-09-05. The protected production BTC market-maker
image, task definition, account, funds, and lifecycle remain outside this
migration.

## Exact persisted-state delta

`CoreStateSnapshot` adds `direct_final_results`, a bounded map keyed by the
domain-separated account and request ID. The field has a Serde default and is
omitted while empty, so a snapshot from the base release decodes to an empty
index without rewriting historical balances, orders, positions, fills,
markets, sessions, sequence, journal head, or state root.

Each final entry binds the original request and terminal result. Deposit-credit
entries additionally bind the immutable custody replay key, exact encrypted
journal record, signed receipt wire, and restart evidence. A committed deposit
also adds domain-separated replay markers to existing ledger/system replay-key
sets. Those markers and the corresponding balance mutation are created in one
journaled transition. Effect-none results never claim a custody replay key.

Historical snapshots have no direct result entries and therefore require no
synthetic backfill. The first accepted direct request is a normal forward state
transition. The candidate rejects duplicate custody keys, malformed stored
results, missing ledger/system markers, downgraded deposit records, and forged
restart evidence during restore.

## Production replay plan

Before production activation:

1. Fence candidate mutations and copy the exact current encrypted snapshot,
   journal head, sequence, state root, object version, source EIF hash, PCR0,
   and writer-fence evidence into the immutable release record.
2. Restore that unmodified snapshot into the candidate EIF in an isolated,
   attested environment using only the existing recipient-bound restore path.
3. Require exact equality of pre-transition sequence, journal head, state root,
   aggregate asset totals, order/withdrawal holds, positions, open orders,
   fills, markets, sessions, and all historical replay keys. The new direct
   result index must be empty before its first operation.
4. Run read-only private queries for multiple identities and prove no state,
   sequence, root, journal, or cross-account change.
5. Execute a finalized green deposit credit, replay the exact request and
   custody event, restart the enclave, and prove one mutation, byte-identical
   final replay, one balanced projection, and valid encrypted sidecars.
6. Repeat with response loss after artifact archive, an effect-none request,
   invalid source evidence, account/amount tampering, and concurrent duplicate
   custody submissions. Every non-applied path must preserve balances.
7. Immediately before cutover, repeat steps 1-4 against the then-current
   production artifact. Any mismatch, unresolved legacy preparation, unknown
   direct outcome, or unarchived final receipt is a hard stop.

Only privacy-safe hashes, aggregate reconciliations, attestation evidence, and
qualified outcomes may leave the enclave. Private account-level snapshot state
must not be exported.

## Activation order

1. Apply additive receipt/projection migrations with all direct-credit flags
   disabled.
2. Start the candidate enclave as the sole private writer and prove attestation,
   exact restore, direct lookup absence, and ordinary read health.
3. Deploy coordinator and worker support disabled; verify their expected
   fail-closed responses and the unchanged production MM fingerprint.
4. Enable the coordinator, then the funding worker, for direct deposit credit
   only. Keep legacy `DIRECT_FUNDING_CREDIT_ENABLED=false`.
5. Re-drive only preflight-qualified pool-confirmed deposits. Require signed
   final results, archive completion, balanced projection, user/pool
   reconciliation, and duplicate-delivery no-op evidence.

No market, order, withdrawal, settlement, or other command is authorized by
this deposit-credit activation.

## Rollback plan

Before the first direct state transition, stop the candidate and return the
writer fence, launch template, AMI, EIF, PCR allowlist, snapshot, and journal to
the retained base release. No data transformation is required because the new
index is still empty.

After any direct result is journaled, rollback to the base EIF is prohibited:
the base does not understand the new replay index and could duplicate a
financial effect. Disable new direct requests, retain the candidate enclave and
artifact archive, resolve every unknown response through exact request/custody
lookup, and project every applied receipt exactly once. Recovery must then move
forward with this schema or a separately reviewed successor that preserves the
index and replay markers. Never delete an entry, truncate the journal, remove a
replay marker, or edit a balance to make the old release load.

The production BTC market-maker is not rolled back or redeployed by this plan.
