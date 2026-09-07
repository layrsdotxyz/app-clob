# Direct withdrawal final-result and restart artifacts

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 9d6d899fec5a590e12ad4f45f8f0f60777147bf8
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration covers the direct-withdrawal candidate rooted at CLOB commit
`7051ca849a1859796b42a5f10784da483d25491d` and its restart-artifact correction
rooted at `a10ee7a8b91e54d3f0ead20e2fc46fe92825e3e7`. It authorizes review and GREEN
certification only. It does not authorize a production PCR rotation, custody
credential use, wallet/fund movement, traffic cutover, or market-maker change.

## Exact persisted-state delta

The existing direct final-result index accepts terminal
`RESERVE_WITHDRAWAL`, `FINALIZE_WITHDRAWAL`, and `RELEASE_WITHDRAWAL` entries.
Each entry binds account, request ID/hash, canonical operation payload, terminal
state/effect/retry policy, operation-plus-withdrawal replay key for committed
effects, signed enclave receipt, encrypted journal record, and optional signed
withdrawal authorization. Effect-none results bind the exact request ID and
signed failure but intentionally do not claim the business replay key, allowing
a new request after a terminal no-effect failure.

Committed reserve/finalize/release transitions update the existing private
ledger and system replay-key sets in the same journaled mutation. No admission,
preparation, pending slot, TTL, recovery command, or global command coordinator
state is added.

The relay correction includes direct-withdrawal submit and lookup responses in
the existing synchronous encrypted journal, signed receipt, and post-mutation
encrypted snapshot sidecar path. It changes no private state schema; it ensures
the already-created withdrawal state is durably exported before the response is
released.

Historical snapshots decode unchanged. Snapshots created after the unified
direct-execution foundation but before the first direct withdrawal contain no
withdrawal entries and require no backfill.

## Replay and replacement-host plan

Before any production activation:

1. Build an immutable EIF/AMI from the reviewed commit with direct deposit and
   direct withdrawal enabled; publish hashes, PCR0, and attestation evidence.
2. Start it only in the isolated GREEN enclave stack with the explicit
   deny-production IAM boundary.
3. Restore the highest archived GREEN snapshot and journal. Require exact
   sequence, state root, journal head, account totals, holds, direct-result
   index, and replay-key equality.
4. Submit a GREEN reserve, finalize, release, and effect-none failure. Archive
   a same-sequence encrypted journal record, signed receipt, and snapshot for
   every terminal result before accepting the response.
5. Replace the GREEN enclave host and restore from those archived artifacts.
   Same-ID submit and committed operation-key lookup must return byte-identical
   signed result wires without another financial mutation.
6. Require database projections to remain exactly once, terminal withdrawal
   rows to remain bound to immutable direct receipt IDs, and all green
   withdrawal/funding/reconciliation queues and DLQs to be empty.
7. Run an independently funded GREEN custody sign/broadcast/confirmation and
   worker-restart test. Production custody authority must never be borrowed.

Any missing artifact, restore mismatch, changed signed wire, duplicate effect,
projection drift, unknown outcome, or absent independent GREEN custody
authority is a hard stop.

## Rollback plan

Before the first direct-withdrawal transition, the candidate may be stopped and
the retained GREEN launch template/AMI/PCR restored because no withdrawal state
needs migration.

After a direct-withdrawal result is journaled, rollback to an EIF that cannot
decode or validate that result is prohibited. Disable new direct-withdrawal
requests, retain the current writer and immutable artifact archive, recover
each named result through exact same-ID or operation-key lookup, complete every
projection exactly once, and move forward only to a reviewed successor that
preserves the direct result, ledger/system replay markers, journal sequence,
state root, and signed receipt bindings.

The production enclave, production custody, public traffic, and production BTC
market maker are outside this GREEN certification and remain unchanged.
