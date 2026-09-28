# Direct Execution v71 Storage Contract

Status: implementation contract for isolated development only. This document
does not authorize a production deployment, AWS mutation, database migration,
S3 write, EIF rollout, or writer-grant consumption.

Baseline: `80399af76522a5598997f84c4210437690be8415` (`v70`).

## Scope fence

This work fixes only direct-execution state persistence and recovery costs:

1. a v70-compatible frame/checkpoint safety bridge;
2. compact historical request retention without weakening idempotency or
   financial deduplication;
3. a signed, encrypted, sequence-linked per-commit journal;
4. bounded checkpoint-plus-tail restore;
5. non-writer shadow comparison and exact v70 rollback export.

It must not change matching, order priority, balances, holds, positions, fees,
market registration/resolution, custody semantics, receipt semantics, public
projection semantics, authentication, or external market-maker behavior.
Unrelated cleanup and refactoring are prohibited.

## Existing v70 invariants

For an accepted command, v71 must produce the same terminal status, effect,
receipt fields and signature, fills, balances, holds, positions, orders,
custody references, and financial state root as a logically equivalent v70
execution. Exact replay returns the original terminal result. Reuse of a
request id with a different request hash fails closed. Deposit, withdrawal,
market-resolution, and payout identifiers remain exactly-once for the life of
the lineage.

The authoritative sequence is explicit in v71; it must not be derived from the
size of a bounded request cache. Sequence continuity is strict and monotonic.

## v70 safety bridge

The bridge keeps every v70 artifact and checkpoint byte-compatible. It may:

- raise the parent and enclave frame limits to one identical benchmarked value;
- make the checkpoint seal performed after a successful restore best-effort;
- classify an oversized background checkpoint as skipped instead of retrying
  it indefinitely;
- replace the fixed 100,000-record validation limit only with a bounded,
  memory-benchmarked limit or a streaming-equivalent validation path.

The implemented bridge uses one shared 768 MiB parent/enclave frame ceiling
and a 250,000-record lineage guard. The byte ceiling remains tighter for normal
records. `V70_BRIDGE_BENCHMARK.md` records the synthetic 200,000-record memory,
commit, checkpoint, and restore measurements used to accept those bounds.

It may not make artifact validation, lineage validation, receipt signature
validation, or committed-head validation optional.

## Compact request history

Live state may replace a historical `(request_hash, DirectResult)` with a
compact terminal entry only when that entry preserves:

- account id and request id;
- request hash;
- terminal status and effect;
- signed receipt digest and immutable archive locator;
- every permanent financial deduplication key implied by the command.

An exact retry must return the same signed receipt after its archived bytes are
verified against the retained digest. If those bytes are unavailable or do not
match, the retry fails closed; it must never execute the command again.

The bounded v71 form retains only an authenticated sparse request-index root in
the enclave. For a new request, the parent must provide a valid non-membership
proof against that root; for a retry, it must provide the terminal membership
proof and the signed encrypted journal record named by the leaf. Missing,
conflicting, or stale proofs fail closed. The parent cannot turn an existing
request id into a new command by omitting history.

## v71 commit record

Each committed mutation is represented by a canonical record containing at
least:

- protocol and epoch id;
- writer epoch and sequence;
- previous record hash;
- previous and next transition roots, where the next root commits to the
  predecessor, sequence, request, and terminal result without serializing the
  full state;
- previous and next authenticated request-index roots;
- account id, request id, and request hash commitments;
- terminal result and signed receipt commitments;
- encrypted canonical mutation payload;
- ciphertext hash, nonce, and enclave signature.

The authenticated encryption associated data binds protocol, epoch, writer
epoch, sequence, previous record hash, previous transition root, account,
request id, request hash, signed receipt hash, terminal result hash, and both
request-index roots.
Nonce construction must be unique for the state key and fail closed on any
sequence reuse.

The transition root is not described as a full financial-state hash. The
authenticated checkpoint binds the canonical full-state hash; journal replay
must reproduce and validate that checkpoint hash. This distinction prevents a
hidden full-state serialization from remaining on every commit.

The parent is untrusted storage. It may persist bytes but cannot authorize a
sequence, manufacture a state transition, or alter a receipt. Durable append is
conditional on the expected writer epoch and sequence. A command is not
reported committed until that append is durably acknowledged.

## Checkpoint and restore

A v71 checkpoint binds an exact epoch, writer epoch, sequence, record hash,
transition root, and canonical full-state hash. Checkpoint creation must not
serialize a mutable state while commands continue changing that state.
Implementations must use an
immutable generation, copy-on-write view, or another proven consistent view.

Restore performs:

1. checkpoint authentication and full invariant validation;
2. strict replay of the subsequent journal records;
3. previous-record, sequence, request, receipt, and transition-root
   verification for every record;
4. exact final-head and checkpoint full-state-hash comparison before writer
   eligibility.

The retained journal tail is bounded by policy. Missing, duplicate, reordered,
or corrupted records fail closed. Genesis fallback remains forbidden when a
committed lineage exists.

## Shadow and writer handoff

Shadow mode has no writer authority and cannot publish financial effects. It
consumes the authoritative command order and compares terminal result, receipt,
fills, financial state, sequence, and transition root after every command.

There is no separate offline or 24-hour pre-cutover soak. Shadow verification
runs non-disruptively in production while v70 remains authoritative and users
continue trading. Cutover eligibility requires a consecutive live-match window
covering every financial action class observed in the window, successful
checkpoint-plus-tail restores, and a rehearsed v70 rollback from a
production-sized copy. The rollout runbook records the exact minimum commit
count before rollout; a mismatch resets the window and blocks cutover.

Writer handoff uses an explicit fence. Incoming commands remain durably queued
while dispatch pauses. The old writer completes at head `H`, both runtimes prove
the same head, the old writer is fenced at `H`, and the new writer may begin at
`H + 1`. Both writers must never be eligible for the same writer epoch and
sequence.

## Rollback

Until the rollback window closes, v71 changes storage mechanics only. It must
export a v70-format full artifact for its exact committed head. That artifact
must restore in the retained v70 EIF and reproduce the same balances, holds,
positions, orders, request/dedup behavior, sequence, and state root.

The v70 EIF and a separate unconsumed rollback grant remain outside this code
change. No development worker may inspect or consume production grants.

## Required verification

- Golden v70 artifact restore and deterministic replay.
- Exact replay and conflicting-request-id tests before and after compaction.
- Permanent deposit, withdrawal, payout, and resolution deduplication tests.
- Crash injection before append, after append/before response, during
  checkpoint creation, and during writer handoff.
- Missing, duplicate, reordered, truncated, and modified journal records.
- Concurrent-writer and stale-writer fencing.
- v71 checkpoint plus maximum permitted journal-tail restore.
- v71-to-v70 export and v70 restore.
- Peak RSS for commit, checkpoint, and full restore within an 8 GiB enclave.
- Production-sized latency benchmark proving no full-state work in the commit
  path and targets of p50 <= 250 ms and p95 <= 750 ms. p99 below one second is
  a target and a rollout gate if the production durable store can sustain it.

## Worker ownership

Codex owns this contract, integration, enclave state semantics, journal format,
state roots, compaction, replay, and final review.

The parent worker may change only parent transport/persistence and directly
associated tests. It must not change `DirectRuntime`, matching, custody, or
receipt semantics.

The verification worker may add fixtures, benchmarks, fault tests, shadow
comparison, and runbooks. It must not change production behavior to make a test
pass.

All workers are prohibited from AWS, S3, database, task-definition, deployment,
EIF, AMI, or writer-grant mutations.
