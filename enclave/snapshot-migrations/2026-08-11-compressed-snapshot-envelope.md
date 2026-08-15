# 2026-08-11 - compressed authenticated snapshot envelope

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 84bccc29ade15b5098671260d89e3af264eb3b03
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly authorized completing the
funded production certification and repairing the enclave liveness failure
before traffic resumes.

## Change

New private-core snapshots compress the serialized state with zstd level 1
before authenticated encryption. A fixed version prefix inside the AEAD
plaintext distinguishes the compressed envelope. Restore accepts both the new
versioned envelope and every legacy uncompressed snapshot produced by release
`84bccc29ade15b5098671260d89e3af264eb3b03`.

No ledger, order book, market, session, hold, position, fill, fee, receipt,
withdrawal, reward, resolution, replay-cache, journal-entry or state-root field
is added, removed, reordered or reinterpreted. Compression changes only the
durable snapshot transport representation. Decompression is bounded to 512 MiB
and fails closed before JSON decoding if that limit is exceeded.

The parent runtime also limits concurrent enclave exchanges, applies a bounded
exchange deadline below the HTTP deadline, checks the enclave over VSOCK in its
health endpoint, and installs a watchdog that restarts the parent/enclave pair
if the measured enclave process is absent. These liveness controls do not alter
private state.

## Production replay plan

1. Keep order intake and high-volume schedulers fenced while preserving the
   latest immutable encrypted snapshot and journal head from release
   `84bccc29ade15b5098671260d89e3af264eb3b03`.
2. Build the enclave and parent from the same source commit, archive their
   checksums and measurements, and rotate the signed release manifest and PCR
   policy together.
3. Restore the exact legacy production snapshot into the candidate EIF. Require
   equality of restored sequence, journal head, state root, balances, holds,
   positions, open orders and market registrations before admitting traffic.
4. Export a new compressed snapshot and restore it into the same candidate.
   Require the same state and materially smaller encrypted checkpoint payload.
5. Run one authenticated controlled session and state-changing canary. Require
   completion within the parent deadline, a durable compressed checkpoint,
   correct signed receipt and identical replayed state root.
6. Restore control, resolution and market-data workers one at a time. Require no
   VSOCK timeout storm, enclave restart, snapshot failure, new DLQ message or
   stale private command before funded certification continues.

Unit and integration gates cover compressed round-trip, legacy restore,
decompression bounds, production-lineage migration, replay-cache behavior,
frame limits and timeout ordering in both locked enclave runtimes.

## Rollback plan

Before the candidate accepts a command, fence its parent and restore the prior
AMI, EIF, parent binary, signed manifest and PCR allowlist for release
`84bccc29ade15b5098671260d89e3af264eb3b03` using the retained legacy snapshot.

After the candidate accepts a command, retain its compressed checkpoint and
encrypted journal, stop new intake and repair forward. The old release cannot
read the new compressed envelope, so never point it at that checkpoint, never
truncate the journal and never infer or rewrite balances. If rollback is still
required, reconcile every post-cutover custody and ledger movement explicitly
against the last retained legacy snapshot before reopening.

## Approval

This is an intentional snapshot-envelope migration required to prevent the
production CLOB from becoming unavailable under checkpoint load. It must use
the measured EIF build, exact legacy replay, signed manifest, PCR rotation,
compressed checkpoint canary and staged worker restoration described above.
