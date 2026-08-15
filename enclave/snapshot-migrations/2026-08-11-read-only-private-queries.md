# 2026-08-11 — non-mutating private query receipts

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 7d41e9f83912df12f2b32f70f4d8c57ff194fcdd
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

Authenticated `Portfolio`, `Rewards`, and `BootstrapStatus` commands now execute
as read-only enclave queries. They still verify the registered session key,
signed request hash, expiry, and sequence, and they still return an
enclave-signed receipt bound to the current state root. They no longer append a
journal record, advance the private-core sequence, mutate the replay cache, or
emit a new encrypted snapshot.

The response's `encrypted_record` field becomes optional and is omitted for
these read-only queries. Every money- or state-moving command retains its
existing journal, snapshot, replay, and publication behavior.

## Reason

Production private reads were incorrectly treated as durable ledger
transitions. Every portfolio refresh serialized and encrypted the complete
private snapshot, which had grown to approximately 24 MB, monopolizing the
single enclave command mutex and causing authenticated reads and resolution
work to time out. A query must authenticate and attest what it read, but it must
not manufacture a new ledger transition.

## State compatibility

This release does not change `CoreStateSnapshot`, ledger accounts, books,
markets, sessions, processed-command state, rewards, resolutions, journal
plaintext, journal encryption, snapshot compression, or state-root
serialization. Existing snapshots and journals restore without transformation.

Mutating user commands still return `encrypted_record: Some(...)`. Read-only
responses omit the field using Serde's optional-field compatibility. Their
receipts use the current sequence and identical prior/current state roots, are
marked `publication_eligible=false`, and bind a domain-separated hash of the
signed command, returned result, and current state root.

## Production replay plan

1. Keep order intake and background workers drained during cutover.
2. Retain the immutable snapshot, journal, parent binary, EIF, measurements,
   and signed manifest for the base release above.
3. Restore that snapshot into the candidate EIF and require the exact existing
   sequence, journal head, and state root.
4. Execute repeated authenticated portfolio and reward reads and verify that
   sequence, state root, journal head, and snapshot publication remain
   unchanged while the signed receipts verify.
5. Execute a controlled mutating command and verify that it advances exactly
   one sequence, emits exactly one encrypted record, and restores on replay.
6. Rotate the signed release manifest, PCR policy, and parent AMI through the
   normal measured release process, then restore background work with bounded
   pacing.

The regression suite asserts the read-only invariants and the following
withdrawal mutation, in addition to the full private-core and complete-set
matching suites.

## Rollback plan

If snapshot restore, attestation, signed reads, or the mutating canary fails,
keep trading and workers drained and restore the retained base parent AMI,
EIF, signed manifest, and PCR policy. Because successful read-only commands
create no durable transition, rollback requires no ledger reconciliation.
If a mutating candidate command was accepted, preserve its journal/snapshot and
reconcile it through the normal forward-recovery procedure; never truncate the
journal.

## Approval

This is an intentional enclave behavior correction requested for production
fund certification. It must use the measured EIF, signed manifest, PCR rotation,
restore canary, and capped worker reactivation process.
