# Private registration receipt release

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 360c120a585c855c3925e1dc5442f3e0e85efe4f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Scope

This release intentionally changes snapshot-sensitive engine code so
`REGISTER_SESSION` emits a publication-eligible signed TEE receipt plus a
privacy-safe registration commitment and nullifier. It does not add, remove, or
reorder any persisted private-core snapshot field. The new
`registration_evidence` field exists only on the transient `SystemResponse`.

## Compatibility and replay plan

1. Preserve the latest encrypted snapshot and journal artifacts produced by
   release `360c120a585c855c3925e1dc5442f3e0e85efe4f`.
2. Restore that snapshot into the candidate enclave and replay every later
   journal record before admitting traffic.
3. Compare the restored sequence and state root against the production durable
   checkpoint. Registration receipt derivation happens only for new
   `REGISTER_SESSION` commands; historical sessions are not fabricated or
   backfilled.
4. Run an authenticated controlled registration canary and verify the receipt
   signature, command commitment, durable artifact, and identity-unique
   nullifier before enabling registration batching.

## Rollback plan

If restore/replay, attestation, registration canary, or receipt publication
fails, keep registration batching disabled, stop the candidate parent, restore
the prior EIF/release manifest for commit
`360c120a585c855c3925e1dc5442f3e0e85efe4f`, and resume from the last checkpoint
created by that release. No on-chain registration is published before its TEE
receipt batch is confirmed, so failed candidate registrations cannot create
unbacked public evidence.
