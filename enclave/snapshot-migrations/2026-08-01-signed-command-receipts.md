# 2026-08-01 — signed private-command receipts

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 77d8809d02a30b8454debfba59b8b5a8d9d6e85f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs protocol owner, who explicitly prioritized user-verifiable
receipts for resting and cancelled orders and privacy-safe public root batching.

## Change

Authenticated user commands now receive a version-two enclave receipt. The
receipt signs the existing SHA-256 commitment to the exact decrypted command
identifier, idempotency key and action payload. It also signs whether the
command is eligible for privacy-safe root publication. State-changing commands
such as order submission and cancellation are eligible; read-only portfolio and
status queries are not.

Historical receipts and enclave-system receipts remain version one. The
external JSON shape of the enclave user response is unchanged; boxing the Rust
response enum payload is an internal allocation detail needed only to keep the
measured binary within the strict lint gate.

## State compatibility

This release does not add or modify persisted private-engine, ledger, book,
session, replay-cache, journal-record or snapshot fields. It does not change the
state-root preimage, matching behavior, collateral accounting, fee math,
withdrawal authorization or market resolution. Existing encrypted snapshots
and journals therefore restore and replay without transformation and produce
the same sequence, journal head and state root.

The new receipt fields are generated after an authenticated command completes;
they are response evidence and are not part of the encrypted snapshot or state
root. Backend persistence is explicitly backward compatible with both receipt
versions. Only version-two receipts whose signed publication policy is true are
eligible for a public Merkle root; neither owner identity nor action payload is
published.

## Production replay plan

1. Deploy the additive database migration and backward-compatible API/worker
   release before activating the candidate EIF.
2. Freeze new private commands and retain the latest immutable snapshot,
   encrypted journal, anchored sequence and journal head.
3. Restore that snapshot into the candidate EIF and replay every later journal
   record. Require exact equality of sequence, journal head and state root with
   the running release.
4. Verify the candidate measurement and signed release manifest, then run
   owner-isolated canaries for a resting order and its cancellation. Require
   exact local-command commitment verification, receipt-signature verification,
   immutable artifact reread and owner-only retrieval.
5. Publish a batch containing at least two eligible receipts, verify the Merkle
   proofs and compare the Horizen registry record with the API response before
   reopening capped traffic.

## Rollback plan

If restore, replay, attestation, receipt verification, owner isolation or root
reconciliation differs, fence the candidate and restore release
`77d8809d02a30b8454debfba59b8b5a8d9d6e85f` with its prior PCR allowlist. No
snapshot or journal rewrite is required because private state-transition
semantics and persisted schemas are unchanged. Retain any valid version-two
receipt artifacts already issued; the backward-compatible backend continues to
verify both versions while the older EIF resumes issuing version-one receipts.
