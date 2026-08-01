# 2026-08-01 — user-verifiable private command receipts v2

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 77d8809d02a30b8454debfba59b8b5a8d9d6e85f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

Authenticated user commands now return a `layrs.v2` signed enclave receipt.
The receipt adds optional `request_hash` and `result_hash` fields, binding the
signed state transition to the exact authenticated request and private result.
System/operator receipts remain `layrs.v1` and omit those fields.

## Reason

A fully resting or cancelled order has no public fill artifact. The v2 receipt
lets its authenticated owner verify in the browser that the measured enclave
accepted the exact request and returned the exact private result. Receipts are
subsequently included in privacy-safe Merkle roots on Horizen without exposing
the user, market, side, price, quantity or action.

## State compatibility

This change does not alter the private ledger, order book, holds, fills,
positions, collateral, fees, settlement logic, matching behavior, snapshot
schema or state-root serialization. The receipt is created only after the
existing command-local state mutation and journal append have succeeded.

The two new receipt fields use Serde defaults and are omitted when absent, so
pre-v2 receipt values remain decodable. Existing snapshots and encrypted
journals load without transformation. Replaying an existing command produces
the same state root and journal head; only a newly returned authenticated user
receipt uses the v2 wire shape.

## Production replay plan

1. Freeze new private commands and drain in-flight requests.
2. Retain the immutable pre-cutover snapshot, encrypted journal head and active
   release manifest for commit `77d8809d02a30b8454debfba59b8b5a8d9d6e85f`.
3. Restore that exact snapshot/journal into the candidate EIF and require the
   same state root, open orders, holds, balances and positions.
4. Submit one controlled non-crossing order and verify its v2 receipt in the
   browser against the attested receipt key and candidate PCR0.
5. Cancel that order through the authenticated path and verify its cancellation
   receipt, released hold and unchanged custody balance.
6. Confirm both receipts are owner-bound in the database, archived only through
   a privacy-safe batch manifest, rooted on Horizen and retrievable with valid
   Merkle proofs.
7. Rotate the measured PCR0, signed release manifest and KMS attestation policy
   together; reopen capped traffic only after API, UI, worker, alarm and DLQ
   checks pass.

## Rollback plan

Before accepting a candidate command, restore the retained release, PCR
allowlist, snapshot and journal without transformation. After accepting v2
commands, freeze traffic and retain the candidate journal. Because receipt v2
does not alter command execution or state serialization, the prior release may
restore and replay the same command state; any v2 evidence already returned to
a user remains immutable evidence and is not deleted or rewritten. Reconcile
all receipt-batch jobs and custody balances before reopening. Never truncate the
journal or discard a user receipt silently.

## Approval

This is an intentional enclave release requested as the first controlled-alpha
evidence gate. It requires the normal measured EIF build, signed manifest/PCR
rotation, replay canary, Horizen-root confirmation and capped activation.
