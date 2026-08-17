# Private order and fill history

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: f1268f5de193f6c1ccb30cd626d4b641470499c5
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

Release owner: Layrs platform and financial-core owners, subject to the normal
measured-EIF, signed-manifest, PCR and production certification gates.

The migration diff is based on the certified E06-S03 projection commit above;
the recorded deployed enclave lineage remains
`97614f37c05089708f93bf50ac8831adde98ab2f` and is the production replay source.

## Change

This release adds cumulative `filled_micros` to each private order and an
enclave-private `fill_history` collection to each price-time book. Every new
fill commits its deterministic fill identifier, maker and taker order links,
private owner identifiers, market/outcome/match type, exact price and quantity,
sequence and occurrence time in the same state transition as matching.

The fields support owner-scoped, encrypted order and fill history reads. They
are never returned to the coordinator in plaintext. Cursors are short-lived,
signed and bound to the enclave-derived owner, projection and exact filter.
Activity pages are padded to a constant 512-KiB plaintext length before
encryption so ciphertext length does not disclose private row cardinality.

## State compatibility

Pre-history snapshots omit both fields. Restore continues to accept their
recorded legacy state root and reconstructs only cumulative fill quantity when
that quantity is unambiguous from a GTC/GTD order. It never fabricates maker or
taker fill rows. FAK/FOK partial history that cannot be reconstructed fails
closed with `SnapshotMigrationRequired`.

A restored legacy state can continue trading, but private activity reads fail
with `PRIVATE_ACTIVITY_HISTORY_MIGRATION_REQUIRED` whenever cumulative order
fills cannot be reconciled exactly to committed fill rows. Production must not
enable the history routes until journal replay has produced a complete
projection.

## Production replay plan

1. Fence private mutations and retain the immutable production snapshot,
   encrypted journal, sequence, journal head, state root, parent binary, EIF,
   measurements, signed manifest and PCR policy.
2. Restore the retained snapshot with the candidate and replay every journaled
   order transition from the last complete checkpoint into a fresh candidate
   state. Do not synthesize fill identities or timestamps.
3. Require exact equality of balances, holds, positions, active-order state,
   fees, rewards, resolutions, sequence and journal head. Reconcile every
   order's cumulative filled quantity to its exact maker/taker fill rows.
4. Compare owner-scoped order/fill pages for the controlled six-account corpus
   against signed receipts. Require exact price, quantity, maker/taker role,
   fee, match type and time, and prove no counterparty identity is present.
5. Exercise legacy incomplete history, tampered/cross-owner/expired cursors,
   wrong recipient keys, ciphertext tampering and replay. Each must fail closed
   without a state-root or financial-state mutation.
6. Build and measure the candidate EIF, rotate the signed manifest and PCR
   allowlist together, run a read-only canary, then enable history reads only
   after the replay reconciler certifies completeness.

## Rollback plan

Before the candidate accepts a mutating command, fence it and restore the
retained production parent AMI, EIF, signed manifest and PCR policy. If the
candidate has accepted any mutation, preserve its snapshot and encrypted
journal, stop intake, reconcile all financial state, and repair forward. Never
truncate or edit the journal to force an older state root.

The API readiness registry must return the history-migration error while the
candidate is incomplete; it must never fall back to Aurora, receipts or a
plaintext identity-financial projection.

## Approval

This is an intentional persisted-state change. Activation requires exact
production-lineage replay, full history reconciliation, recipient-only
encryption and authorization tests, measured EIF release, signed manifest/PCR
rotation and controlled production readback with zero financial difference.
