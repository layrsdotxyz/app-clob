# 2026-07-29 — explicit cumulative order fill history

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 2b85c2aaa6143395e69c5deea2f7423356a15cd0
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

`BookOrder` adds `filled_micros`, a cumulative executed-quantity field. It is
initialized to zero and incremented for both the resting maker and incoming
taker in the same deterministic matching loop that decrements
`remaining_micros`.

This field is required because fill-and-kill orders deliberately discard an
unfilled remainder. After that cancellation, `quantity_micros -
remaining_micros` is not the executed quantity. Persisting the cumulative fill
amount keeps filled, partially filled, cancelled, and expired order history
truthful without reconstructing private journal contents in the browser.

## State compatibility

The field uses a Serde default so existing snapshot plaintext remains
decodable. Decoding alone is not sufficient: adding the field also changes the
canonical book bytes committed into the private-core state root.

The production checkpoint was emitted by release
`2b85c2aaa6143395e69c5deea2f7423356a15cd0`. That release also predates
private reward accounting, so its state root does not contain a serialized
`private_rewards` component. The measured migration therefore:

1. Computes and verifies the exact pre-`filled_micros` book serialization
   against the snapshot's committed state root.
2. Reproduces both the later complete-set lineage and the exact production
   lineage, including omission of the not-yet-existent private reward
   component.
3. Rejects the snapshot if the current root and both approved legacy roots
   fail to match.
4. Reconstructs cumulative fills deterministically:
   - `FILLED` orders use their original quantity;
   - GTC/GTD orders use `quantity - remaining`;
   - rejected and unfilled cancelled FAK/FOK orders use zero.
5. Fails closed with `SnapshotMigrationRequired` for a historical partially
   filled FAK/FOK order because its discarded remainder cannot be inferred
   truthfully.

The legacy-root path is used only during restore. All snapshots and state roots
emitted after migration include `filled_micros`.

No ledger account, hold, position, collateral, fee, withdrawal, resolution, or
reward balance is changed by this field. It is order-history state only.

## Production replay plan

1. Freeze new order submission and drain in-flight commands.
2. Retain the immutable pre-cutover snapshot and journal head.
3. Restore the snapshot into the candidate EIF, verify its exact legacy state
   root and reconstruct deterministic cumulative fills.
4. Require the pre-cutover book to contain no partially-filled active order.
   If one exists, cancel it through the normal authenticated path and reconcile
   its position, released hold, and signed fill artifacts before proceeding.
5. Exercise full, partial, FAK, cancellation-after-partial, and complete-set
   canaries with controlled users.
6. Verify order history, holds, positions, fees, audit artifacts, and repeated
   replay state roots.
7. Rotate PCR0, the signed release manifest, and KMS attestation policy as one
   release before capped traffic resumes.

The release gate includes
`restores_legacy_book_root_and_reconstructs_deterministic_fill_history` and
`restores_actual_production_lineage_without_private_reward_root` and
`rejects_legacy_fak_partial_fill_that_cannot_be_reconstructed`.

## Rollback plan

Before accepting any command on the candidate EIF, restore the retained
pre-cutover snapshot and the
`2b85c2aaa6143395e69c5deea2f7423356a15cd0` release/PCR allowlist.

After accepting commands, freeze trading and retain the candidate snapshot and
journal. Roll back only after reconciling post-cutover orders, holds, positions,
fees, and custody movements. Never infer fills by subtracting a cancelled
remainder and never truncate the journal silently.

## Approval

This is an intentional additive state change requested to make private order
history accurate. It follows the normal measured EIF, signed manifest, PCR
rotation, replay-canary, and capped-activation process.
