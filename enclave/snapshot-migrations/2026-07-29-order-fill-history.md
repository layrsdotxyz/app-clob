# 2026-07-29 — explicit cumulative order fill history

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: abdf6843f8dd7173b0f3b88e797ab3af65422bb3
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

The field uses a Serde default of zero. Existing snapshots therefore restore
without transformation and all existing open orders begin with zero historical
fills unless their pre-cutover fill quantity is reconstructed during the
controlled replay check. New matches update the field deterministically.

No ledger account, hold, position, collateral, fee, withdrawal, resolution, or
reward balance is changed by this field. It is order-history state only.

## Production replay plan

1. Freeze new order submission and drain in-flight commands.
2. Retain the immutable pre-cutover snapshot and journal head.
3. Restore the snapshot into the candidate EIF and verify its state root.
4. Require the pre-cutover book to contain no partially-filled active order.
   If one exists, cancel it through the normal authenticated path and reconcile
   its position, released hold, and signed fill artifacts before proceeding.
5. Exercise full, partial, FAK, cancellation-after-partial, and complete-set
   canaries with controlled users.
6. Verify order history, holds, positions, fees, audit artifacts, and repeated
   replay state roots.
7. Rotate PCR0, the signed release manifest, and KMS attestation policy as one
   release before capped traffic resumes.

## Rollback plan

Before accepting any command on the candidate EIF, restore the retained
pre-cutover snapshot and the
`abdf6843f8dd7173b0f3b88e797ab3af65422bb3` release/PCR allowlist.

After accepting commands, freeze trading and retain the candidate snapshot and
journal. Roll back only after reconciling post-cutover orders, holds, positions,
fees, and custody movements. Never infer fills by subtracting a cancelled
remainder and never truncate the journal silently.

## Approval

This is an intentional additive state change requested to make private order
history accurate. It follows the normal measured EIF, signed manifest, PCR
rotation, replay-canary, and capped-activation process.
