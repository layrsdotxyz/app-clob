# Resolution proof equivalence release

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 2b85c2aaa6143395e69c5deea2f7423356a15cd0
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Scope

This release routes the existing deterministic `UP`, `DOWN`, and `PUSH`
comparison through the same side-effect-free Rust crate used by the RISC Zero
guest. It adds no command, journal variant, state field, receipt field, balance
rule, order rule, or serialization change.

## Persisted-state compatibility

- `derive_resolution_outcome` maps the existing opening/closing median
  comparison to the existing `ResolutionOutcome` enum.
- The enum variants and their serialized representation are unchanged.
- State-root inputs, journal AAD, snapshot AAD, replay order and command
  idempotency are unchanged.
- Golden-vector and property tests compare the production engine with the proof
  core across `UP`, `DOWN`, `PUSH`, and wide integer boundaries.

Production replay must restore the immutable snapshot and journal from release
`2b85c2aaa6143395e69c5deea2f7423356a15cd0` into a passive candidate, then
compare the recovered state root and sequence with the active release before
cutover.

## Rollback

Drain and fence the candidate, restore the same immutable snapshot and journal
into release `2b85c2aaa6143395e69c5deea2f7423356a15cd0`, and require state-root,
sequence, receipt-key and audit-anchor parity before routing traffic back. The
candidate emits no new serialized state shape, so rollback remains replay
compatible.

## Approval

The protocol owner requested production-code equivalence and final enclave
release verification as part of the Claims-to-Evidence P0 gate.
