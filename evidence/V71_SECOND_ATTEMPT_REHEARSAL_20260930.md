# v71 second-attempt rehearsal evidence — 2026-09-30

## Corrected production failure causes

- The 05:42 checkpoint failure was the enclave response
  `JOURNAL_CHECKPOINT_VERIFY_UNAVAILABLE`: pre-promotion verification consulted
  only the authoritative v71 runtime even though the exact checkpoint belonged
  to the active shadow.
- Shadow catch-up held the enclave transition gate during CPU-heavy replay. The
  production candidate recorded a 144-second `enclave_candidate` wait while the
  parent listen queue reached `129/128`.
- A subsequent review found a second fail-closed gap: after the immutable
  cutover marker was written, an unconfirmed enclave promotion returned and
  released the financial gate. Later v70 acknowledgements could then exceed
  the marker-selected v71 restart frontier.

## Implemented safety boundaries

- Exact active-shadow base checkpoints can be authenticated before promotion;
  unrelated checkpoints remain unavailable.
- Catch-up snapshots under the transition gate, replays outside it, and
  reacquires it only to compare/install an exact head.
- Once a cutover marker exists, a transport failure or mismatched promotion
  permanently retains the process's financial gate and fails health with
  `V71_CUTOVER_CONFIRMATION_UNCERTAIN` until replacement.
- Marker-selected startup requires the latest v70 archive head to equal the
  marker sequence. Any newer, older, absent, or malformed v70 tip fails closed.

## Focused verification

- `v71_hot_restore_requires_the_legacy_tip_to_equal_the_cutover_marker`: pass.
- `unconfirmed_promotion_after_marker_fails_health_and_keeps_gate_closed`: pass.
- Complete debug smoke rehearsal: pass.

Smoke metrics:

```text
V71_FULL_PROMOTION_REHEARSAL history=1000 pending_commits=16 framed_commits=1 shadow_active_ms=35322 pending_gate_wait_ms=0 pending_burst_ms=2 framed_p50_ms=1306 framed_p99_ms=1306 largest_v70_artifact_bytes=2327903 export_ms=5 checkpoint_verify_ms=75 promotion_ms=13 journal_commit_ms=52 rollback_seal_ms=21907 rollback_checkpoint_bytes=3661554 final_sequence=1018 writer_epoch=shadow-production-rehearsal
```

The smoke path covered Pending authoritative commits, shadow activation, a
full framed v70 commit while Active, complete export, exact checkpoint
verification, exact-head promotion, a compact v71 commit, v70 rollback seal,
v70 restore, portfolio equality, and idempotent result replay.

## Remaining gates

- Re-run the same path in release mode at the freshly measured production
  frontier with concurrent load and record p50/p99 and peak RSS.
- Build and inspect the corrected candidate and bridge-derived rollback AMIs.
- Rehearse the isolated storage/promotion, exact-head handoff, rollback ASG
  replacement, and forward/rollback identity-consumer rotations.
- Recheck Horizen gas and all sign-up/deposit/withdrawal preflights before any
  production retry. No funds or thresholds are changed by this work.
