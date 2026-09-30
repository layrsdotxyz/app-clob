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

## Current-frontier release-mode rehearsal

The immutable production frontier was refreshed read-only immediately before
this run:

- Head sequence: 44,779.
- Head artifact: 175,371,119 bytes.
- Latest checkpoint: sequence 44,767, 258,882,961 bytes.
- One healthy in-service writer; parent restart count zero; parent memory
  2,868,994,048 bytes.

The release-mode enclave rehearsal then passed the complete transition at the
same record count:

```text
V71_FULL_PROMOTION_REHEARSAL history=44779 pending_commits=64 framed_commits=2 shadow_active_ms=126781 pending_gate_wait_ms=0 pending_burst_ms=1 framed_p50_ms=4493 framed_p99_ms=4991 largest_v70_artifact_bytes=91055883 export_ms=59 checkpoint_verify_ms=15 promotion_ms=122 journal_commit_ms=61 rollback_seal_ms=35387 rollback_checkpoint_bytes=149717893 final_sequence=44846 writer_epoch=shadow-production-rehearsal
REHEARSAL_MAX_VMHWM_KIB=4105296
```

Result: pass for sequence-scale correctness and concurrent Pending load. The
64 Pending commits were all caught up, two full framed v70 commits matched,
promotion was exact, the compact successor committed, and the restored v70
checkpoint preserved the exact sequence, portfolio and idempotent result.

Memory is not yet accepted from this run alone. Its synthetic full artifact
and rollback checkpoint are materially smaller than production at the same
sequence. A conservative byte-sized run is required before the 8 GiB gate can
pass.

## Conservative byte-sized rehearsal

The same complete release-mode path passed with 90,000 historical commits,
64 commits arriving during shadow construction and two framed v70 commits at
the promotion edge:

```text
V71_FULL_PROMOTION_REHEARSAL history=90000 pending_commits=64 framed_commits=2 shadow_active_ms=264524 pending_gate_wait_ms=0 pending_burst_ms=1 framed_p50_ms=9215 framed_p99_ms=9544 largest_v70_artifact_bytes=182606164 export_ms=116 checkpoint_verify_ms=83 promotion_ms=249 journal_commit_ms=125 rollback_seal_ms=75579 rollback_checkpoint_bytes=300466827 final_sequence=90067 writer_epoch=shadow-production-rehearsal
V71_REHEARSAL_MEMORY phase=rollback_restored rss_kib=4917464 high_water_kib=7980460
```

Result: pass. The byte sizes exceeded the current production head/checkpoint,
and the exact-head v70 rollback restored sequence, portfolio and idempotent
result equality. Peak RSS was 7,980,460 KiB (7.61 GiB). This is useful
conservative evidence but has insufficient margin to approve operation at
90,000 records inside an 8 GiB enclave; the current-frontier 44,779-history
result remains the production rollout memory gate at 4,105,296 KiB (3.92 GiB).

## Parent storage review correction

Independent review found three parent release blockers after the first
rehearsal:

- v71 shadow records reused v70 `heads/{sequence}`, so a live v70 head at the
  same sequence would force `ARCHIVE_SEQUENCE_CONFLICT` before promotion;
- restart's v70-tip check would count post-promotion v71 records as v70 heads;
- an ambiguous immutable cutover-marker PUT could return before promotion and
  release the financial gate while the marker might already be durable.

The correction uses canonical
`journal-v71/records/{sequence:020}.cbor` keys, lists only `heads/` for the
v70-tip equality check, and routes every marker-write error through the same
permanent gate-retention and failed-health path as an unconfirmed promotion.
The v71 format has not shipped, so this namespace correction has no deployed
compatibility cost.

Parent verification after the correction:

```text
cargo test --bin layrs-direct-parent
124 passed; 0 failed; 1 ignored
```

The passing suite includes create-only append/readback/fence ordering,
same-sequence v70/v71 key isolation, canonical journal listing and restore,
exact-head rollback inputs, true-v70-tip marker validation, and both ambiguous
marker and ambiguous promotion gate-retention tests.
The complete `cargo test` run for `enclave/direct-execution-v1` also passed
across the library, enclave, parent, integration tests and doc tests.

## Post-correction current-frontier rerun

Read-only production refresh immediately before the rerun:

- Head sequence: 44,840.
- Head artifact: 175,636,642 bytes.
- Latest checkpoint: sequence 44,834, 259,321,856 bytes.
- One healthy in-service writer; launch-template version 75; ASG health grace
  3,600 seconds.

The exact `f231bc4d22c8eb7bdc841d6abe11c73a0e3f0dd7` release source then passed the
complete release-mode transition again:

```text
V71_FULL_PROMOTION_REHEARSAL history=44840 pending_commits=64 framed_commits=2 shadow_active_ms=133869 pending_gate_wait_ms=0 pending_burst_ms=1 framed_p50_ms=4527 framed_p99_ms=4728 largest_v70_artifact_bytes=91173714 export_ms=68 checkpoint_verify_ms=18 promotion_ms=118 journal_commit_ms=59 rollback_seal_ms=36219 rollback_checkpoint_bytes=149922401 final_sequence=44907 writer_epoch=shadow-production-rehearsal
V71_REHEARSAL_MEMORY phase=rollback_restored rss_kib=2390596 high_water_kib=3905604
```

Result: pass through shadow build under concurrent load, exact checkpoint
verification, promotion, compact successor, rollback materialization and v70
restore. Peak RSS was 3,905,604 KiB (3.73 GiB). Release binaries:

- enclave SHA-256:
  `9e2bf99d1a15ed6028d965c6a6de4e0985594511dddd9926835dcb0d0398e236`;
- parent SHA-256:
  `8d198971869c187d7d2719842d32ac48bc8894354201a059b53fa8b5d2e560f0`.

## Candidate image build and independent inspection

- Candidate AMI: `ami-030d6c96d9509c615`.
- Encrypted snapshot: `snap-0895021d8a0e1a223`.
- AMI state: available, private, deregistration protection
  `enabled-with-cooldown`.
- Safety tags: `WriterEnabled=false`, `ProductionAccess=denied`.
- Installed parent SHA-256:
  `8d198971869c187d7d2719842d32ac48bc8894354201a059b53fa8b5d2e560f0`.
- Installed EIF SHA-256:
  `6dbda0f0e78947fd28970641faf523c5029f24fe28bce3c94db2b08b55c5e461`.
- PCR0:
  `0fb65478faedc58e15f0f43db6ae1b0844f33d538402775a49fc588609ba1b75fd9e4bb6a14271935dac2e15b8efd894`.
- PCR1:
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`.
- PCR2:
  `6c380880f381edb2af483a547979d949937852ad982a28d41a0186c6059bbc327b11e0618b8731a12db5a07e8557bdb7`.
- Allocator: 8,192 MiB, two CPUs.
- `/etc/layrs-opening/direct-runtime.env`: absent.
- Local artifact files: zero.

The inspection host was disposable and writer-disabled. It was terminated
immediately after inspection; the Packer source host, temporary security group
and temporary key pair were also removed.

## Paired retained-v70 rollback image

- Rollback source commit: `5dad5a03daec069a15634db3827715cf4691ff34`.
- Rollback AMI: `ami-03627140f4af90a9c`.
- Encrypted snapshot: `snap-031214db5c62062fa`.
- AMI state: available, private, deregistration protection
  `enabled-with-cooldown`.
- Safety tags: `WriterEnabled=false`, `ProductionAccess=denied`.
- Installed compatibility-parent SHA-256:
  `c7a6c8be7b4a78c366cb2b6eb29b6c6cc0ee5cb2f25b495f19808b53e21deb42`.
- Preserved live-bridge EIF SHA-256:
  `6100a96de33300bac8b13e7f0700883e0fe9f14bdfb900305d55d651b95a9256`.
- Preserved PCR0:
  `59beb72420f56eb9b6a794b7d9ac4aced2c191ee964381cbc01d2d73e386645abe4eaa9af8757984ad52e79916029572`.
- Preserved PCR1:
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`.
- Preserved PCR2:
  `28a6c5946a520ea6f72ace25a5cf9b57a8949c84377858e1c81457edaadd188e2b11b2eaafcb8c3352bf9e4a9f012ced`.
- Allocator: 8,192 MiB, two CPUs; runtime env absent; local artifact files
  zero.
- Exact release-mode parent suite: 83 passed, zero failed, one benchmark
  ignored.

The rollback inspection host was terminated immediately after inspection.
This image retains the bridge enclave identity but includes the strict sparse
exact-head restore parent; the exact live bridge parent remains a later
fallback only after a separately produced contiguous v70 archive exists.

## Isolated ASG forward-to-rollback handoff

The inspected candidate and rollback AMIs were exercised through a temporary
ASG with the production instance class, subnet, enclave setting and
restore-based 3,600-second health grace, but with the non-production SSM role,
no runtime env, no grant, no archive prefix and no load balancer.

- Candidate launch-template v1 reached `InService` in 17 seconds.
- The booted candidate enclave reported the exact candidate PCR0/PCR1/PCR2,
  8,192 MiB and two CPUs; no runtime env was present.
- Launch-template v2 changed only the image to the paired retained-v70 AMI.
- The ASG refresh began at Unix `1790760921` and completed successfully at
  `1790761129`: 208 seconds.
- Final state before cleanup: desired 1, max 1, exactly one healthy `InService`
  instance on version 2, 3,600-second health grace; the version-1 instance was
  gone.
- The temporary ASG and launch template were deleted. Both ASG instances and
  both independent inspection instances are confirmed terminated.

This rehearsal validates the complete ASG rollback leg and its timing. It does
not substitute for the pre-rollout exact-head package materialization check;
that remains a gate against the current production frontier.

## Remaining gates

- Re-run the complete path after the storage correction against a refreshed
  production frontier and exercise the parent S3 staging/marker protocol.
- Build and inspect the corrected candidate and bridge-derived rollback AMIs.
- Rehearse the isolated storage/promotion, exact-head handoff, rollback ASG
  replacement, and forward/rollback identity-consumer rotations.
- Recheck Horizen gas and all sign-up/deposit/withdrawal preflights before any
  production retry. No funds or thresholds are changed by this work.
