# v71 release packet: `3cbce68`

Status: built and inspected; exact-head restore and complete ASG rollback
rehearsed; current-production-frontier V1 and production change sets remain.

This packet replaces `V71_RELEASE_9F93FB0.md`. The earlier packet must not be
used because its rollback package could become stale after later acknowledged
v71 commits. This release adds an explicit exact-head handoff: `SIGUSR2` takes
the financial gate, validates and emits the retained-v70 package, and keeps the
gate until the ASG replacement completes. It does not add Durable Commands or
a command queue. It also replaces the draft `009e198` packet: the internal
shadow-promotion timeout is now 25 minutes and no obsolete shorter fixed gate
remains in the v71 packet, runbook or parent controller.

## Immutable release identity

- Source commit: `3cbce68549717642c8ad525a2340b0b36262ffcb`
- Candidate AMI: `ami-00498fa3f6e6a20e8`
- Candidate snapshot: `snap-023f816e3459da783`
- Candidate parent SHA-256: `6b6ead2f255a7466d0b507e6dc3215f6d2b699319d5ed1e02ccc5dddaa77b929`
- Candidate enclave SHA-256: `0915f6bc609df6ba8d319e89c6d97e60d149437cb1d4050f56adca674160f8da`
- Candidate EIF SHA-256: `cc604191f25613094de7aeda9678dd146fb82f8dfa2bb8a5535680f61801685f`
- Candidate PCR0: `db914cd8668e133389cf81587f4b046976b3cffe9e75c835cc8d09353b13865b451c4dee6d380890ccdfaa358a4bd2f5`
- Candidate PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- Candidate PCR2: `02b8b7b1093b3c2bbe02627e041a40e76fa99717fd285b4d29d43816584091b48d873a76f98140090816600b85361acd`
- Bridge-derived sparse-rollback AMI: `ami-0b4ed3c6d60f6714b`
- Rollback snapshot: `snap-088223183d321a1b3`
- Rollback implementation commit: `37338667f80e562b8aa2c2d58a397dbc2ce1fea0`
- Rollback evidence commit: `2212d423177095f5d76aa907052b27eabcd89c94`
- Rollback parent SHA-256: `d18529a45fa875c95c44e9c7aa7ed59e8096b83bc53d9c03d95c8aa29367c143`
- Preserved live-bridge EIF SHA-256: `6100a96de33300bac8b13e7f0700883e0fe9f14bdfb900305d55d651b95a9256`
- Preserved live-bridge PCR0: `59beb72420f56eb9b6a794b7d9ac4aced2c191ee964381cbc01d2d73e386645abe4eaa9af8757984ad52e79916029572`
- Retained-v70 PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- Preserved live-bridge PCR2: `28a6c5946a520ea6f72ace25a5cf9b57a8949c84377858e1c81457edaadd188e2b11b2eaafcb8c3352bf9e4a9f012ced`

Both AMIs are encrypted, tagged `WriterEnabled=false` and
`ProductionAccess=denied`, and protected from deregistration. Independent boot
inspection found an 8 GiB/two-CPU enclave allocation, no runtime environment,
and zero local artifact files. All temporary inspection resources were removed.

The machine-readable manifest is
`deployment/releases/3cbce68549717642c8ad525a2340b0b36262ffcb.json`.

## Verification completed

- Exact candidate source tree: library 110 passed, enclave 33 passed, parent
  121 passed with one benchmark ignored,
  and deployment template 3 passed.
- Release-mode rollback suite: 12 passed. The regression acknowledges a real
  v71 successor after a stale package, captures the exact new head, restores it
  through retained-v70 with matching sequence/state/portfolios/results/receipts,
  and proves later dispatch remains fenced.
- v71 compact commit at 45,000 historical requests, 500 samples: 5.098 ms p50,
  7.196 ms p95, 8.162 ms p99, 36,088-byte largest journal record, 874,224 KiB
  process peak RSS. This excludes network and S3 durability latency.
- v70 checkpoint concurrency at 45,000 records: 1,770 ms gate hold and 805 ms
  persistence after release; baseline order 895 ms and concurrent order
  2,659 ms. The S3-sized write is outside the financial gate.
- Bridge-derived compatibility-parent suite: 83 passed with one benchmark
  ignored. A loopback immutable-S3 rehearsal restored a sparse exact-head
  checkpoint plus a contiguous v70 successor, verified the final root and
  receipt cache, and proved ordinary v70 mode rejects the sparse archive.
- Isolated ASG rollback: candidate launch-template version 1 was replaced by
  bridge-derived rollback version 2 in 211 seconds; the candidate terminated
  and exactly one healthy rollback instance remained. The ASG, launch template
  and instances were then removed.

The rollback parent is necessary because the exact live bridge parent cannot
interpret v71 journals or a sparse archive beginning above sequence 1. The
compatibility parent is derived from the live bridge source and adds only the
strict governed sparse-baseline listing/restore path; it contains no v71
journal, shadow, promotion or materialization path. The exact live bridge image
(`5b508b…` parent plus `6100a9…` EIF) is not an immediate second hop: it may be
used only after a separately produced and rehearsed contiguous `1..head` v70
archive exists. The present three-object handoff does not create that archive.

## Remaining production gates

1. Re-run V1 against the current immutable production frontier: checkpoint
   readability, exact sequence/state/artifact hashes, zero unexplained holds,
   no other unresolved external effects, one healthy writer, and non-writer
   restore verification. Preserve the documented mm01 hold in
   `evidence/MM01_EXPLAINED_WITHDRAWAL_HOLD_20260930.json`; after promotion it
   must settle through its original idempotency key and existing Base proof,
   without hold reversal or a replacement payout.
2. Create two distinct grants. The candidate never receives the unconsumed
   rollback grant. A failed candidate cannot burn the rollback activation.
3. Sign the new immutable release manifest with the existing release signer.
   Do not create or rotate the signer key.
4. Prepare immutable successor secrets and atomic identity updates for the
   direct BFF, direct-market resolver, and public-proof publisher. Keep all old
   secrets and task definitions intact for rollback.
5. Create and inspect candidate and rollback CloudFormation change sets. The
   candidate scope must contain only the reviewed direct-execution resources;
   the rollback packet must include the ASG update. Both processed templates
   must show `HealthCheckGracePeriod: 3600` and must source the 50,000-atomic
   subsidy cap from the same hash-pinned Phase-1 configuration used by the BFF.
6. Five-minute soft abort. Hard abort is the current-frontier measured restore
   plus the measured ASG/traffic-switch duration plus five minutes, never less
   than 25 minutes. The isolated ASG component measured 211 seconds. Avoid
   `:25`-`:35` IST.

No production rollout begins if any sequence, balance, receipt, lineage,
attestation, grant, consumer identity, market, proof, deposit or withdrawal
check is ambiguous.
