# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: immutable candidate/retained-v70 builds and production-copy rollback rehearsal |
| What's done | Committed the exact-head fail-closed rollback handoff (`76eeeab`): local `SIGUSR2` takes and retains the financial gate through package publication and ASG replacement; no durable command or network route was added. The regression now materializes sequence 4, acknowledges a real v71 successor at sequence 5, refreshes and restores retained-v70 at exact sequence 5 with matching state/portfolios/results, and proves the next commit is fenced. Integrated the live bridge memory delta: 768 MiB frame, 250,000-record bound, `MALLOC_ARENA_MAX=2`, zero-copy S3 body, non-fatal post-restore seal, five-minute refresh, and gate release before checkpoint S3 persistence. Exact tree passes core 110/110 (3 ignored benchmarks), enclave 33/33, parent 121/121 (1 ignored benchmark), and template 3/3. |
| What's next | Correct the abort/runbook packet; build immutable v71 and retained-v70 EIF/AMIs from the exact tree; inspect hashes/PCRs; rehearse promotion, post-promotion traffic, `SIGUSR2` fencing, complete ASG rollback and exact balance/receipt/sequence continuity on a production copy; rerun V1; then execute the approved rollout with atomic release-identity consumer rotation. |
| Blockers | None. Production remains untouched until V1, both AMI rehearsals, complete ASG rollback, restore-timed abort gates and consumer-identity rotation all pass. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 01:02:14 IST |
