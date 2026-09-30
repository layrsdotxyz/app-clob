# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue item 2: v71 second-attempt fixes and full promotion rehearsal |
| What's done | Item 1 rotation is deployed; user-flow verification is pending the user's gas-wallet decision. Commits `8f4ca93`, `963340b` and `f231bc4` fix active-shadow verification, non-blocking catch-up, fail-closed marker/promotion ambiguity, and isolate staged v71 records from authoritative v70 heads. Full direct-execution tests pass. A conservative 90,000-history path passed but its 7,980,460 KiB peak is too close to 8 GiB for a 90k operating claim. The post-fix current-frontier rerun passed at 44,840 history through promotion, compact successor and exact-head v70 restore at 44,907; p50/p99 framed commits were 4.53/4.73 s, compact commit 59 ms and peak RSS 3,905,604 KiB. Candidate `ami-030d6c96d9509c615` and paired rollback `ami-03627140f4af90a9c` are built, protected and independently inspected. Isolated ASG candidate-to-rollback handoff passed in 208 seconds with exactly one healthy v2 instance and 3,600-second grace; all temporary resources were removed. The release-mode S3 exact-head three-object materialization and baseline restore test reran successfully at 15:16 IST. Evidence is in `evidence/V71_SECOND_ATTEMPT_REHEARSAL_20260930.md`. |
| What's next | Rehearse forward/rollback identity handoffs, generate signed immutable release artifacts, refresh the production frontier, and inspect exact production change sets. |
| Blockers | No code/rehearsal blocker. The separate Horizen gas reserve remains below its preflight floor and must be rechecked before any production retry; no funds or thresholds will be changed here. |
| Production-affecting action pending approval | None in flight. No v71 production retry until the gas reserve passes and all rehearsal gates pass. |
| Last updated (IST) | 2026-09-30 15:16 IST |
