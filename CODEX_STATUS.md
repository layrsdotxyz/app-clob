# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue item 2: v71 second-attempt fixes and full promotion rehearsal |
| What's done | Item 1 rotation is deployed; user-flow verification is pending the user's gas-wallet decision. Commits `8f4ca93` and `963340b` fix exact active-shadow verification, non-blocking catch-up, and fail-closed post-marker promotion ambiguity. Current-frontier rehearsal passed at 44,779 history through exact promotion, compact successor and exact-head v70 restore with 4,105,296 KiB peak RSS. A conservative 90,000-history run also passed with a 182.6 MB artifact and 300.5 MB rollback checkpoint; its 7,980,460 KiB peak is too close to 8 GiB for a 90k operating claim. Parent storage review then found and corrected the v70/v71 same-sequence key collision, restart namespace confusion, and ambiguous marker-write gate release. Corrected parent suite passes 124/124 with one benchmark ignored. Evidence is in `evidence/V71_SECOND_ATTEMPT_REHEARSAL_20260930.md`. |
| What's next | Complete the full direct-execution suite, commit the parent storage correction, refresh the production frontier, run parent S3 staging/marker plus full promotion/rollback rehearsal, then build/inspect both AMIs and rehearse the exact ASG and forward/rollback identity handoffs. |
| Blockers | No code/rehearsal blocker. The separate Horizen gas reserve remains below its preflight floor and must be rechecked before any production retry; no funds or thresholds will be changed here. |
| Production-affecting action pending approval | None in flight. No v71 production retry until the gas reserve passes and all rehearsal gates pass. |
| Last updated (IST) | 2026-09-30 14:40 IST |
