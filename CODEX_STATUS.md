# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue item 2: v71 second-attempt fixes and full promotion rehearsal |
| What's done | Item 1 rotation is deployed; user-flow verification is pending the user's gas-wallet decision. Commits `8f4ca93` and `963340b` fix exact active-shadow verification, non-blocking catch-up, and fail-closed post-marker ambiguity. Focused parent tests pass. The complete smoke rehearsal passed. The release-mode current-frontier run also passed at 44,779 history + 64 Pending + 2 framed commits through exact promotion, compact successor and exact-head v70 restore at 44,846. It measured 4.49s p50/4.99s p99 local framed v70 commits, 61ms compact commit and 4,105,296 KiB peak RSS. Evidence is in `evidence/V71_SECOND_ATTEMPT_REHEARSAL_20260930.md`. |
| What's next | Run a conservative production-byte-sized memory rehearsal because the same-sequence synthetic artifact/checkpoint were smaller than production, then run the full suite, build/inspect both AMIs and rehearse storage promotion, exact-head rollback ASG handoff and forward/rollback identity rotation. |
| Blockers | No code/rehearsal blocker. The separate Horizen gas reserve remains below its preflight floor and must be rechecked before any production retry; no funds or thresholds will be changed here. |
| Production-affecting action pending approval | None in flight. No v71 production retry until the gas reserve passes and all rehearsal gates pass. |
| Last updated (IST) | 2026-09-30 14:23 IST |
