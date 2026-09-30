# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue item 2: v71 second-attempt fixes and full promotion rehearsal |
| What's done | Item 1 rotation is deployed; user-flow verification is pending the user's gas-wallet decision. Commit `8f4ca93` fixes exact active-shadow checkpoint verification and moves catch-up replay outside the transition gate. The second safety review found and fixed the post-marker ambiguity: an unconfirmed promotion now permanently fences the process and fails health, and marker-selected startup rejects any unequal v70 archive tip. Both focused parent tests pass. The complete 1,000-record smoke path passed Pending load, framed v70 commit, verification, promotion, compact v71 commit, exact-head v70 seal/restore, portfolio equality and idempotent replay. Evidence is in `evidence/V71_SECOND_ATTEMPT_REHEARSAL_20260930.md`. |
| What's next | Commit the post-marker safety fix, refresh the live frontier read-only, run the release-mode production-sized concurrent rehearsal, then build/inspect both AMIs and rehearse storage promotion, exact-head rollback ASG handoff and forward/rollback identity rotation. |
| Blockers | No code/rehearsal blocker. The separate Horizen gas reserve remains below its preflight floor and must be rechecked before any production retry; no funds or thresholds will be changed here. |
| Production-affecting action pending approval | None in flight. No v71 production retry until the gas reserve passes and all rehearsal gates pass. |
| Last updated (IST) | 2026-09-30 14:16 IST |
