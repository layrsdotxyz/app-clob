# CODEX status

| Field | Status |
| --- | --- |
| Current step | v71 production rollout stopped at no-go; retained-v70 rollback completed |
| What's done | Candidate restored exact v70 sequence 43,205 but v71 promotion aborted before cutover with `journal checkpoint verification mismatch`. The immutable cutover marker is absent. The reviewed pre-promotion rollback executed with the separate grant and restored exact sequence 43,207; the rollback writer is the sole healthy instance, has zero restarts, and projection advanced monotonically to 43,217. User balances and commits were preserved; mm01 remains the same single explained hold and no payout was duplicated. |
| What's next | Stop. Diagnose the checkpoint-verification mismatch and prepare a separately reviewed rollback-identity consumer rotation before any new production action. Do not resume v71 or rotate consumers from this failed packet. |
| Blockers | Hard no-go: BFF and proof publisher reject the new rollback grant/key-release binding with `QUEST_PUBLIC_RECEIPT_BINDING_INVALID`. Proofs are not advancing and the user-facing release bar is not met, despite the healthy financial writer. |
| Production-affecting action pending approval | None in flight. Further production changes require a corrected, reviewed packet. |
| Last updated (IST) | 2026-09-30 06:09 IST |
