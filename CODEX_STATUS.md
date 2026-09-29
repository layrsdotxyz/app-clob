# CODEX status

| Field | Status |
| --- | --- |
| Current step | Part 2 V1 complete; V2 blocked and not approvable |
| What's done | V1 report written. Proven that retained-v70 rollback loses every v71 commit after its one-time captured baseline. Frontier 41,416; checkpoint 41,414 is 237,196,916 B and still v70-readable. Read-only archive/DB checks show zero withdrawal holds and no unresolved external effect. Observed unplanned production OOM and automatic ASG replacement; no intervention made. |
| What's next | Continue read-only monitoring of automatic v70 restore. Await owner decision between a narrowly corrected rollback-preservation packet and a bridge-only emergency release; rerun V1 before any V2 action. |
| Blockers | Current packet 3990739 fails V1(a). Production parent OOM occurred at 2026-09-29 13:20:11 IST; replacement was still restoring at last check. V2 requires explicit approval and must not execute from the current packet. |
| Production-affecting action pending approval | V2 writer fence, grants, manifest rotation and CloudFormation execution are pending approval; none is in flight. |
| Last updated (IST) | 2026-09-29 13:31:15 IST |
