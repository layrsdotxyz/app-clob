# CODEX status

| Field | Status |
| --- | --- |
| Current step | Part 2 V1 complete; V2 blocked and not approvable |
| What's done | V1 report written. Proven that retained-v70 rollback loses every v71 commit after its one-time captured baseline. Frontier advanced from 41,416 to 41,418 during the automatic recovery. Read-only archive/DB checks show zero withdrawal holds and no unresolved external effect. Observed the unplanned OOM and first automatic replacement without intervention. The replacement completed restore after about 21 minutes, two seconds after the ASG had already selected it for termination, then durably committed 41,417 and 41,418. |
| What's next | Continue read-only monitoring of the second automatic v70 restore and sequence continuity. Await owner decision between a narrowly corrected rollback-preservation packet and a bridge-only emergency release; rerun V1 before any V2 action. |
| Blockers | Current packet 3990739 fails V1(a). The production ASG health grace is 1,200 seconds while the observed restore took about 1,261 seconds, causing an automatic replacement loop and continued direct-lane unavailability. V2 requires explicit approval and must not execute from the current packet. |
| Production-affecting action pending approval | V2 writer fence, grants, manifest rotation and CloudFormation execution are pending approval; none is in flight. |
| Last updated (IST) | 2026-09-29 13:48:30 IST |
