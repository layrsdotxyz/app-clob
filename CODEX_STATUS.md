# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: freeze exact grants and prepare fail-closed production change sets |
| What's done | Candidate `ami-0139d10db7981b086` and rollback `ami-0f0bd57649a151201` are available, encrypted and deregistration-protected. Independent writer-disabled inspection matched both artifacts. Candidate template suites pass 12/12 and rollback suites pass 7/7. The candidate-to-rollback ASG replacement passed in 218 seconds with one healthy rollback instance and a 3,600-second health grace. The live ASG, live processed stack, retained rollback change set, candidate source and tests all resolve to 3,600 seconds; the old 300-second assertion is gone. Exact candidate and separate rollback grants verify cryptographically and remain unconsumed. Production is unchanged. |
| What's next | Commit the rehearsal/grant evidence, complete the read-only unresolved-effect audit, then create and inspect candidate and rollback production change sets. Refuse execution unless both processed templates retain exactly 3,600 seconds. |
| Blockers | Signed release manifest, consumer identity rotation and exact production change-set inspection are still required. The exact live bridge parent is not an immediate post-v71 fallback because it cannot consume the sparse archive; the bridge-derived compatibility parent is the rehearsed rollback. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 04:14 IST |
