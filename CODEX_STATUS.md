# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: current-frontier V1 and actual candidate-to-rollback ASG rehearsal |
| What's done | Candidate `ami-0139d10db7981b086` and rollback `ami-0f0bd57649a151201` are available, encrypted and deregistration-protected. Independent writer-disabled SSM inspection matched candidate parent `e65c6056…656` and EIF `fd432646…679`; rollback parent `6e69773e…0a2` and preserved bridge EIF `6100a96d…256`. Neither image contained a runtime environment, and both inspectors were terminated. Candidate template suites pass 12/12; Rust suites pass 110 library, 34 enclave and 121 parent tests. Production is unchanged. |
| What's next | Commit build evidence, rerun current-frontier V1 plus actual ASG rollback rehearsal, then prepare and inspect both processed production change sets. |
| Blockers | Current-frontier V1, refreshed AMIs, grants, signed manifest and exact production change-set inspection are still required. The exact live bridge parent is not an immediate post-v71 fallback because it cannot consume the sparse archive; the bridge-derived compatibility parent is the rehearsed rollback. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 03:53 IST |
