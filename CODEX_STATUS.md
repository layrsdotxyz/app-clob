# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: refreshed candidate/rollback builds and V1 rehearsal |
| What's done | Candidate and rollback templates read the 50,000-atomic cap from the same SHA-256-pinned Phase-1 configuration used by the BFF; the CloudFormation parameter is a fixed 50,000 deployment guard. The mm01 hold is documented as explained and proof-backed, with no revert or replacement payout. Candidate source and both health-grace tests require `HealthCheckGracePeriod: 3600` and at least the 25-minute restore-based floor. Read-only AWS inspection confirmed both the current production stack and retained rollback change set resolve to 3600. Candidate template suites pass 12/12; candidate Rust suites pass 110 library, 34 enclave and 121 parent tests with only explicit benchmarks ignored. Non-writer checkpoint verification is committed at `15ddb90`. Production is unchanged. |
| What's next | Commit the cap/health/evidence packet, rebuild candidate and rollback artifacts, rerun current-frontier V1 plus actual ASG rollback rehearsal, and inspect both processed change sets. |
| Blockers | Current-frontier V1, refreshed AMIs, grants, signed manifest and exact production change-set inspection are still required. The exact live bridge parent is not an immediate post-v71 fallback because it cannot consume the sparse archive; the bridge-derived compatibility parent is the rehearsed rollback. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 03:38 IST |
