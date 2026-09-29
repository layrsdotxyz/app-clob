# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: deadline correction, candidate rebuild and bridge-derived rollback rehearsal |
| What's done | Exact-head handoff and bridge memory delta are committed through `009e198`. Deadline audit found and corrected the sole executable stale ten-minute value: shadow promotion now times out at 25 minutes with a duration-neutral error; old packet/runbook references are superseded or restore-based. A bridge-derived compatibility parent is separately committed and AMI `ami-0b4ed3c6d60f6714b` preserves the exact live bridge EIF while adding only strict sparse exact-head restore. Production is unchanged. |
| What's next | Commit the deadline correction, rebuild/reinspect the v71 candidate, rerun all release and rollback tests, rehearse candidate-to-compatibility-parent ASG rollback and exact-head restore, then create the successor packet with restore plus ASG/traffic switch plus five minutes and a 25-minute floor. |
| Blockers | The prior candidate `ami-0a695041bad897f9d` and draft `009e198` packet are stale after the timeout correction and must not be deployed or frozen. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 02:01:16 IST |
