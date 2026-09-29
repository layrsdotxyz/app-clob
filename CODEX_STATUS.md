# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 production rollout: final current-frontier refresh, projection-authority handoff, candidate execution and identity-consumer rotation |
| What's done | Current-frontier V1 passes with only the documented mm01 hold and zero unexplained holds. Candidate and rollback suites pass; replacement AMIs are encrypted, hash-inspected and protected. Separate signed candidate/rollback grants verify. The isolated ASG candidate-to-rollback rehearsal passed in 220 seconds. Candidate, pre-promotion rollback and post-promotion exact-head rollback change sets are AVAILABLE, each changes exactly DormantLaunchTemplate, DormantAutoScalingGroup and the narrow RuntimeRole, and every processed template resolves HealthCheckGracePeriod to 3,600 seconds. The existing signer produced a new immutable v71 manifest; predecessor secrets are untouched. Production is still on the bridge. |
| What's next | Refresh the mutable frontier and no-go gates, atomically rebind the projection authority to the candidate, execute the inspected candidate change set outside :25–:35 IST, monitor restore/promotion under the restore-based deadline, rotate all three release-identity consumers, then run post-release flow/proof/market checks. |
| Blockers | None. Any second writer, unexplained hold, lineage/grant mismatch, new unresolved external effect, scope drift, or grace below 3,600 seconds is a hard no-go. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 05:08 IST |
