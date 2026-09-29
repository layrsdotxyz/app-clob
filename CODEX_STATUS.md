# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: verify and commit the exact-head, fail-closed v70 rollback handoff; then merge the live bridge delta |
| What's done | Implemented an inert-until-signalled rollback handoff: local `SIGUSR2` acquires the financial gate, validates the exact v71 head and no unresolved effect, seals and durably publishes the v70 package, and retains the gate until ASG replacement. Normal v71 commits remain journal-only; no durable command or network operator route was added. Added and passed a regression proving a post-capture v71 commit cannot cross the gate while the package restores in retained-v70 mode with exact sequence, state, portfolios and receipts. Added the mandatory production gates for browser attestation/portfolio, resolver lifecycle, proof progress and binding-error logs. |
| What's next | Run the complete rollback group and review; commit the narrow correction; merge bridge memory/checkpoint fixes; run library/enclave/parent/template suites; rebuild candidate and rollback AMIs; rehearse promotion, post-promotion traffic, `SIGUSR2` fencing, complete ASG rollback and exact balance/receipt/sequence continuity; rerun V1; then execute the approved rollout with all release-identity consumers rotated atomically. |
| Blockers | None. Production remains untouched until V1, both AMI rehearsals, complete ASG rollback, restore-timed abort gates and consumer-identity rotation all pass. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 00:55:44 IST |
