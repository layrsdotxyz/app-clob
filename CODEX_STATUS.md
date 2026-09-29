# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: design and implement zero-loss v70 rollback preservation, then merge the live bridge delta |
| What's done | Reconfirmed V1(a): packet `3990739` captures one v71 head and loses every acknowledged successor on retained-v70 rollback. Confirmed the existing exact-head materializer releases the financial gate before package persistence and is one-shot, so it cannot be the final rollback guarantee. Added the missing mandatory production gates: authenticated browser attestation/portfolio smoke, resolver capability and market lifecycle, proof-frontier/backlog progress, and zero new BFF/publisher binding errors. Auditing the narrowest lineage-preserving correction against the existing rollback worker branches and the live bridge commit `d5e65d7`. |
| What's next | Implement the corrected rollback lineage and its post-capture v71-commit test; merge bridge memory/checkpoint fixes; run library/enclave/parent/template suites; rebuild candidate and rollback AMIs; rehearse promotion, post-promotion commits, complete ASG rollback and exact balance/receipt/sequence continuity; rerun V1; then prepare and execute the approved production rollout with all release-identity consumers rotated atomically. |
| Blockers | None. Production remains untouched until V1, both AMI rehearsals, complete ASG rollback, restore-timed abort gates and consumer-identity rotation all pass. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-29 23:24:00 IST |
