# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: current-frontier V1 and production change-set preparation |
| What's done | Final candidate source `3cbce68` removes the obsolete fixed timeout and passes 121 parent tests with 1 benchmark ignored. Encrypted protected candidate `ami-00498fa3f6e6a20e8` independently matches parent `6b6ead2f…` and preserved v71 EIF/PCRs. Bridge-derived rollback `ami-0b4ed3c6d60f6714b` matches parent `d18529a4…` and the exact live bridge EIF. Its suite passes 83 tests with 1 benchmark ignored, including sparse baseline plus successor restore. A real isolated ASG rollback replaced candidate version 1 with rollback version 2 in 211 seconds, left exactly one healthy rollback instance, and all rehearsal resources were removed. Packet/runbook/controller audit has zero obsolete short-gate matches; hard abort is measured restore plus measured ASG/traffic switch plus five minutes, floor 25 minutes. Production is unchanged. |
| What's next | Commit the successor packet, run current-production-frontier V1 and non-writer restore verification, then prepare separate grants, existing-signer manifest, exact candidate/rollback change sets and atomic BFF/resolver/proof-publisher identity rotation. |
| Blockers | Current-frontier V1, grants, signed manifest and exact production change-set inspection are still required. The exact live bridge parent is not an immediate post-v71 fallback because it cannot consume the sparse archive; the bridge-derived compatibility parent is the rehearsed rollback. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 02:25:18 IST |
