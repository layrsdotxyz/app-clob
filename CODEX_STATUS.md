# CODEX status

| Field | Status |
| --- | --- |
| Current step | Unified-flow engine release based on the recovered v71 production lineage. |
| What's done | The branch now carries the production recovery fixes through `01b64a6` (older-checkpoint replay, cutover-marker ancestor validation and terminal Taxi custody verification) together with policy-free pool-wallet binding, user-signed withdrawal reservation, finalized Horizen payout verification, expiry release proof and removal of the legacy Horizen USDC credit minimum. |
| What's next | Add per-deposit in-transit withdrawal holds while keeping credited funds tradable, complete the permanent checkpoint-pause fix, remove obsolete Bus/Quest runtime paths that are not needed to verify historical receipts, then build and test the new EIF. |
| Blockers | None in code. Production rollout remains contingent on a passing full suite, immutable release artifacts and the writer-grant consistency gate. |
| Production-affecting action pending approval | None; standing owner authorization applies. |
| Last updated (IST) | 2026-10-02 04:30 IST |
