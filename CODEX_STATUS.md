# CODEX status

| Field | Status |
| --- | --- |
| Current step | Unified-flow release integration while the recovered v71 writer remains live and untouched. |
| What's done | The engine candidate includes source-finality credit with per-deposit in-transit withdrawal holds, user-signed withdrawals bound to live assets, finalized Horizen payout verification, hot seven-day writer-grant renewal, the checkpoint health fix, the stale migration-bundle selection fix, the v71 cold-restart fixes and exact BNB 18-to-6 decimal normalization. Full engine suites passed. Parent-only candidate AMI `ami-02608d2bc5bdf2419` was baked from canonical commit `5fe6494511686e5cfef3455e9d3127509c6efa47`; its parent hash was independently read back, while its EIF hash and PCR0/PCR1/PCR2 are byte-for-byte unchanged from the tested `7dca9dd` candidate. The fill-to-Horizen-proof canary remains unproven since the outage and must be the first funded unified-flow end-to-end check. |
| What's next | Complete backend/consumer CI and stale Quest/Bus cleanup, execute the two queued LayrsPool upgrades after their timelocks, deploy the engine candidate under a programmatically built successor grant, then roll backend/frontend and run deposit, trade, proof and withdrawal canaries. |
| Blockers | The pool upgrade timelocks mature on 2026-10-03 at 01:49:34 and 01:51:58 UTC. The live writer grant is not a blocker: the production row, exact versioned artifact and live attestation all report expiry Unix `1791496258` (2026-10-08 21:50:58 UTC). Do not rotate or restart the live writer on 2026-10-02. |
| Production-affecting action pending approval | None; standing owner authorization applies. |
| Last updated (IST) | 2026-10-02 10:05 IST |
