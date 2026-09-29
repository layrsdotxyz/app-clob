# CODEX status

| Field | Status |
| --- | --- |
| Current step | Part A A0 complete; A1a pre-execution report next; v71 A2 correction remains non-production |
| What's done | V1 report proves retained-v70 rollback loses every post-baseline v71 commit. A0 changed only the production ASG health-check grace from 1,200 to 3,600 seconds, with no process suspension; readback showed the same healthy `i-0592e0c1c53d007da` InService and desired/min/max unchanged at 1/0/1. Evidence is in `enclave/direct-execution-v1/A0_GRACE_RESULT.md`. |
| What's next | Prepare A1a read-only bridge report: exact v70-only image/parameters, launch-template/ASG-only change-set proof, m6i.2xlarge memory/restore evidence, retained-v70 rollback path, signer inputs and current safety cutoff. Separately correct v71 rollback preservation, rebuild/rehearse both AMIs and rerun V1 before any later promotion approval. |
| Blockers | A1b execution requires explicit approval after A1a. Current v71 packet 3990739 fails rollback-preservation V1(a) and cannot be promoted. |
| Production-affecting action pending approval | A1 bridge execution and any later v71 promotion are not authorized. No production action is in flight. |
| Last updated (IST) | 2026-09-29 14:21:00 IST |
