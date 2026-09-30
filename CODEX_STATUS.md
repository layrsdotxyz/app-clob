# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue item 1: retained-v70 rollback identity consumers rotated; internal-account flow verification stopped on a freshly reconfirmed reserve no-go |
| What's done | Fresh Nitro attestation verified the rollback identity. New immutable manifest, BFF Phase-1, publication-successor, and administration Phase-1 secrets were created with only release-identity fields changed; predecessors remain untouched. BFF `:189`, proof publisher `:33`, and quest administration `:88` are each 1/1 healthy and all stacks are `UPDATE_COMPLETE`. Public manifest and attestation verify; the BFF stayed up; publisher binding failures stopped and at least 23 Horizen batches confirmed. Evidence: `evidence/ROLLBACK_IDENTITY_CONSUMER_ROTATION_20260930.md`. |
| What's next | Obtain exact transfer authorization identifying the funding source and amount before any movement into the shared Horizen operating wallet. Then rerun internal-account signup setup, deposit and withdrawal checks. Do not skip queue item 1 or begin the v71 second attempt first. |
| Blockers | Fresh read at 10:36 IST reconfirmed `QUEST_PREFLIGHT_RESERVE_SHORTFALL`: Horizen company native balance remains exactly `91636664139358` wei versus `102000000000000` required, a `10363335860642` wei deficit. Funding is a real-money action outside the identity-only approval. |
| Production-affecting action pending approval | None in flight. A separate authorization is required to top up the public company address by at least the `10363335860642` wei deficit plus operational margin. |
| Last updated (IST) | 2026-09-30 10:36 IST |
