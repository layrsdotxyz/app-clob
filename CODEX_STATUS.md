# CODEX status

| Field | Status |
| --- | --- |
| Current step | Retained-v70 rollback identity consumers rotated; post-check stopped on an independent reserve no-go |
| What's done | Fresh Nitro attestation verified the rollback identity. New immutable manifest, BFF Phase-1, publication-successor, and administration Phase-1 secrets were created with only release-identity fields changed; predecessors remain untouched. BFF `:189`, proof publisher `:33`, and quest administration `:88` are each 1/1 healthy and all stacks are `UPDATE_COMPLETE`. Public manifest and attestation verify; the BFF stayed up; publisher binding failures stopped and at least 23 Horizen batches confirmed. Evidence: `evidence/ROLLBACK_IDENTITY_CONSUMER_ROTATION_20260930.md`. |
| What's next | Stop scope expansion. Obtain explicit authorization before any funds movement to restore the shared Horizen native reserve floor. After that, rerun internal-account signup setup, deposit and withdrawal checks; v71 remains separately stopped on its checkpoint-verification no-go. |
| Blockers | Deposit, withdrawal, and wallet-setup admission preflights fail `QUEST_PREFLIGHT_RESERVE_SHORTFALL`: Horizen company native balance is `91636664139358` wei versus `102000000000000` required. All other configured reserve floors pass. Funding is outside this identity-only approval. |
| Production-affecting action pending approval | None in flight. A separate authorization is required to top up the public company address by at least the `10363335860642` wei deficit plus operational margin. |
| Last updated (IST) | 2026-09-30 10:34 IST |
