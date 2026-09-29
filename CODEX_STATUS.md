# CODEX status

| Field | Status |
| --- | --- |
| Current step | Approved v71 completion: rebuild and rehearse the corrected pre-issued rollback-grant path |
| What's done | Current-frontier V1 passes with only the documented mm01 hold and zero unexplained holds or active deposit effects. The signed release manifest is stored in a new immutable secret under the existing signer. Review found that the prior sparse restore wrongly required a pre-issued rollback grant to name the unknowable future rollback head. The narrow correction now accepts a later exact-head checkpoint only when it cryptographically contains the signed historical frontier; targeted rollback tests pass 12/12, including later-head preservation and tamper/missing/extra-object rejection. Production is unchanged. |
| What's next | Apply the identical restore correction to the bridge-derived rollback parent, run full suites, rebuild and inspect both AMIs, repeat the ASG rollback rehearsal, then generate and inspect candidate and rollback production change sets. Refuse execution unless both processed templates retain exactly 3,600 seconds. |
| Blockers | No external blocker. Existing AMIs and their old rollback rehearsal are superseded by the correction and are not deployable. |
| Production-affecting action pending approval | The owner has approved production rollout after all listed gates pass. No production action is currently in flight. |
| Last updated (IST) | 2026-09-30 04:43 IST |
