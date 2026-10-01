# v71 production no-go and rollback — 2026-09-30

Result: **NO-GO; v71 was not promoted. Production rolled back to the retained
v70 EIF with the bridge-derived rollback parent.**

## Candidate timeline (IST)

- Projection authority rebound to candidate: 05:12:46.
- Candidate change-set execution: 05:13:09.
- Writer availability pause began: 05:13:42.
- Non-writer checkpoint verification accepted sequence 43,205: 05:37:01.
- Exact v70 restore completed at sequence 43,205: 05:37:15.
- First post-restore commit completed: 05:37:54.
- Load-balancer target became healthy: 05:39:27.
- v71 shadow remained non-authoritative. It wrote one migration object only;
  `journal-v71/cutover.cbor` was absent.
- Promotion aborted at 05:42:09 with
  `journal checkpoint verification mismatch`.

The failure occurred before the immutable cutover marker. All candidate
commits therefore remained ordinary authoritative v70 full-state artifacts.

## Abort and rollback timeline (IST)

- Rollback projection authority committed: 05:43:19.
- CloudFormation had invalidated the pre-created sibling change sets after the
  candidate stack update. The pre-promotion rollback change set was recreated
  from the frozen rollback template and signed inputs, then re-inspected. It
  changed exactly `DormantLaunchTemplate`, `DormantAutoScalingGroup`, and
  `RuntimeRole`; processed grace was 3,600 seconds; format was `v70`; archive
  prefix was the authoritative opening-epoch prefix.
- Rollback change-set execution: 05:44:45.
- Rollback writer pause began: 05:45:20.
- Retained-v70 exact restore completed at sequence 43,207: 06:04:57.
- First rollback-writer commit completed: 06:05:31.
- Rollback target became load-balancer healthy: 06:06:44.

## Verified post-state

- Exactly one ASG instance: `i-091fc1eb35b3542eb`, healthy, launch-template
  version 75, rollback AMI `ami-00b8bd8408d5008db`.
- Exactly one projection fence and one grant, bound to
  `layrs-v70-rollback-b980988-20260930-b020a0e0`.
- Projection reached 43,217 receipts after rollback. The immutable archive
  advanced monotonically beyond the candidate's last v70 head; no commit or
  user balance was rolled back.
- The known mm01 withdrawal remains exactly one `BOARDED` hold with the same
  reservation receipt and no settlement/rejection receipt. No replacement
  payout was submitted.
- Parent restart count is zero. Peak observed parent cgroup memory during the
  candidate restore was approximately 3.36 GB; rollback restore remained below
  the 8 GiB enclave allocation and completed.

## Remaining no-go

The rollback grant has a new grant commitment and key-release artifact even
though it retains the bridge EIF/PCR0. The BFF and proof publisher still pin
the previous bridge binding. They now emit
`QUEST_PUBLIC_RECEIPT_BINDING_INVALID`; proof publication is not advancing and
the mm01 worker cannot record settlement. This is exactly the release-identity
consumer gap the rollout gate was intended to prevent.

No BFF, proof-publisher, resolver, secret, publication pointer, database
financial row, customer balance, or withdrawal was changed after detecting
this no-go. Continuing requires a separately reviewed rollback-identity
consumer packet or a corrected v71 build; this rollout is stopped.
