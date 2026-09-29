# v71 release packet: `9f93fb0`

This is the frozen pre-production packet for the full-state write-amplification
bridge and v71 hot migration. It is not authorization to deploy. Do not execute
the production commands until the named rollout owner has approved the current
frontier, both grants, and the abort sheet.

The release contains no Durable Commands and does not add a command queue.

## Immutable release identity

- Source commit: `9f93fb017d1578c04ecaeb6ab44eb3886dae2c57`
- Candidate AMI: `ami-09a85e9808a6da50e`
- Candidate parent SHA-256:
  `a52c57f3b9f6afcbac24f2b5134ada6036ecc4c4ab4dd425c01ddb9ade79a2ea`
- Candidate enclave binary SHA-256:
  `2c550442d9105f8d60d33fc82d4b439d6fce13efd33262e05fb1e8db84213ac7`
- Candidate EIF SHA-256:
  `00af4c138d35c8b7efaeaaac1e92e3b15d2f0568f6a43bc9f2fe79f0aed8ce18`
- Candidate PCR0:
  `d7ee4c71e109ca62a676a6460a2f0c790eaf6a8e73ba36ef624ea744d7ebaa7215bc7ce4b3483cc4d98f73bc54f980e5`
- Candidate PCR1:
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- Candidate PCR2:
  `5f5b11b872fd76984dd780163d7048db4711c583a4f25fe50317f4b7d748bd34e95f3dcecf1f9777067375d374b3d305`
- Retained-v70 rollback AMI: `ami-093fabb94cc52931e`
- Retained-v70 EIF SHA-256:
  `ff165914950152093be4b8088aec45d853ef32a68935b85ee710a85e57cb7ade`
- Retained-v70 enclave binary SHA-256:
  `a133d806cd893d357cc722bf5f70b27d7096dd828785cd122af4263b80f94fe4`
- Retained-v70 PCR0:
  `ddc56e079110c40b0f5014ae07645279b9e59d9f8a6c9cea2e56398f259c43758a293caa8b48562541a9ce23167fc721`
- Retained-v70 PCR1:
  `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- Retained-v70 PCR2:
  `6204f86cccc410f4643f1190e2c6f67ef6b325ca08ca26cc979047ecdc74f9587f9cc9a2e4baef893f44359ad4c754ac`

Both AMIs are encrypted, tagged `WriterEnabled=false` and
`ProductionAccess=denied`, and have image-deregistration protection enabled.
Isolated inspection found no runtime environment and no local artifacts. The
inspection instances, build instances, temporary keypairs, and temporary
security groups were removed.

The machine-readable copy is
`deployment/releases/9f93fb017d1578c04ecaeb6ab44eb3886dae2c57.json`.

## Exact candidate measurement binding

The governance-signed candidate grant must embed this object exactly:

```json
{
  "amiId": "ami-09a85e9808a6da50e",
  "eifSha256": "00af4c138d35c8b7efaeaaac1e92e3b15d2f0568f6a43bc9f2fe79f0aed8ce18",
  "pcr0": "d7ee4c71e109ca62a676a6460a2f0c790eaf6a8e73ba36ef624ea744d7ebaa7215bc7ce4b3483cc4d98f73bc54f980e5",
  "pcr1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
  "pcr2": "5f5b11b872fd76984dd780163d7048db4711c583a4f25fe50317f4b7d748bd34e95f3dcecf1f9777067375d374b3d305",
  "sourceCommit": "9f93fb017d1578c04ecaeb6ab44eb3886dae2c57",
  "enclaveSha256": "2c550442d9105f8d60d33fc82d4b439d6fce13efd33262e05fb1e8db84213ac7",
  "parentSha256": "a52c57f3b9f6afcbac24f2b5134ada6036ecc4c4ab4dd425c01ddb9ade79a2ea"
}
```

The rollback binding uses the rollback AMI, the same parent hash, and these
retained-v70 values: EIF `ff165914...7ade`, enclave
`a133d806...4fe4`, PCR0 `ddc56e07...c721`, PCR1
`4b4d5b36...a493`, and PCR2 `6204f86c...54ac`. It must be generated in full
from the machine-readable release manifest, reviewed, and signed separately.

## Completed pre-rollout evidence

- Exact release suite: library 110 passed with 3 ignored; enclave 33 passed;
  parent 119 passed.
- v71 at 35,000 historical results: 36,081-byte largest journal record,
  4.904 ms p50, 6.970 ms p95, 7.603 ms p99, 346,096 KiB peak RSS.
- v70 bridge at 200,000 records: 428,796,104-byte full artifact,
  688,466,676-byte checkpoint, 3,506,420 KiB peak RSS, exact full restore.
- The CloudFormation template validates and its v71 bootstrap tests pass.
- A deleted, never-executed change set showed only the launch template and
  Auto Scaling group changing.
- The candidate and rollback AMIs were inspected independently and are not
  attached to the production launch template, ASG, or target group.

## Rollout-only inputs

These values are intentionally not precomputed because they must bind the
actual frozen production head:

1. exact sequence, state hash, artifact hash, checkpoint key and checkpoint
   size immediately before handoff;
2. independently verified old-writer fence evidence;
3. a fresh candidate activation id and signed candidate grant;
4. a distinct fresh rollback activation id and unconsumed signed rollback
   grant;
5. fresh candidate and rollback grant commitments;
6. the fresh v71 shadow run id and fresh rollback archive prefix;
7. the public attestation manifest containing the exact candidate PCRs and an
   expiry beyond the rollout and observation window;
8. confirmation that no external effect is unresolved.

Do not place a grant, runtime binding, credential, token, or secret value on a
shell command line. Supply the reviewed CloudFormation parameter JSON through
a root-only temporary file outside the repository and delete that file after
CloudFormation has accepted it.

## Production execution order

Use AWS profile `predifi-root` and region `us-east-1` throughout.

1. Re-read production health, target health, ASG/LT versions, archive head,
   checkpoint size, current latency, grant expiry, public-manifest expiry, and
   unresolved external effects. Stop if the old 256 MiB reader cannot restore
   the current checkpoint.
2. Freeze and independently record the authoritative frontier. Fence the old
   writer according to the existing governed handoff procedure. Confirm only
   one writer can become eligible.
3. Produce and independently verify two grants. The candidate receives only
   the candidate grant. The rollback grant remains outside the candidate
   parameters and unconsumed.
4. Create a CloudFormation change set against stack
   `layrs-production-direct-execution-dormant`, using the exact checked-in
   template and `UsePreviousValue` for every unrelated parameter. Override
   only the candidate AMI, candidate binding/grant/PCRs and these values:

   ```text
   PersistenceFormat=v71-hot
   V71ShadowRunId=<fresh-lowercase-run-id>
   V71AutoPromote=true
   V70RollbackPrefix=<fresh-object-lock-prefix>
   ```

5. Inspect the change set. It must modify only `DormantLaunchTemplate` and
   `DormantAutoScalingGroup`; it must not modify the database, archive bucket,
   KMS keys, secrets, load balancer, target group, security groups, market
   services, or publisher. Delete the change set on any deviation.
6. Record the five-minute soft-abort and ten-minute hard-abort timestamps,
   then execute once. Do not retry with the same candidate grant.
7. Require exact candidate attestation, grant commitment, verified restore,
   sequence/root continuity, healthy target, and no second writer before
   restoring normal routing. Require at least one exact v70-to-v71 replay match
   before the immutable cutover marker is accepted.
8. Require `V70_ROLLBACK_MATERIALIZER_COMPLETE` for the exact promoted head.
   Verify its three create-only objects and measure the materialization time.
   Do not treat a merely started materializer as rollback readiness.
9. Continue normal production traffic as the soak. Watch total commit latency,
   journal candidate time, object PUT/readback, ACK time, journal record size,
   sequence continuity, all authenticated roots, checkpoint verification,
   unresolved effects, and writer health.
10. Before the handoff, inventory every release-identity consumer and prepare
    rollback-pinned rotations for the direct-market resolver, direct BFF and
    public-proof publisher. After the candidate attests, rotate their exact
    PCR/binding/manifest inputs together; preserve predecessor task definitions
    and immutable secrets. A healthy writer alone is not release success.
11. Run an authenticated production browser smoke as a normal user. Require a
    verified enclave, trading enabled, and a readable private portfolio; abort
    on `TRADING BLOCKED`, an attestation error, or an admission/portfolio error.
12. Require the direct-market resolver capability check to pass against a fresh
    nonce-bound candidate attestation, and verify the current market is open
    and the first due resolution completes without a capability failure.
13. Require the public-proof publisher frontier to advance and the pre-handoff
    backlog to drain without a permanent gap or duplicate. Query both BFF and
    publisher logs from handoff onward and require zero new
    `QUEST_PUBLIC_RECEIPT_BINDING_INVALID` and
    `QUEST_PUBLIC_RECEIPT_ATTESTATION_INVALID` errors. Any failure is an
    incomplete release step and triggers the reviewed consumer/runtime rollback.

The reviewed candidate invocation is:

```bash
aws --profile predifi-root --region us-east-1 cloudformation create-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_CANDIDATE_CHANGE_SET" \
  --change-set-type UPDATE \
  --template-body file://deployment/layrs-direct-execution-production.template.yaml \
  --parameters "file://$LAYRS_CANDIDATE_PARAMETERS" \
  --capabilities CAPABILITY_NAMED_IAM

aws --profile predifi-root --region us-east-1 cloudformation describe-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_CANDIDATE_CHANGE_SET"

aws --profile predifi-root --region us-east-1 cloudformation execute-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_CANDIDATE_CHANGE_SET"
```

The candidate parameter file overrides only `CandidateAmiId`,
`PersistenceFormat`, `V71ShadowRunId`, `V71AutoPromote`,
`V70RollbackPrefix`, `WriterGrantBase64`, `ApprovedRuntimeBindingBase64`,
`WriterGrantCommitment`, and `ApprovedPcr0/1/2`. Every other existing
parameter uses `UsePreviousValue: true`.

## Abort and rollback

- **Five minutes:** stop advancement. Do not consume another grant, write a
  cutover marker manually, or broaden scope.
- **Ten minutes:** remove the candidate from routing and execute rollback. Do
  not wait indefinitely for restore, health, shadow, materialization, or a
  checkpoint.
- Before v71 is authoritative, rollback uses AMI
  `ami-093fabb94cc52931e`, `PersistenceFormat=v70`, the unchanged production
  archive prefix, and the separate rollback grant pinned to the frozen v70
  frontier.
- After v71 is authoritative, rollback uses the same retained-v70 AMI,
  `PersistenceFormat=v70-rollback-baseline`, the fresh materialized prefix,
  and a rollback grant whose committed frontier exactly names that baseline.
- A failed candidate can consume only its own activation id. Never supply the
  rollback grant to a candidate launch, and never retry a consumed activation.
- Remove or terminate the failed writer before making the rollback writer
  eligible. Rollback is a writer handoff, not a traffic-only switch.

After the candidate stack operation has reached a terminal state, the reviewed
rollback invocation is:

```bash
aws --profile predifi-root --region us-east-1 cloudformation create-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_ROLLBACK_CHANGE_SET" \
  --change-set-type UPDATE \
  --template-body file://deployment/layrs-direct-execution-production.template.yaml \
  --parameters "file://$LAYRS_ROLLBACK_PARAMETERS" \
  --capabilities CAPABILITY_NAMED_IAM

aws --profile predifi-root --region us-east-1 cloudformation describe-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_ROLLBACK_CHANGE_SET"

aws --profile predifi-root --region us-east-1 cloudformation execute-change-set \
  --stack-name layrs-production-direct-execution-dormant \
  --change-set-name "$LAYRS_ROLLBACK_CHANGE_SET"
```

The rollback parameter file overrides the rollback AMI and binding, the
separate rollback grant and commitment, retained-v70 PCRs, the applicable
archive prefix, and either `PersistenceFormat=v70` or
`PersistenceFormat=v70-rollback-baseline`. It sets `V71ShadowRunId`,
`V70RollbackPrefix` to empty and `V71AutoPromote=false`. The change set must be
inspected before execution even under the hard-abort path; a pre-reviewed
root-only parameter file is what keeps that inspection within the ten-minute
limit.

## Important availability limit

The current production ASG has `MaxSize=1`; the runtime has no durable command
queue. Therefore a strict zero-duration outage during the initial EIF/writer
replacement cannot be promised by this release. The handoff must be bounded by
the five/ten-minute rule, and requests made while there is no healthy writer
cannot be durably queued by this system. This must be accepted explicitly or a
separately approved dual-slot handoff must be built before execution.

The v71 promotion itself is same-process and does not restart the writer. The
post-promotion soak uses normal production traffic; there is no separate shadow
soak requirement.
