# A0 ASG health-check grace result

Status: **COMPLETE**  
Executed: 2026-09-29 14:16 IST  
Authorization: final master instruction A0

## Exact change

- Auto Scaling group:
  `layrs-production-direct-execution-dormant-DormantAutoScalingGroup-7IpwwCXpbuJL`
- Region/profile: `us-east-1` / `predifi-root`
- Before: `HealthCheckGracePeriod=1200`
- After: `HealthCheckGracePeriod=3600`

No ASG process was suspended. No launch template, instance, desired/min/max
capacity, AMI, task, database, S3 object, writer, grant, or application setting
was changed.

## Independent readback

Immediately after the update, `describe-auto-scaling-groups` returned:

- grace `3600`;
- health check type `ELB`;
- desired/min/max `1/0/1`;
- no suspended processes;
- `i-0592e0c1c53d007da` remained `Healthy` and `InService`.

The five most recent scaling activities were unchanged; the latest remained the
successful launch of `i-0592e0c1c53d007da` at `2026-09-29T08:14:08.100Z`.
There was no restart or replacement caused by A0.

## Persistence requirement

Every A1 or later CloudFormation change set must preserve
`HealthCheckGracePeriod=3600`; any plan that reverts it fails inspection.
