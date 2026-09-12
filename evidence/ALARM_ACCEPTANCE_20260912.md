# Production alarm disposition — 2026-09-12

Devendra Tanwar authorized a bounded 72-hour acceptance for remaining
non-critical historical/operational Layrs alarms, while remediation continues.
The acceptance expires at `2026-09-15T10:30:00Z`.

Nineteen active Layrs alarms were tagged in CloudWatch with:

```text
AcceptanceOwner=Devendra Tanwar
AcceptanceExpiresAt=2026-09-15T10:30:00Z
AcceptanceScope=non-critical-historical-operational
RemediationContinuing=true
```

The tags do not disable, mute, delete, rename, suppress, redrive, or otherwise
weaken an alarm.  In particular, the legacy deposit/withdrawal DLQ remains
preserved and its legacy writer remains fenced.

`layrs-production-direct-runtime-health-missing` was excluded from acceptance
because it is activation-critical.  Its prior undimensioned metric could never
receive EC2 datapoints.  It was remediated to monitor
`AWS/EC2 StatusCheckFailed` for the current dormant direct-runtime instance
at a five-minute period with two evaluation periods and missing data breaching.
The alert action remains the existing production SNS topic.  The alarm must be
rebound to the final candidate instance during governed promotion; no state was
forced or suppressed while waiting for normal metric evaluation.
