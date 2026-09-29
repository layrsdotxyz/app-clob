# v71 rollout: no durable commands

This runbook covers the v70 bridge, the live v71 shadow, same-process
promotion, restart recovery, and the retained-v70 rollback baseline. It does
not add a durable command queue. Requests remain synchronous and serialized by
the existing in-memory financial gate. Only committed results and authenticated
state transitions are written to immutable storage.

No step in this document is authorization to deploy or mutate production.

## Hard gates

Do not begin a production rollout unless all of these are true:

1. The current checkpoint and full archive are readable by the exact live
   bridge image, which remains the pre-promotion fallback.
2. The bridge's 768 MiB frame benchmark passes within the 8 GiB enclave for
   commit, checkpoint seal, full restore, and failed oversize handling.
3. The bridge-derived sparse-rollback parent, unchanged live bridge EIF digest,
   launch inputs, and rollback commands have been independently checked.
4. There are two distinct grants: one candidate grant and one unconsumed
   rollback grant. The rollback grant is never supplied to the candidate. A
   failed candidate attempt may consume only the candidate grant.
5. A production-copy rehearsal has produced the three-object rollback
   baseline and measured handoff capture, restore, and traffic-switch time.
6. The non-writer restore verifier has accepted the latest v70 checkpoint and
   every published v71 checkpoint.
7. There is no unresolved external effect.

The soft abort is five minutes. At five minutes, stop advancing the rollout
and retain the current authoritative writer. The hard abort must be later than
the rehearsal's measured restore plus traffic-switch duration with a five
minute margin, and is never less than 25 minutes. Any shorter fixed deadline
is invalid because the measured legacy restore exceeded it. At the hard gate,
remove the candidate from routing and use the retained writer or rehearsed
rollback procedure. Never wait indefinitely for a checkpoint, shadow, grant,
or health check.

## Configuration

The bridge keeps today's behavior by default. The hot path is opt-in:

```text
LAYRS_DIRECT_PERSISTENCE_FORMAT=v71-hot
LAYRS_DIRECT_V71_SHADOW_RUN_ID=<lowercase rollout id>
LAYRS_DIRECT_V71_AUTO_PROMOTE=true
LAYRS_DIRECT_V70_ROLLBACK_PREFIX=<fresh rollback prefix>
```

`v71-hot` starts on v70 when the immutable cutover marker is absent. It starts
on v71 only when `journal-v71/cutover.cbor` exists and exactly matches the
cryptographically verified checkpoint-plus-tail head. Pre-staged migration,
checkpoint, snapshot, or journal objects cannot select v71 by themselves.

`LAYRS_DIRECT_V70_ROLLBACK_PREFIX` arms an explicit, one-shot local operator
hook; setting it alone does not capture state or affect traffic. After v71 is
authoritative, `SIGUSR2` makes the parent take the financial gate, capture the
exact committed head, and write the three-object rollback baseline. On
success it logs `V70_ROLLBACK_HANDOFF_READY` and deliberately retains the gate
until the retained-v70 ASG replaces the process. This prevents any later v71
command from being acknowledged outside the rollback package. Leave the
prefix unset until the production-shaped-copy seal duration has been measured and
the fresh prefix and rollback grant have been verified. The hook does not
capture, queue, or replay pending commands and exposes no network endpoint.

Rollback restore is explicit and never inferred:

```text
LAYRS_DIRECT_PERSISTENCE_FORMAT=v70-rollback-baseline
LAYRS_DIRECT_ARCHIVE_PREFIX=<fresh rollback prefix>
```

The rollback grant's committed frontier must exactly name the baseline head.
Normal `v70` mode rejects the sparse archive.

## Release order

### 1. Bridge

Build and retain both the old v70 EIF and the bridge EIF. Run the complete
library, enclave, and parent suites, then the production-size memory benchmark.
Roll out the bridge while the old checkpoint still fits 256 MiB. Do not change
the archive prefix or persistence format in this step.

The current CloudFormation resource has `MaxSize: 1` and
`MinInstancesInService: 0`. That resource cannot prove a zero-duration binary
replacement by itself. A release must therefore use the separately approved
writer-handoff procedure, or stop: this code does not hide that infrastructure
gap with a command queue.

### 2. Live shadow and committed-state staging

Enable `v71-hot` with a unique run id. The enclave clones the verified v70 head
and seals the migration in the background. v70 remains authoritative. Each
subsequent committed v70 result is replayed through v71 and compared inside the
enclave. A mismatch latches only the shadow and aborts promotion.

After at least one exact live match, the parent exports only committed shadow
state. It writes the migration bundle, base checkpoint, parent acceleration
snapshots, and bounded journal tail while v70 continues serving requests. No
request or pending command is exported.

### 3. Same-process promotion

The parent catches up outside the financial gate. It then takes the existing
in-memory gate, exports and persists only the final delta, verifies that no
external effect is pending, and writes the immutable cutover marker for that
exact head. The enclave promotes only if sequence and all five authenticated
head roots still match the authoritative v70 state. The parent then switches
the request path to bounded v71 journal commits and releases the gate.

There is no process restart at this cutover. If the process dies after the
marker but before the in-memory switch, restart restores the exact marked v71
head. If it dies before the marker, restart remains on v70.

### 4. Non-disruptive production soak

Keep normal traffic on the promoted writer. For every commit, monitor journal
record size, candidate time, immutable PUT/readback time, terminal ACK time,
and total latency. For every checkpoint, require disposable non-writer restore
verification before publication. Abort on a journal latch, root mismatch,
unresolved external effect, or latency regression beyond the agreed gate.

### 5. Bridge-derived v70 rollback

Keep serving v71 until rollback is actually required. Pause external dispatch,
send `SIGUSR2` to the parent service, and require
`V70_ROLLBACK_HANDOFF_READY` for the exact current sequence. The handoff reads
the authenticated migration and journal, asks the enclave for an exact v70
checkpoint, and writes exactly three objects under a fresh prefix: one full
encrypted head artifact, one head pointer, and one checkpoint discovery
marker. Every write is create-only, KMS encrypted, Object Lock protected, and
read back exactly. The parent retains the financial gate after readiness; do
not resume it or send a second signal. Execute the pre-reviewed ASG rollback
while that exact-head fence remains held.

Before a rollout that may need rollback, rehearse this against a
production-shaped copy. The rollback uses the bridge-derived compatibility
parent, unchanged live bridge EIF, fresh rollback prefix, exact committed
frontier, and separate unconsumed rollback grant. Missing, extra, mutated,
noncanonical, or wrong-frontier objects fail closed. The exact live bridge
parent is not an immediate second hop because it requires a contiguous
sequence-1-through-head archive; use it only after such an archive has been
separately produced and rehearsed.

## Abort behavior

- Shadow mismatch or timeout: leave v70 authoritative; do not write the
  cutover marker.
- Staging failure before the marker: leave v70 authoritative. Orphan immutable
  v71 objects are non-authoritative.
- Ambiguous promotion transport after the marker: restart in `v71-hot`; the
  marker selects the exact verified v71 head.
- v71 failure after promotion: stop new dispatch, trigger `SIGUSR2`, require
  exact-head `V70_ROLLBACK_HANDOFF_READY`, then execute only the rehearsed
  sparse-baseline v70 ASG restore with the retained EIF and rollback grant.
- Rollback preparation failure: do not change the ASG or consume the rollback
  grant. The gate is released and v71 remains authoritative; investigate and
  retry only with a new fresh prefix after review.
- Never route two writers, reuse a consumed grant, delete immutable evidence,
  or convert a failed attempt into a pending-command workflow.

## User withdrawal availability

This persistence work does not create an out-of-enclave withdrawal path. If
the sole writer is unavailable, new withdrawals cannot be admitted or settled
through this runtime. Providing withdrawal availability during an extended
writer outage requires a separately designed and governed recovery service;
it is not implemented by this rollout.
