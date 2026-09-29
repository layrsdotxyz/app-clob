# v71 V1 pre-execution report

Status: **FAILED / V2 NOT APPROVABLE**  
Observed: 2026-09-29 13:31 IST  
Scope: read-only production and source inspection; no production change was made.

## Executive result

The release packet cannot safely enter V2 as written. Its retained-v70 rollback
package captures one v71 head. Every v71 commit after that capture is absent
from the package. A post-promotion rollback would therefore move the ledger
backward, discard acknowledged trades/deposits/withdrawals/resolutions, and
reuse sequence numbers from a different state lineage.

This is independent of the current production incident: at 13:20:11 IST the
live v70 parent was killed by the Linux OOM killer. The ASG automatically
started a replacement at 13:22:07 IST. At report time the replacement was
still restoring and had not opened port 8443. Codex did not cause or intervene
in that replacement.

## V1(a): rollback semantics

Answer: **rollback restores the one materialized baseline; it does not preserve
post-materialization v71 commits.**

Evidence:

- Hot promotion enables v71 and releases the financial gate before rollback
  capture (`src/bin/parent.rs:7758-7765`).
- The materializer's own contract says commits after the captured head are not
  in the package (`src/bin/parent.rs:7769-7774`).
- It reads one eligible v71 head (`src/bin/parent.rs:7793-7798`), verifies that
  the head did not move while taking the gate (`src/bin/parent.rs:7815-7824`),
  then seals that exact state (`src/bin/parent.rs:7833-7858`).
- The startup hook invokes the materializer once and logs failure without a
  retry loop (`src/bin/parent.rs:7873-7914`).
- The package contains exactly three objects: one full artifact, one head
  pointer and one checkpoint (`src/bin/parent.rs:3462-3514`).
- Sparse rollback restore reads only that fresh rollback prefix. Any later
  successors must already be contiguous v70 artifacts in that prefix
  (`src/bin/parent.rs:3516-3625`, `src/bin/parent.rs:3631-3726`).
- `PersistenceFormat=v70-rollback-baseline` dispatches to that sparse restore;
  it does not read or convert the authoritative v71 journal
  (`src/bin/parent.rs:7233-7251`).

The current test named `v70_rollback_baseline_restores_contiguous_v70_successors`
injects a synthetic v70 successor into the rollback prefix. It does not test a
v71 commit after capture followed by rollback. There is also no production
test for the `v70 rollback head advanced` branch or the one-shot startup hook.

Required correction before V2: provide a rollback path whose governed v70
frontier is refreshed to the exact last acknowledged v71 head before writer
handoff, or an equivalent continuously proven representation. The corrected
test must commit on v71 after initial materialization, roll back, and prove the
same sequence, state root, balances, effects and receipts without sequence
reuse. This needs a separately approved code/release packet; it is not safe to
improvise during rollout.

## V1(b): current frontier and retained-v70 readability

At 13:19:41 IST immediately before the OOM:

- Authoritative S3 head and DB projection: sequence **41,416**.
- Sequence 41,416 artifact: **160,740,132 bytes**.
- Latest verified checkpoint: sequence **41,414**, **237,196,916 bytes**.
- Retained-v70 frame ceiling: **268,435,456 bytes (256 MiB)**.
- Remaining checkpoint headroom: **31,238,540 bytes (29.79 MiB)**.

Therefore `ami-093fabb94cc52931e` can still read the latest checkpoint by frame
size. The AMI is `available`, encrypted, and has deregistration protection
enabled. This does not cure the post-promotion rollback loss described above.

Production incident evidence:

- Old instance `i-0c79d376c4eae72a7`: OOM kill at 07:50:11 UTC.
- ASG activity: automatic replacement due to ELB health-check failure.
- Replacement `i-044e96d1f819baf72`: old v70 AMI, launched 07:52:07 UTC;
  restoring, target unhealthy/port not listening at the report timestamp.
- ASG remains `MinSize=0`, `MaxSize=1`, `DesiredCapacity=1`, with a 1,200-second
  health grace period.

Post-report incident update (read-only observation at 13:46 IST):

- The replacement logged `VERIFIED_ARCHIVE_RESTORE_START 41414/41416` at
  08:13:30 UTC and `VERIFIED_ARCHIVE_RESTORE_COMPLETE 41416` at 08:14:08 UTC,
  about 21 minutes after its final service start.
- The ASG had already selected it for replacement at 08:14:06 UTC, two seconds
  before restore completed, because the 1,200-second health grace expired.
- Before termination/draining completed, the restored writer durably committed
  sequences 41,417 and 41,418 and persisted verified checkpoints for both.
- The parent used about 970 MiB RSS after restore and no second OOM was present.
  This replacement was lost to a health-grace race, not memory pressure.
- The ASG automatically launched `i-0592e0c1c53d007da` at 08:14:08 UTC. The
  direct lane remained unavailable while that second replacement initialized.

The current incident therefore adds a second independent lockout mechanism:
the normal v70 restore duration is already longer than the ASG health grace.
Unless a subsequent restore happens faster, the ASG will recycle otherwise
valid writers just as they become ready. No ASG setting, instance, or runtime
was changed during this observation.

Emergency recovery option, requiring explicit owner approval: temporarily
suspend only the ASG `HealthCheck` and `ReplaceUnhealthy` processes before the
current instance's grace expires; allow the existing v70 restore to complete;
verify a healthy target, exactly one writer and continuity from sequence
41,418; then update the governed ASG health grace from 1,200 to 1,800 seconds
and resume both processes. AWS documents that `HealthCheck` marks failed ELB
instances unhealthy and `ReplaceUnhealthy` terminates/replaces them; suspending
those two processes is the narrow reversible control for this loop. It does
not change the AMI, writer grant, ledger, archive, database or desired capacity.
It is an incident recovery action, not approval to execute V2 packet 3990739.

## V1(c): external effects and withdrawals

Read-only archive plus PostgreSQL checks at sequence 41,416 found:

- Positive `USER_WITHDRAWAL_HOLD` balances: **0 accounts, 0 atomic USDC**.
- Immutable external-effect intents: **10**.
- Exact terminal committed matches: **9**, all `WITHDRAWAL_SETTLED`.
- Remaining intent: a field-equivalent duplicate of a request whose sibling
  intent is committed; immutable reconciliation evidence exists for that
  duplicate. This is the explicit duplicate-intent path in
  `recover_external_effect_intents` (`src/bin/parent.rs:8416-8443`), not an
  unresolved effect.
- Latest immutable intent was written 2026-09-18 21:42:36 UTC.

Conclusion: **no unresolved external effect and no in-flight withdrawal at the
41,416 frontier.** The current runtime is nevertheless unavailable while its
automatic replacement restores.

## V1(d): rollout window and signer inputs

There is no safe V2 window for the current packet. The previously proposed
15:40-17:10 IST window is withdrawn because V1(a) failed and production is
already in an automatic restore incident.

For a corrected packet, the signer must provide two distinct, independently
reviewed authorizations through root-only temporary files, never command-line
arguments or repository files:

1. Candidate grant: fresh activation id; exact candidate AMI/EIF/parent/enclave
   hashes and PCRs from the immutable manifest; exact frozen v70 sequence,
   state hash and artifact hash; fresh v71 shadow run id; expiry covering the
   bounded rollout.
2. Rollback grant: separate fresh activation id, never supplied to the
   candidate; retained-v70 AMI/EIF/parent/enclave hashes and PCRs; and the exact
   rollback baseline sequence/state/artifact hashes. Under the current design
   those exact safe hashes do not exist until a post-promotion baseline is
   produced, and that baseline immediately becomes stale when another v71
   commit is acknowledged. Pre-signing it does not solve V1(a).

Both grants must remain unconsumed until their respective writer handoff. A
consumed activation is never retried.

## Timing and decision required

The last measured checkpoint growth leaves only hours before the 12-hour safety
margin is breached, and the OOM shows production has already hit a memory wall
before the frame wall. The immediate choices require owner approval:

1. Approve a narrowly corrected rollback-preservation release, rebuild and
   re-verify both AMIs, then rerun V1; or
2. Approve a bridge-only emergency release to restore memory/frame safety while
   the rollback-preservation correction is completed.

V2 must not execute from release packet `3990739` in its current form.

## Read-only commands and queries used

- `aws ... autoscaling describe-auto-scaling-groups` and
  `describe-scaling-activities`
- `aws ... ec2 describe-images`, `describe-instances`, and
  `describe-instance-status`
- `aws ... elbv2 describe-target-health`
- `aws ... s3api list-objects-v2` for `artifacts/`, `heads/`, `checkpoints/`,
  `external-effect-intents/`, and reconciliation prefixes
- Short SSM `journalctl`, `systemctl`, `free`, `ps`, `ss`, and local health
  reads; no host files or configuration were changed
- PostgreSQL `BEGIN READ ONLY` through an ephemeral SSM port forward:
  positive withdrawal-hold aggregate; receipt/effect aggregates; and exact
  intent-to-terminal-receipt matching. The temporary CA file was mode 0600 and
  deleted; no credential or DB URL was printed or persisted.
