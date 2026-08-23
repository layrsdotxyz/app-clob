# Durable command state-machine migration

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: e1fb04eeb225560ce2ddc833a4e246c98c9066ab
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
FUNDED_CANARY_REQUIRED: true

Story: E07-S07. Release owner: Layrs financial-core owner. This approval covers
the forward-only PREPARE -> DURABLE -> FINALIZE command protocol and does not
authorize deployment, migration execution, or funded traffic.

## Compatibility and state change

- Legacy snapshots restore without a pending prepared transition. The first
  prepared transition is held outside the live financial core and cannot alter
  balances, orders, journal sequence, state root, receipts, audit output, or
  TaskOn output before FINALIZE.
- A signed preparation binds the environment, source EIF measurement and
  snapshot schema, actor and exact command bindings, writer-fence epoch and
  lease, prior and successor sequence/root/journal head, and every staged
  journal, snapshot, receipt, audit, task, and padded-response digest.
- FINALIZE opens the exact staged successor snapshot and swaps it atomically.
  Same-head retries are idempotent; branches, gaps, lower writer epochs, and
  mismatched manifests fail closed.
- Terminal command rejections are signed and exact-bound no-op results. An
  unsigned parent, proxy, or transport status cannot make a command ABORTED.
- The durable manifest is the irrevocable commit decision. Only PREPARED work
  without a durable manifest may be superseded. DURABLE work always rolls
  forward before the enclave becomes ready or admits another mutation.

## Roll-forward procedure

1. Drain all legacy financial mutations and prove there are no in-flight
   commands before enabling the versioned durable coordinator.
2. Install the immutable command schema and coordinator-only writer grants,
   then start the coordinator/reconciler with release disabled.
3. Build and measure the candidate EIF. Preserve the exact S06 EIF until every
   old-measurement DURABLE manifest is FINALIZED.
4. Provision the current append-only chain head and writer-fence epoch; reject
   readiness until all contiguous DURABLE manifests have been restored and
   finalized.
5. Enable the versioned API and browser pending-command protocol only after the
   coordinator, enclave, artifact store, and status endpoint pass the exact
   readiness handshake.
6. Run capped unfunded crash vectors before any funded canary.

## EIF transition and rollback boundary

Same-measurement FINALIZE is the normal path. Cross-measurement roll-forward is
allowed only for an already-DURABLE immutable manifest and a governed release
policy that binds the source and target PCR0 values, snapshot schema, manifest
commitment, all successor hashes, and a short-lived current writer fence. The
target EIF must embed the exact approved policy hash and successfully decode
and authenticate the old successor snapshot. An operator signature alone does
not authorize an arbitrary source measurement.

Before the first DURABLE manifest, rollback may restore the exact S06 release
and its latest anchored snapshot. After the first DURABLE manifest, rollback to
an S06 binary is prohibited. Recovery is roll-forward using the old EIF or an
explicitly governed compatible target EIF; authoritative command, manifest,
object-version, and chain-head history remains append-only.

## Required evidence

- no live-state mutation before the durable manifest and no accepted response
  before FINALIZE plus durable response release;
- crash cuts at admission, prepare response loss, object write/readback,
  SERIALIZABLE manifest commit, enclave apply, DB FINALIZED, and response loss;
- exact retry at every transition and monotonic state with no regression;
- multiple-replica writer takeover, heartbeat loss, stale epoch rejection, and
  a greater-than-30-second exact preparation rebind without re-execution;
- fresh-core nonzero sequence-zero root and contiguous multi-row restore;
- old-PCR DURABLE to governed new-PCR FINALIZE, plus unapproved-policy rejection;
- signed terminal rejection, account-bound browser recovery, delivery ACK,
  response retirement, failed deletion retry, and retained manual-review paths;
- bootstrap venue-intent-before-I/O and sponsored-withdrawal unknown-outcome
  reconciliation without blind resend; and
- measured maximum-state clone/snapshot latency and memory within the EIF
  release budget before funded canary approval.
