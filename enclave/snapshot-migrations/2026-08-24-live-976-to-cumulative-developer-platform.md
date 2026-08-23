# Live 976 to cumulative Developer API, MCP and x402 state migration

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 97614f37c05089708f93bf50ac8831adde98ab2f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

This declaration covers review of the cumulative private-core feature base
`c820266a0163ef807423467b26964db6763a2742` against the exact production EIF
source release above. It is a fail-closed migration gate, not permission to
deploy, activate an EIF, rotate PCR policy, or accept funded traffic.

## Exact persisted-state delta

The encrypted `CoreStateSnapshot` adds a bounded `recovery_capsules` map with a
Serde default. A 976 snapshot therefore decodes it as empty. Recovery capsules
are not directly included in the state-root function; their processed-command
and archive markers are. The first candidate command that creates a capsule or
marker is consequently a forward state transition.

`LedgerWire` retains the same three fields: balances, applied idempotency keys,
and sequence. The candidate decoder is intentionally stricter: it rejects zero
balances, duplicate accounts, malformed account components and malformed replay
keys. The 976 mutation code could retain a zero-valued account after a full
debit, so compatibility must be proven against the actual final production
snapshot. A synthetic green fixture is not sufficient.

The candidate appends vault-cash, strategy-in-transit and strategy-receivable
account-bucket enum values. Historical enum values are unchanged. It also adds
new journal/result fields with Serde defaults, trusted-time markers in the
existing encrypted `system_keys` set, and a durable PREPARE/DURABLE/FINALIZE
protocol. Pending prepared transitions are runtime state; the durable manifest,
successor snapshot and journal record are external recovery artifacts and must
be treated as one commit boundary.

The first trusted-time command adds a versioned high-water marker and changes
the state root. Historical roots remain byte-compatible before that marker is
installed. New balanced custody postings do not synthesize historical
`PoolCash`; an independently reconciled opening balance is required before the
new deposit and withdrawal model is activated.

## Required exact-live fixture and replay evidence

Before an EIF is built for activation, export the frozen 976 encrypted snapshot
and immutable journal together with its sequence, journal head, state root,
parent AMI, EIF hash, PCR0/1/2, release manifest and anchored minimum sequence.
Perform the following offline against the candidate:

1. decrypt and restore the real snapshot with the production-lineage key only
   inside the approved attested recovery environment;
2. require byte-for-byte equality of sequence, journal head and pre-transition
   state root;
3. require exact equality of every user available/order/withdrawal hold,
   position, order, fill, resolution, reward, fee, market and replay key;
4. record the legacy zero-account count while preserving the historical root;
   reject duplicate accounts, malformed accounts and malformed replay keys;
   remove zero accounts only inside the journaled historical opening transition;
5. reconcile custody and all user liabilities by asset and chain, then post the
   governed historical `PoolCash` opening balance without changing a user
   balance;
6. prove the opening transition, new snapshot and journal record as one
   auditable migration artifact and re-run conservation; and
7. save only hashes, qualified totals and signed equality evidence outside the
   enclave. Never export private account-level plaintext.

The attested runner report must bind `sourceReleaseCommit` to exact 976 and
`checkpointSha256` to the checkpoint file supplied to the wrapper; otherwise
the wrapper rejects the report even if every equality boolean is true.

Any failed restore or equality check is a hard stop. Do not canonicalize,
rewrite or manually edit the production snapshot to make the candidate load.
The privacy-safe wrapper for the attested runner is
`scripts/certify-live-976-cumulative-restore.sh`; a synthetic fixture does not
replace its real frozen-artifact report.

## Durable-command and cross-PCR gate

Before starting a candidate writer, fence all old private mutations and prove
there is no in-flight legacy command, pending preparation, unfinalized durable
manifest, evidence-pending receipt, queue item or outbox item. Install and test
the host persistence schema and grants first.

The release policy must bind the source and target PCR0 values, snapshot schema,
manifest commitment, successor snapshot hash, journal-record hash, current
writer fence and policy hash. Retain the old EIF until every old-PCR durable
manifest is finalized. The candidate must reject readiness if it cannot prove a
contiguous anchored head and an empty unresolved-manifest set.

## Activation order

1. Restore the frozen 976 snapshot in a passive candidate and produce the exact
   equality report.
2. Run delegated private reads for at least two identities and prove strict
   isolation, recipient-only decryption and no sequence/root/head change.
3. Run negative capability, audience, environment, expiry, revocation,
   substitution, tamper, nonce and replay vectors.
4. Run unfunded PREPARE crash/restart/finalize vectors with the old writer still
   fenced and prove exactly-once recovery.
5. Apply and reconcile the historical custody opening transition.
6. Enable one candidate writer only; run capped Developer API order/cancel,
   MCP approval/trading and x402 paid-order canaries with exact receipts,
   idempotency and ledger conservation.
7. Certify usage logs, latency and error rates without exposing secrets or
   private command payloads.

## Rollback boundary

Before the candidate records a trusted-time marker, historical opening posting,
recovery capsule, durable manifest or any other mutating command, rollback is a
direct return to the retained 976 AMI, EIF, snapshot, journal and PCR policy.

After the first candidate durable or state transition, direct rollback to 976 is
prohibited. Freeze mutations, retain all candidate artifacts, and recover
forward with the candidate EIF or a separately governed cross-measurement
successor. Never truncate a journal, delete a durable manifest, remove a posting
or edit a user balance to recover the old root.
