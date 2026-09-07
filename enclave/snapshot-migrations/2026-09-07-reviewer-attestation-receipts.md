# Reviewer-attested receipt metadata

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 3f389df6b7e75caa89e6b6f280c476a465441664
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
CUMULATIVE_STATE_MIGRATION: true
FUNDED_CANARY_REQUIRED: true

Release owner: Layrs protocol owner. This document records the mandatory
migration and certification gates for the reviewer-attestation candidate. It is
not permission to deploy an EIF, rotate a PCR policy, start another writer,
change the production market maker, or accept funded traffic.

## Exact persisted-state delta

The top-level `CoreStateSnapshot`, ledger, order book, market, session, reward,
resolution, replay-key, sequence, state-root, and encrypted-journal envelope
schemas are unchanged.

`EnclaveReceipt` gains one optional `reviewer_event` object containing only a
bounded public event type and the terminal status `COMPLETED`. The field uses a
Serde default and is omitted when absent. Historical receipts therefore decode
with `reviewer_event = None` and serialize to the same signed payload; they are
not relabelled, resigned, rewritten, or backfilled.

New journal-committed mutations may emit a `layrs.v3` receipt whose signature
binds the reviewer event, command commitment, result commitment, journal policy,
sequence, roots, and journal hash. Existing `layrs.v1`, `layrs.v2`, and
`layrs.v3` receipts retain their original protocol version and signature bytes.
Read-only and preview commands remain ineligible for reviewer publication.

The encrypted command result or recovery state can contain an
`EnclaveReceipt`, so this additive nested field is conservatively treated as a
cumulative state migration even though no top-level snapshot member changes.
No historical state transformation is required. The first reviewer-attested
receipt is a normal forward state transition.

## Production replay plan

Before any production activation:

1. Fence all private mutations and record the exact active writer, production
   snapshot object/version/body hash, complete journal boundary, sequence,
   journal head, state root, base AMI, parent binary, EIF hash, PCR0/1/2,
   receipt-verification key, signed release manifest, and KMS policy.
2. Restore that unmodified snapshot into the passive candidate EIF through the
   existing recipient-bound attested restore path. Require exact equality of
   sequence, journal head, state root, aggregate asset and bucket totals,
   available balances, order and withdrawal holds, positions, orders, fills,
   resolutions, markets, sessions, rewards, fees, direct final results, and all
   replay keys. No mutation is permitted during this comparison.
3. Decode and verify every retained receipt shape present in the snapshot and
   archived terminal-result set. For historical receipts, require
   `reviewer_event = None`, byte-identical signature payload reconstruction,
   and the original signature result. Reject any receipt that changes protocol
   version, commitment, journal binding, sequence, root, hash, timestamp, or
   signature after candidate decoding.
4. Run delegated private reads for at least two identities and prove strict
   isolation plus no change to sequence, state root, journal head, snapshot
   hash, balances, or holds.
5. In isolated Green, execute one allowlisted example for every reviewer event
   class reached by the release. Verify the event is inside the exact
   enclave-signed payload, contains no account, wallet, order, market, balance,
   amount, price, destination, or free-form value, and is emitted only after a
   journal-committed mutation. Preview/read-only and rejected no-effect vectors
   must not produce a completed reviewer event.
6. Replay each Green request with the same idempotency key, restart the enclave,
   and replay again. Require one state transition, one journal record,
   byte-identical terminal result, valid receipt signature, unchanged principal,
   and no duplicate reviewer event. Tampered event type/status, removed result
   commitment, changed publication policy, changed journal flag, and altered
   roots/hash/signature must all fail closed.
7. Build the candidate from the reviewed commit, record reproducible parent/EIF
   hashes and SBOMs, measure PCR0/1/2, attest the isolated host, and repeat the
   snapshot restore and receipt checks against that exact measured artifact.
8. Immediately before cutover, repeat steps 1 through 4 against the then-current
   production snapshot and archive boundary. Any mismatch, unresolved command,
   unknown outcome, missing archive object, invalid historical signature, or
   non-empty second-writer capability is a hard stop.

Only privacy-safe hashes, aggregate reconciliations, event-taxonomy counts, and
signed pass/fail evidence may leave the enclave. Private snapshot plaintext and
account-level state must not be exported.

## Activation order

1. Keep the candidate passive while exact restore and read-only gates run.
2. Deploy downstream receipt readers that tolerate the optional field while
   reviewer publication remains disabled.
3. Install the measured candidate as the sole private writer only after the old
   writer is fenced and the current snapshot replay certificate passes.
4. Run one capped, reversible Green-equivalent production canary for a
   non-financial mutation, then one explicitly approved funded canary. Reconcile
   state, journal, receipt archive, projections, and reviewer output after each.
5. Open broader traffic only after duplicate, response-loss, restart, privacy,
   signature, and rollback gates remain green.

## Rollback plan

Before the first reviewer-attested candidate mutation, stop the candidate and
restore the retained base launch-template version, AMI, parent binary, EIF, PCR
allowlist, KMS policy, encrypted snapshot, and journal boundary. Because no
candidate state has committed, no data rewrite or journal truncation is needed.

After the first reviewer-attested receipt is committed, never replay that state
with the older binary. Disable new mutations, retain the candidate snapshot,
journal, receipts, archive, manifests, and measured artifacts, and recover
forward with this schema or a separately reviewed compatible successor. Never
delete a reviewer event, receipt, replay key, direct result, or journal record;
never edit a balance or truncate the journal to force rollback.
