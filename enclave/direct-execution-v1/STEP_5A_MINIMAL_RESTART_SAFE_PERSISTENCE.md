# Step 5A — minimal restart-safe direct execution

## Decision

Reuse the existing encrypted snapshot/journal primitives from
`app-clob/src/private_core/{engine,journal}.rs` and the immutable artifact
archive in `app-backend/packages/enclave-artifacts`.  The clean runtime must
not treat PostgreSQL as a state source.

For this new epoch, every state-changing direct command produces one
**self-contained encrypted commit artifact**.  It contains the complete next
private state, the encrypted journal record, the signed receipt, and the
request/idempotency commitment.  A successful immutable object write is the
only financial commit boundary.  This deliberately chooses a full encrypted
snapshot per command: the opening state is small, the operation is simple,
and it avoids inventing a separate journal-replay importer for the clean
runtime.  Snapshot compaction can be evaluated later, after correctness is
proven.

The object is opaque outside the enclave.  PostgreSQL stores a copy of public
receipt/accounting metadata and an optional index, but no PostgreSQL row is
required to restore, select, or verify private financial state.

## Existing capability and gap

Already present in the repository:

* `EncryptedJournal` creates AEAD-encrypted, hash-chained records with
  sequence, prior-record hash, next state root, and ciphertext hash.
* `EncryptedSnapshot` binds the full encrypted state to sequence, journal
  head, and state root; `PrivateTradingCore::restore_encrypted_snapshot`
  verifies the authenticated state root and rollback floor.
* `ReceiptSigner` derives a stable receipt key from the protected journal key;
  receipts carry prior root, next root, journal hash, command commitment, and
  signature.
* `EnclaveArtifactArchive` already writes immutable, checksummed objects with
  `IfNoneMatch: '*'`, verifies a post-write readback, and records immutable
  metadata.  The recovery runbook already specifies restore plus contiguous
  journal verification.

The clean direct runtime has none of those state-persistence types.  It mutates
`DirectRuntime` memory, then its parent writes a PostgreSQL projection.  That
is why the isolated restart returned the opening `5,000,000` balance while the
projection retained a `1,000,000` withdrawal reservation.

## Authoritative artifact

`DirectCommitArtifact` is an encrypted, versioned payload stored under a
write-once key such as:

```
direct-state/<epoch-id>/commits/<request-hash>.cbor
```

Its cleartext envelope is limited to integrity/recovery fields:

```
epoch_id, format_version, sequence, prior_sequence,
prior_state_root, prior_journal_head, state_root, journal_head,
request_hash, request_id, receipt_id,
snapshot_ciphertext_hash, journal_record_hash
```

Its encrypted payload contains the complete direct state: balances, orders,
holds, processed request hashes and terminal receipts.  It is sealed with the
existing `JournalKey`/AEAD format and authenticated to the envelope values.
The embedded receipt is signed with the stable enclave receipt signer.  The
state root includes the processed-request map, so replay protection is part of
the authoritative state, not a PostgreSQL session table.

The sealed opening epoch is sequence 0.  It remains the genesis artifact and
is never altered.  A committed artifact is a successor only when its prior
sequence/root/head exactly match the current committed state.

## One-request commit semantics

The external API remains exactly one synchronous request:

```
authenticated request -> parent -> enclave -> direct execution
  -> immutable encrypted commit write -> enclave adopts commit -> response
```

Internally, the existing VSOCK exchange needs a bounded persistence callback:

1. The enclave executes against a clone of its committed state.  It creates
   the candidate encrypted commit artifact and signed terminal receipt, but
   does not mutate its live committed state and does not expose success.
2. The parent writes that exact opaque artifact through the existing immutable
   archive adapter, with `If-None-Match: *`, checksum, version/object-lock
   policy, and post-write `HeadObject` verification.
3. The parent returns only the immutable object identity and artifact hash to
   the enclave.  The enclave verifies they equal its candidate and then swaps
   the cloned state into memory.
4. Only then does the enclave return the receipt.  The parent may write the
   PostgreSQL projection before responding, but its failure does not undo or
   redefine the committed private state.

This is a synchronous durability acknowledgement inside one request, not an
admission/preparation/finalization protocol.  There are no durable command
records, queues, leases, timers, retries, or externally visible intermediate
states.  There is one command, one immutable state artifact, and one terminal
receipt.  The only valid terminal outcomes are `COMMITTED` and
`REJECTED_EFFECT_NONE`; an uncertain network result is resolved by looking up
the same request hash, never by executing a new transition.

Because Nitro enclaves have no independent object-storage transport, the
untrusted parent must relay ciphertext.  The enclave verifies all identity,
state-root, hash-chain, artifact-hash, and receipt bindings; the parent cannot
substitute a state artifact or manufacture success.

## Recovery, integrity, and replay

At boot, the enclave obtains the same protected journal key through the
attested KMS/key-release path already used by the legacy core.  It lists only
the epoch's immutable commit prefix, decrypts and verifies every candidate,
and selects the unique contiguous chain beginning at sealed genesis.  For each
successor it verifies sequence +1, prior root/head, journal record hash,
snapshot ciphertext hash, receipt signature, and recomputed state root.

The highest verified contiguous artifact is authoritative.  A missing,
forked, corrupt, non-decryptable, or non-contiguous successor freezes writes
and reports `DIRECT_STATE_RECOVERY_FAILED`; it never falls back to PostgreSQL
or a lower state.  A deployment-provided recovery floor (sequence/root) must
be at or below the selected artifact, preventing rollback.

For a duplicate request after crash, recovery loads the processed request hash
and receipt from the encrypted artifact.  The same request hash returns the
same receipt.  The same request ID with different content is rejected.  A
request already written to object storage but not acknowledged is therefore
committed once, never run a second time.

PostgreSQL disagreement is a projection incident: receipt/accounting rows are
repaired from verified encrypted artifacts.  PostgreSQL can never create,
choose, alter, or restore a private state.

## Failure matrix

| Case | Safe result |
|---|---|
| A. Execute and immutable write succeeds | Enclave adopts candidate; signed receipt is returned; projection follows. |
| B. Execute and write fails | Candidate is discarded; no state swap, receipt, or success. Retry is safe. |
| C. Parent crashes before acknowledgement | If no object exists, no effect. If object exists, restart discovers it; retry returns its receipt. |
| D. Enclave crashes before persistence | Clone was never adopted; restart uses prior committed artifact. |
| E. Enclave crashes after persistence before acknowledgement | Restart selects the new artifact; retry returns its existing receipt exactly once. |
| F. Duplicate after restart | Processed request commitment in restored encrypted state returns prior receipt; mismatched content is rejected. |
| G. Stale command after restart | Its prior-root/request context cannot match current state and is rejected with no effect. |
| H. Corrupt artifact | AEAD/hash/root verification fails; writes freeze and incident recovery is required. |
| I. Missing successor | The last contiguous artifact is used only if it meets the recovery floor; otherwise fail closed. |
| J. PostgreSQL differs | Private state remains the verified artifact; projection is reconciled from it and no financial state is reconstructed from SQL. |

## Required changes (not implemented in Step 5A)

1. `enclave/direct-execution-v1/src/lib.rs`
   * Add the direct state snapshot, encrypted journal/receipt types, state-root
     calculation, protected-key restore, candidate construction, verified
     recovery, and persisted request/receipt index.
   * Change execution from in-place mutation to clone/candidate/adopt.
2. `enclave/direct-execution-v1/src/bin/enclave.rs`
   * Add the bounded encrypted-artifact persistence callback over the existing
     VSOCK session and reject an unmatched persistence acknowledgement.
3. `enclave/direct-execution-v1/src/bin/parent.rs`
   * Replace `record_result` as the financial commit point with an immutable
     ciphertext artifact writer.  Keep `record_result` projection-only and
     reconcile it from committed artifacts.
4. A new direct-runtime artifact adapter package, extracted narrowly from
   `app-backend/packages/enclave-artifacts/src/index.ts`
   * Isolated S3-compatible test implementation and production object-lock/KMS
     configuration.  It must contain no Durable Command imports or tables.
5. `enclave/direct-execution-v1/sql/001_direct_execution_projection.sql`
   * Add non-authoritative commit-artifact metadata and reconciliation cursor;
     do not add balances as a restore source.
6. `enclave/direct-execution-v1/nitro/*`
   * Add only attested key-release and isolated object-storage configuration.
     No writer authority is enabled by these changes.

No `DURABLE_*` schema, command queue, preparation row, lease, state transition
table, or alternate financial writer is introduced.

## Implementation scope and proof plan

Estimated implementation scope: roughly 500–800 Rust lines, 150–250 adapter
and SQL lines, plus isolated tests.  It requires a new measured EIF because
the enclave protocol and direct state serialization change; Step 5A does not
build or deploy it.

Required isolated tests:

1. Genesis plus one reservation: restart returns `4,000,000`, the identical
   signed receipt, root, and sequence—not the old `5,000,000` state.
2. Fault injection before immutable write: no artifact and `5,000,000` after
   restart.
3. Fault injection after write/before reply: restart returns `4,000,000`; a
   duplicate returns exactly the stored receipt.
4. Parent and enclave crash cases, duplicate/mismatched request IDs, stale
   command, corrupted artifact, missing link, rollback floor, and SQL outage.
5. Assert PostgreSQL can be deleted/rebuilt from encrypted artifacts without
   changing recovered TEE state.
6. Verify one direct request emits exactly one immutable artifact and no
   `DURABLE_PREPARATION_*`, PREPARE, FINALIZE, queue, lease, or staged command
   state is present in the clean execution path.

## Boundary

This is a design only.  It does not change the sealed epoch, current isolated
runtime, AWS resources, Production, Green, balances, custody, writer authority,
or historical sequence 75594.
