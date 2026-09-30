# v71 Parent Journal Persistence Plan (Worker B)

Status: plan only. This document authorizes no code change, AWS call, S3
write, deployment, EIF, or grant use. Base contract:
`FULL_STATE_JOURNAL_V71_CONTRACT.md`. Baseline commit on this branch:
`200d90e`.

Scope: the smallest parent-side production-code change that (a) durably
appends one `DirectJournalRecord` per commit, write-once, conditional on the
expected writer epoch, sequence, and predecessor head; (b) fences writers at a
head; (c) lists and restores checkpoint-plus-tail at startup; and (d) confines
shadow mode. It reuses the existing S3/Object Lock primitive unchanged.
Enclave semantics, the journal format, the v71 checkpoint format, compaction,
matching, custody, and receipts stay with Codex (contract lines 171-178).

All `parent.rs` references are `enclave/direct-execution-v1/src/bin/parent.rs`.
`lib.rs` and `journal.rs` are under `enclave/direct-execution-v1/src/`.

---

## 1. What exists today (the pattern this plan reuses)

| Concern | Current code |
|---|---|
| Only write primitive | `write_once` parent.rs:2123-2161. A single `PutObject` with `If-None-Match: *` (2139), SSE-KMS (2140-2141), Object Lock `COMPLIANCE` plus retain-until (2142-2143), then a full `read` of the object and a byte comparison (2148-2159). |
| Idempotent retry | `put.is_err()` with an identical readback counts as success (2149). This covers an SDK retry (3 attempts, 2052) after a lost 200. |
| Sequence conflict | A `/heads/` key with different bytes returns `ARCHIVE_SEQUENCE_CONFLICT` (2150-2155), which maps to HTTP 409 (4346-4350). |
| Ambiguous PUT | `bounded_archive_operation` timeout (95-105, 60 s at 83) returns `ARCHIVE_TIMEOUT` through `?` at 2146 **without readback**. |
| Sequence slot | `archive_head_key` = `{prefix}/heads/{seq:020}.cbor` (1790-1792). Create-only, so at most one head per sequence. |
| v70 two-object commit | Artifact, then head (`persist_readback` 2304-2333, order at 2313-2320). |
| Commit exchange | `exchange_direct` 5972-6064: `Execute` → `CommitCandidate` (6005) → persist/readback (6010) → `DurabilityAck` (6028-6038) → `Execute` terminal. On success, `committed_state_root` is updated (6040-6043), then a checkpoint refresh runs (6048-6062). |
| Restore listing | `list_restore_keys` 2337-2380 (paginated, repeat-token and duplicate checks, bound). `prepare_restore` 2381-2480. `restore_streamed` 2481-2620. |
| v70 head parse | A non-legacy head body must be exactly 64 lowercase hex characters, or restore fails (2410-2421). |
| Startup order | Stale enclave reset (2957-2964) → preflight (2965-2977) → `recover_enclave` (2981, S3 branch 4941) → projection reconcile (2985, 5537-5582) → intents (2987). |
| Transport enums | `RuntimeRequest` lib.rs:3659-3732 and `RuntimeResponse` lib.rs:3735-3783. `DurabilityAck` lib.rs:1220-1267. |
| Journal record | `DirectJournalRecord` journal.rs:41-58. `seal` 79-162. `open_successor` 165-244. `record_hash` 246-248. |

Journal properties this plan relies on (updated by Codex after the worker
review):

- **Sealing is deterministic for an identical complete candidate.** The nonce
  is a keyed derivation over all authenticated metadata and plaintext. This
  preserves byte-identical retry while preventing nonce reuse when a crash or
  competing writer prepares a different predecessor, result, or payload at
  the same sequence. Ed25519 signing is also deterministic. The "412 plus
  identical readback" rule in `write_once` is therefore sound idempotency;
  any different candidate at the same sequence becomes a conflict.
- **Records are small.** journal.rs:442 asserts a minimal record is under 16 KiB. A single `PutObject` is enough, and multipart (`write_once_large`, 2169) is never used for records.
- **The parent has plaintext metadata only.** `writer_epoch`, `sequence`, `previous_record_hash`, `previous_transition_root`, `transition_root`, and `request_hash` are plaintext, so the parent can pre-check them. The receipt is inside the ciphertext, which v70's plaintext `DirectStateArtifact.receipt` (lib.rs:1135) was not.

---

## 2. Design decision: v71 records use a format-specific immutable namespace

**Record key: `{prefix}/journal-v71/records/{sequence:020}.cbor`, body = `serde_cbor(DirectJournalRecord)`, for every sequence above the v70→v71 bridge sequence `B`.**

Reasons:

1. **One create-only PUT per commit.** The v70 artifact-then-head window (2313-2320) and its orphan artifacts disappear. The PUT's success is the commit point.
2. **Shadow construction can coexist with authoritative v70 heads.** The same committed sequence exists in both formats while v70 serves traffic. Reusing `{prefix}/heads/{sequence}` would conflict immediately with the already-durable v70 full-state head and make live shadow staging impossible.
3. **Cross-format exclusion moves to the cutover protocol.** The parent financial gate prevents another local v70 commit while the immutable cutover marker is written and the enclave is promoted. Any ambiguous marker write or promotion retains that gate and fails health. Startup accepts the marker only when the highest true v70 head equals the marker sequence; the writer grant and ASG handoff prevent a second parent writer.

Consequence: a retained raw v70 parent must never be pointed back at the mixed source prefix after cutover because it cannot interpret the v71 marker. Rollback first materializes an exact-head v70 package under a fresh archive prefix and then starts the retained v70 runtime against that prefix.

Other keys (all written only by `write_once`, never overwritten or deleted):

| Object | Key | Body |
|---|---|---|
| v71 record | `{prefix}/journal-v71/records/{seq:020}.cbor` | `serde_cbor(DirectJournalRecord)` |
| v71 checkpoint | `{prefix}/journal-v71/checkpoints/{seq:020}-{sha256(bytes)}.cbor` | Codex-owned `DirectJournalCheckpoint`. Content-addressed like `checkpoint_key` (1994-1997). |
| Writer fence | `{prefix}/journal-v71/fences/{sha256(fenced_writer_epoch)}/{head_seq:020}.cbor` | CBOR `JournalWriterFence` (§3.2) |
| Shadow records | `{prefix}/shadow-v71/{run_id}/heads/{seq:020}.cbor` | same as the record |
| Shadow checkpoints | `{prefix}/shadow-v71/{run_id}/journal-v71/checkpoints/...` | same as the checkpoint |

`writer_epoch` is hashed in fence keys because it is an arbitrary string of up to 128 bytes (journal.rs:90-91). The head sequence is part of the fence key so an *aborted* handoff fence (§5, W13) never blocks a later correct fence.

Only create-only PUT is used. The plan does **not** use `If-Match`/ETag overwrite, mutable pointers, `DeleteObject`, `CopyObject`, or multipart for records or fences.

---

## 3. Exact types and functions

### 3.1 `lib.rs`: transport additions only

These are shared wire types, so Codex must sign off. They are additive: serde-tagged variants (lib.rs:3657-3658, 3733-3734) leave every existing variant's bytes unchanged.

```rust
// Next to DurabilityAck (lib.rs:1220-1267), mirroring issue/verify_for/unsigned.
pub struct JournalDurabilityAck {
    pub epoch_id: String, pub writer_epoch: String, pub sequence: u64,
    pub previous_record_hash: String, pub record_hash: String,
    pub transition_root: String, pub request_hash: String, pub result_hash: String,
    pub signature: String, // sign(commit_ack_key, cbor(unsigned)), same as lib.rs:1240-1243
}
impl JournalDurabilityAck {
    pub fn issue(record: &journal::DirectJournalRecord, key: &[u8]) -> Result<Self, journal::JournalError>;
    pub fn verify_for(&self, record: &journal::DirectJournalRecord, key: &[u8]) -> bool;
}

// RuntimeResponse (lib.rs:3735)
JournalCandidate { record: journal::DirectJournalRecord },
JournalRestoreProgress { sequence: u64, record_hash: String, transition_root: String, receipt: DirectReceipt },
JournalRestoreComplete { tip_writer_epoch: String, sequence: u64, record_hash: String,
                         transition_root: String, state_hash: String,
                         current_writer_epoch: Option<String> }, // None when not a writer (shadow/dormant)
JournalCheckpointSealed { checkpoint_bytes: Vec<u8>, sequence: u64 },

// RuntimeRequest (lib.rs:3659)
JournalDurabilityAck { ack: JournalDurabilityAck },
BeginJournalRestore { checkpoint_bytes: Vec<u8> },
AppendJournalRestore { record: journal::DirectJournalRecord },
FinishJournalRestore { expected_sequence: u64, expected_record_hash: String, expected_transition_root: String },
SealJournalCheckpoint,
```

`JournalRestoreProgress.receipt` is required because the parent can no longer read receipts from storage. Startup projection reconciliation (5537-5582) and `receipt_sequence` (1673-1682) need them. v70 already stores receipts in plaintext (lib.rs:1135), so returning them adds no new exposure. The checkpoint's receipt lineage is Codex's compaction scope (§11).

### 3.2 `parent.rs`: new types

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistenceFormat { V70, V71, V71Shadow }   // LAYRS_DIRECT_PERSISTENCE_FORMAT: unset|"v70" → V70; "v71"; "v71-shadow"; anything else → startup error

#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalHead { writer_epoch: String, sequence: u64, record_hash: String, transition_root: String }

#[derive(Clone, Debug, PartialEq, Eq)]
enum JournalWriterState { Unrestored, Eligible(JournalHead), Latched(&'static str) }

#[derive(Clone, Debug, PartialEq, Eq)]
enum JournalRole { Writer, Shadow }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalWriterFence {
    protocol: String,               // "layrs.direct-execution.journal-fence.v71"
    epoch_id: String,
    fenced_writer_epoch: String,
    successor_writer_epoch: String,
    head_sequence: u64,
    head_record_hash: String,
    head_transition_root: String,
}
```

Field additions:

- `AppState` (142-162): `persistence_format: PersistenceFormat`. Set in `main` (2905-2946). The test literals at 6213-6231 and the one containing 7281 must add it.
- `S3ImmutableArtifactStore` (230-242): `journal: Arc<Mutex<JournalWriterState>>` and `journal_role: JournalRole`. Set in `from_environment` (2064-2074). The test literals at 6212, 6790, 6803, and 6821 must add both fields.

Startup validation in `main`:

- `V71` or `V71Shadow` requires `ArchiveStore::S3` (backend selection 1618-1646). Otherwise startup fails. Filesystem v71 is not implemented.
- `V71Shadow` requires an execution mode other than `admission-enabled`/`production-enabled`, so there is no grant and no custody (2848, 2925-2940).

`V70` is the default. With it, every existing path is byte-for-byte unchanged.

### 3.3 `parent.rs`: new pure helpers (unit-testable, no I/O)

| Function | Contract |
|---|---|
| `fn journal_record_key(prefix: &str, sequence: u64) -> String` | Canonical `{prefix}/journal-v71/records/{sequence:020}.cbor`. |
| `fn journal_record_key_sequence(key: &str, prefix: &str) -> Result<u64, String>` | Strict inverse of `journal_record_key`; rejects suffixes, unpadded, zero, foreign and overflowing keys. |
| `fn journal_fence_prefix(prefix: &str, writer_epoch: &str) -> String` / `fn journal_fence_key(prefix, writer_epoch, head_sequence) -> String` | §2 layout. `sha256` hex of the epoch. |
| `fn journal_checkpoint_key(prefix: &str, sequence: u64, bytes: &[u8]) -> String` | §2 layout. |
| `fn precheck_journal_candidate(head: &JournalHead, record: &DirectJournalRecord) -> Result<Vec<u8>, &'static str>` | §4 step 2. Returns the CBOR bytes to PUT. |
| `fn validate_journal_tail_keys(keys: &[String], prefix: &str, after: u64, max: usize) -> Result<Vec<(u64, String)>, String>` | Every key canonical. Sequences exactly `after+1..=after+n`. `n <= max`. |
| `fn validate_writer_epoch_transitions(checkpoint_epoch: &str, tail: &[(u64, String /*writer_epoch*/)], fences: &BTreeMap<String /*epoch sha*/, BTreeSet<u64>>) -> Result<(), String>` | §7 step 6. |
| `fn verify_terminal_matches_record(result: &DirectResult, record: &DirectJournalRecord) -> bool` | `sha256(serde_cbor(result)) == record.result_hash`, `sha256(serde_cbor(result.receipt)) == record.receipt_hash`, and `result.receipt.request_hash == record.request_hash`. This is the same canonical hash as journal.rs:325-329. |

### 3.4 `parent.rs`: new `S3ImmutableArtifactStore` methods

| Method | Behavior |
|---|---|
| `async fn append_journal_record(&self, record: &DirectJournalRecord) -> Result<JournalHead, String>` | §4 steps 1-6. Holds `self.journal` for the whole call. |
| `async fn writer_fenced(&self, writer_epoch: &str) -> Result<bool, String>` | `list_objects_v2().prefix(journal_fence_prefix(..)).max_keys(1)`. Returns `true` if any key is present. A missing or ambiguous response is `Err`, and the caller treats `Err` as fenced. |
| `async fn latch_journal(&self, code: &'static str)` | Sets `Latched(code)` and logs `JOURNAL_LATCHED reason=<code>`. Never cleared in-process. |
| `async fn list_journal_tail(&self, after: u64, max: usize) -> Result<Vec<String>, String>` | Copy of `list_restore_keys` (2337-2380) with `.start_after(journal_record_key(prefix, after))`. Same pagination, repeat-token, and duplicate checks. Rejects when `len > max`. |
| `async fn list_journal_fences(&self) -> Result<BTreeMap<String, BTreeSet<u64>>, String>` | Lists `journal-v71/fences/` with the same pagination guards. Every key must match §2 exactly. |
| `async fn persist_journal_checkpoint(&self, bytes: Vec<u8>, sequence: u64) -> Result<String, String>` | `write_once(journal_checkpoint_key(..), bytes)`. Returns the key. |
| `async fn establish_writer_fence(&self, tip: &JournalHead, successor: &str) -> Result<(), String>` | §5. |
| `async fn restore_journal_v71(&self, state: &AppState) -> Result<(), String>` | §7. |

### 3.5 `parent.rs`: changed functions

| Function | Change |
|---|---|
| `exchange_direct` 5972-6064 | Gate the existing `CommitCandidate` arm (6005) on `persistence_format == V70`. Otherwise latch and return `JOURNAL_FORMAT_MISMATCH` without writing. Add a `JournalCandidate { record }` arm, accepted only for `V71` + `ArchiveStore::S3` + `JournalRole::Writer`, which calls `complete_journal_candidate`. In any other mode, reject it without writing. In the post-`Execute` block (6048-6062), select the v71 seal closure (`SealJournalCheckpoint` → `persist_journal_checkpoint`) when the format is `V71`. The gate and coalescing (`refresh_checkpoints` 314) stay unchanged. |
| new `async fn complete_journal_candidate<S: AsyncRead + AsyncWrite + Unpin>(state, store, stream: &mut S, record) -> io::Result<RuntimeResponse>` | Generic over the stream, so tests can use `tokio::io::duplex` instead of vsock. It runs §4 steps 1-9. `exchange_direct` passes its `VsockStream`. |
| `recover_enclave` 4934-4941 | S3 branch: `V70` → `restore_streamed` (unchanged). `V71` / `V71Shadow` → `restore_journal_v71`. |
| `commit_error_response` 4335-4361 | Add `JOURNAL_WRITER_FENCED` → 409, `JOURNAL_LATCHED` → 503, and `JOURNAL_CANDIDATE_REJECTED` / `JOURNAL_FORMAT_MISMATCH` → 502. Existing mappings are unchanged, and `ARCHIVE_SEQUENCE_CONFLICT` still maps to 409. |

Unchanged: `write_once` (reused verbatim), `read`, `write_once_large`, `persist_readback`, `prepare_restore`, `restore_streamed`, the v70 `DurabilityAck`, and every v70 key.

---

## 4. Append protocol (writer, per commit, under `financial_gate`)

`exchange_direct` already holds the process-wide financial guard (5975, 4228-4240), so there is at most one append per process. Cross-process exclusion comes only from the slot key and the fence (§5).

```
1. state := store.journal.lock()            // held through step 6
   require state == Eligible(head)          // else: JOURNAL_LATCHED / not restored → no PUT
2. precheck_journal_candidate(head, record):
     record.protocol == DIRECT_JOURNAL_PROTOCOL (journal.rs:18)
     record.epoch_id == EPOCH_ID
     record.writer_epoch == head.writer_epoch       // expected writer epoch
     record.sequence == head.sequence.checked_add(1) // expected sequence
     record.previous_record_hash == head.record_hash // expected head
     record.previous_transition_root == head.transition_root
     bytes := serde_cbor(record); bytes.len() <= MAX_JOURNAL_RECORD_BYTES (Codex constant, must be < 16 MiB)
   failure → latch(JOURNAL_CANDIDATE_OUT_OF_ORDER); NO PUT (never burn a slot)
3. write_once(journal_record_key(prefix, record.sequence), bytes)      // parent.rs:2123 unchanged
     200                     → readback == bytes required (2157-2159)
     412 + identical bytes   → idempotent success (2149)
     412 + different bytes   → ARCHIVE_SEQUENCE_CONFLICT → latch
     ARCHIVE_TIMEOUT / read exhaustion → latch (ambiguous; no ack)
4. fenced := writer_fenced(head.writer_epoch)   // strictly AFTER the PUT returned
     Ok(false) → continue; Ok(true) → latch(JOURNAL_WRITER_FENCED); Err → latch(JOURNAL_FENCE_UNAVAILABLE)
5. new_head := { writer_epoch, record.sequence, record.record_hash()?, record.transition_root }
6. state := Eligible(new_head)   // record is durable regardless of what the enclave does next
7. ack := JournalDurabilityAck::issue(record, commit_ack_key); send; read terminal
     (bounded_enclave_stage, same as 6030-6038)
8. terminal must be Execute{result} with verify_terminal_matches_record(result, record)
     anything else (Error, timeout, transport failure, hash mismatch) → latch(JOURNAL_ENCLAVE_ADOPTION_UNKNOWN);
     do not return the result
9. return Execute{result}; last_commit_at updated as at 6042
```

Invariant: the parent PUTs a record only when its head equals the enclave head proven by the immediately preceding successful `Execute` terminal or by the restore finish. Any break in that chain latches the writer until process restart and full restore. Restart already forces an enclave reset (2957-2964).

---

## 5. Writer-epoch head fence (handoff `H` → `H+1`)

Contract lines 139-143: the old writer is fenced at `H`, the new writer begins at `H+1`, and two writers are never eligible for the same writer epoch and sequence.

- **Per-sequence exclusion** is storage-enforced by the create-only slot (§2). It covers writers in any epoch and in either format.
- **Epoch exclusion** needs two keys (the fence and the next slot). S3 has no multi-key conditional write, so it uses a write-then-read protocol on both sides (Dekker style):

```
New writer W2 (after restore_journal_v71 proves tip H of epoch W1, before eligibility):
  a. write_once(journal_fence_key(prefix, W1, H), cbor(JournalWriterFence{W1, W2, H, hash_H, root_H}))
       identical existing bytes → OK (idempotent re-run); different bytes → fail closed
  b. list_journal_tail(after = H, max = 1)   // strictly AFTER (a) returned
       empty → W2 Eligible at H; non-empty → abort handoff, stay Unrestored (JOURNAL_HANDOFF_RACE)
  c. writer_fenced(W2) must be false (a fenced epoch never resumes)

Old writer W1 (every commit, §4 steps 3-4): PUT slot N, then list fences(W1); ack only if none.
```

**Soundness.** This relies on S3's documented strong read-after-write consistency for `PutObject`, `GetObject`, and `ListObjectsV2`. Suppose W2's listing in (b) misses W1's slot `H+1`. Then W1's PUT took effect after (b), and therefore after (a). W1's post-PUT fence listing (§4 step 4) then sees the fence and does not acknowledge. So at least one side always observes the other. Both sides may abort, which is safe. If this consistency guarantee is not accepted as a safety assumption, the per-commit check is best-effort only. The remaining guarantees are then the slot uniqueness plus the operational dispatch pause.

**Same-epoch restart.** If `tip_writer_epoch == current_writer_epoch`, the only check is (c).

**Scope limit.** The v70 writer cannot perform the fence check, because its code is frozen. Against v70, only slot exclusion applies (§9, N6).

---

## 6. Crash and failure windows

| # | Point | Durable result | Parent action | Restart/restore outcome |
|---|---|---|---|---|
| W0 | `Execute` exchange fails, or enclave returns `Error`, before a candidate | nothing | return error, no latch (4241-4245) | n/a |
| W1 | Candidate fails precheck (§4.2) | nothing | latch, no PUT | restore from storage |
| W2 | PUT in flight: timeout (2146), connection drop, or process crash | **unknown** | latch `ARCHIVE_TIMEOUT`, no ack, 503 | slot present → committed but never reported; an exact retry after restore returns the original receipt (contract lines 29-33). Slot absent → never committed. |
| W3 | PUT 412, readback identical | durable (ours) | continue | — |
| W4 | PUT 412, readback different | slot held by another writer | latch `ARCHIVE_SEQUENCE_CONFLICT`, 409 | restore adopts the other record. This command was never committed. |
| W5 | PUT 200, readback fails or mismatches | durable, unverified | latch, no ack | enclave verifies bytes on restore. Corrupt → fail closed. |
| W6 | Durable, then fence listing shows a fence or errors | durable | latch `JOURNAL_WRITER_FENCED` / `..._FENCE_UNAVAILABLE`, no ack | record is lineage. Handoff must re-fence at the real tip (W13). |
| W7 | Durable, process crash before ack | durable | — | same as W2 when present |
| W8 | Ack sent, terminal is `Error`, timeout, or transport failure | durable | latch, 503 | same as W2 when present |
| W9 | `Execute` result does not match `record.result_hash`/`receipt_hash` | durable | latch, result withheld | restore re-derives the committed result. The mismatch is investigated. |
| W10 | `Execute` returned, crash before projection | durable | existing behavior | startup reconcile (5537-5582) using restore-returned receipts (§3.1) |
| W11 | During checkpoint seal or persist | complete checkpoint object or none (single create-only PUT) | non-fatal, same as v70 (304-360, 2019-2034) | older checkpoint plus a longer tail. Tail over the policy bound → restore fails closed. |
| W12 | Handoff: fence written, crash before re-list | fence durable | W2 not eligible | re-run is idempotent (identical fence bytes). A live W1 latches at its next commit. |
| W13 | Handoff: re-list shows `H+1` | fence at `H` durable (aborted) | W2 stays ineligible | W1 is fenced from then on. The operator re-runs the handoff. The new fence at the actual tip `H'` is a new key. §7 step 6 accepts the aborted lower fence. |

A latch is never cleared in-process and never triggers a self-exit. Recovery is a process restart followed by the full §7 restore. Auto-exit could loop on W4/W6.

---

## 7. Startup restore listing (`restore_journal_v71`)

It runs in place of `restore_streamed` at 4941, before any route is served (2981). Writer eligibility stays off throughout.

1. **Bridge `B`.** The governed mode uses `grant.committed_restore_frontier.sequence` (lib.rs:418, 508-524), which is already validated in `prepare_restore` 2447-2467. `B = 0` is allowed only if `state.isolated_test`. A missing `B` in v71 mode fails closed.
2. **Checkpoint.** `list_restore_keys("journal-v71/checkpoints")` (2337). Select the last key, the same rule as 2503. Its sequence must satisfy `C >= B`, and `journal_checkpoint_key(C, bytes) == key` (content address, same as 2507-2509). A corrupt newest checkpoint fails closed with no fallback to an older one (the same principle as 2614-2616).
   - **No v71 checkpoint.** Allowed only when `list_journal_tail(after = B, max = 1)` is empty, meaning this is the first v71 boot. Run the existing `prepare_restore` + `restore_streamed` for `1..=B` and require the restored sequence `== B`. Then `SealJournalCheckpoint` → `persist_journal_checkpoint` → `read` must match, all **before** eligibility. No v71 append is allowed until a v71 checkpoint at `>= B` is durable. This keeps later restores on this path only.
   - **No checkpoint but tail above `B` exists** → fail closed (genesis/v70 fallback forbidden, contract lines 121-123).
3. **Checkpoint anchor.** If `C == B`, the migration bundle and authenticated v70 frontier anchor the checkpoint. If `C > B`, `read(journal-v71/records/{C})` must decode to a record whose `record_hash()` equals the checkpoint's bound record hash. The enclave re-verifies this.
4. **Tail listing.** `list_journal_tail(after = C, max = MAX_V71_TAIL_RECORDS)` (Codex policy constant), then `validate_journal_tail_keys`. Fail closed on:
   - a gap, duplicate, or non-canonical key;
   - a legacy `{seq}-{hash}` name. Such names sort after `start_after` once `seq > C`, so they are always seen.
   - a count over the bound.
5. **Stream in key order** (download prefetch like 2536-2562 is allowed). For each key:
   - `read`, decode `DirectJournalRecord`, require `record.sequence == key sequence`;
   - parent precheck: `previous_record_hash == prev.record_hash()`;
   - `AppendJournalRestore`, then require `JournalRestoreProgress{sequence, record_hash, transition_root}` to match, and cache the returned receipt.

   A v70 64-hex body above `B` fails decode, meaning a v70 writer ran after cutover, and restore fails closed.
6. **Fences.** `list_journal_fences()` then `validate_writer_epoch_transitions`. For every epoch `Wa` that is not the tip epoch, and appears in the checkpoint-bound epoch or the tail, `max(fences[Wa]) == last sequence written by Wa`. Every change of epoch at sequence `s` has a `Wa` fence at `s-1`. Lower fences for `Wa` are aborted handoffs (W13) and are accepted. Any record of `Wa` above `max(fences[Wa])` when a later epoch exists fails closed.
7. **Finish.** `FinishJournalRestore{H, hash_H, root_H}` must return `JournalRestoreComplete` with the same `(sequence, record_hash, transition_root)`.
8. **Eligibility (`V71` + `Writer` only).** `current_writer_epoch` must be `Some`.
   - If it differs from `tip_writer_epoch`, run `establish_writer_fence` (§5).
   - Otherwise require `writer_fenced(current) == Ok(false)`.

   Then set `Eligible(JournalHead{current, H, hash_H, root_H})`. `V71Shadow` stays `Unrestored` for authoritative purposes (§8).
9. **Delete-marker guard (R1, required before production eligibility, §9 N5).** `list_object_versions` over `journal-v71/records/` with `key_marker = journal-v71/records/{C:020}.cbor`, and over `journal-v71/fences/`. Fail closed on any `DeleteMarker` entry or on any key with more than one version. A permission error fails closed and is never skipped.

---

## 8. Shadow mode (`PersistenceFormat::V71Shadow`)

This is only the non-authoritative mirror running beside live production that
the rollout requires. There is no separate time-based shadow-soak gate: once
the defined replay-match, restore, rollback, and abort checks pass, elapsed
soak time is not a cutover prerequisite.

- **Store prefix.** Built once as `{LAYRS_DIRECT_ARCHIVE_PREFIX}/shadow-v71/{LAYRS_DIRECT_SHADOW_RUN_ID}`. The run id must match `[a-z0-9-]{1,64}` and is rejected otherwise. `journal_role = Shadow`.
- **Write guard.** `append_journal_record` and `persist_journal_checkpoint` assert, in `Shadow` role, that every key starts with `{prefix}/shadow-v71/{run_id}/`. Violation → latch and no PUT.
- **Written during shadow staging:** immutable `journal-v71/records/` and the base `journal-v71/checkpoints/`; these are not authoritative until the cutover marker is durable.
- **Never written by shadow:** v70 `heads/`, `artifacts/`, `checkpoints/`, or `journal-v71/fences/`. `establish_writer_fence` is never called.
- **Never touched by shadow:** `committed_state_root`, projection, custody, intents, or the v70 `DurabilityAck`.
- **No HTTP commands.** The command routes stay disabled because `direct_writer_route_enabled` (3058-3060) is unchanged, and the non-writer execution mode is enforced in §3.2.
- **Same code path.** The shadow uses the §4 append and §7 restore code against its own prefix. That same code provides the "successful checkpoint-plus-tail restore" evidence the cutover gate needs (contract lines 131-137).
- **Failure isolation.** A shadow conflict, latch, or restore failure logs `SHADOW_JOURNAL_LATCHED reason=<code>`. It only invalidates the shadow match window and never affects the authoritative v70 writer.
- **Out of scope here:** how the shadow receives the authoritative command order, and how results are compared. Those belong to the verification worker and Codex.

---

## 9. What current S3 APIs cannot make atomic, and the fail-closed rule for each

| # | Non-atomic pair | Why | Fail-closed protocol |
|---|---|---|---|
| N1 | Record PUT vs. writer-fence check | Different keys, and there is no multi-key conditional write or transaction | §5 write-then-read on both sides. The ack only follows a post-PUT fence listing that is empty and error-free. On any doubt, latch without ack. |
| N2 | Durable append vs. enclave adoption | Storage and enclave memory are separate systems | Head advances on durability (§4.6). Any non-`Execute` or mismatched terminal latches. Restart plus enclave reset (2957-2964) plus restore. Exact-retry dedup returns the original result. |
| N3 | PUT outcome under timeout or connection loss | A dropped future does not tell you whether S3 committed the object (2146 skips readback) | Latch, 503, no ack. Only a later listing decides. No in-process retry after `ARCHIVE_TIMEOUT`. |
| N4 | Append vs. projection write | Separate stores | Existing startup reconcile (5537-5582), fed by restore-returned receipts. Extra or conflicting projection rows still fail closed (5566-5568). |
| N5 | Create-only vs. delete markers | In a versioned Object Lock bucket, a DELETE without a version id adds a delete marker even for locked versions. `ListObjectsV2`/`GetObject` then hide the object. The plan must not assume `If-None-Match: *` rejects a PUT over a delete marker. A hidden record or fence enables rollback or a stale writer. | The parent cannot prevent this. It requires IAM denying `s3:DeleteObject` on the prefix for every runtime principal (infrastructure; not changed here). Detection is R1 (§7.9). This residual already exists for v70 `heads/` and is **not** retrofitted by this plan. |
| N6 | v70 writer vs. v71 fence | Frozen v70 code never reads fences | Only slot exclusion applies (§2). A live v70 writer can win `B+1..`, and v71 then latches (W4) or aborts the handoff (§5b). Pre-emptive v70 stopping remains the governed writer fence (4730) plus the operational pause. |
| N7 | Tail truncation | A listing cannot prove nothing exists beyond the last visible key | R1 (delete markers), the governed frontier (§7.1), and the projection-ahead check (5566-5568). The residual is documented. It is never silently accepted when any detector fires. |
| N8 | Listing vs. concurrent writers | A listing is not a snapshot | Restore runs with eligibility off. The only listing used for exclusion is the post-fence re-list (§5b), which is ordered after the fence PUT. |

---

## 10. Focused local tests (loopback mock S3 only; no AWS, no credentials, no network)

All tests are in the `parent.rs` `#[cfg(test)]` module. They use the existing local `TcpListener` HTTP mock pattern (6778-6823) and `tokio::io::duplex` for the enclave side of `complete_journal_candidate`. Names are prefixed `v71_`, so they run with `cargo test --bin parent v71_`.

1. `v71_record_key_shares_v70_head_slot_and_parser_rejects_legacy_and_foreign_keys`: key equality with `archive_head_key`. Hash suffix, wrong namespace, unpadded, and overflow are all rejected.
2. `v71_precheck_rejects_wrong_epoch_sequence_predecessor_root_protocol_and_size_without_put`: the mock asserts zero connections, and the state becomes `Latched`.
3. `v71_append_puts_once_with_create_only_kms_compliance_headers_then_reads_back_then_checks_fence`: the mock asserts request order PUT → GET → LIST. It also asserts headers `If-None-Match: *`, `x-amz-server-side-encryption: aws:kms`, `x-amz-object-lock-mode: COMPLIANCE`, and the key `journal-v71/records/{seq:020}.cbor`. The head advances.
4. `v71_append_412_with_identical_readback_is_idempotent_success`.
5. `v71_append_412_with_different_readback_latches_sequence_conflict_and_maps_409`.
6. `v71_durable_append_with_existing_fence_latches_without_ack`: the duplex side asserts no ack frame is received.
7. `v71_fence_listing_error_is_treated_as_fenced`.
8. `v71_ambiguous_put_timeout_latches_and_later_candidates_do_not_touch_storage`: uses a short `bounded_archive_operation` duration, like 6640-6663.
9. `v71_enclave_error_or_mismatched_result_hash_after_durable_append_latches_and_withholds_result`.
10. `v71_format_gate_rejects_commit_candidate_in_v71_and_journal_candidate_in_v70`.
11. `v71_tail_listing_uses_start_after_and_rejects_gap_duplicate_legacy_overflow_and_repeated_token`: the mock asserts the `start-after=` query parameter and paginates across more than 1000 keys.
12. `v71_restore_rejects_v70_head_body_above_bridge_and_record_sequence_key_mismatch`.
13. `v71_writer_epoch_transitions_require_matching_fence_and_accept_aborted_lower_fence`: pure-function table test.
14. `v71_handoff_aborts_when_post_fence_relist_sees_next_slot_and_rerun_is_idempotent`.
15. `v71_hot_restore_requires_the_legacy_tip_to_equal_the_cutover_marker`: startup lists only true v70 heads and fails closed if their maximum sequence differs from the immutable cutover marker.
16. `v71_shadow_prefix_confines_all_writes_and_never_calls_fence_or_updates_state_root`.
17. `v71_first_boot_requires_durable_bridge_checkpoint_before_eligibility`.
18. `v71_delete_marker_or_multiple_versions_in_journal_namespace_fail_restore` (R1).

Run `cargo fmt --check` and the existing parent test suite unchanged. The existing tests must pass with only the struct-literal field additions noted in §3.2.

---

## 11. Dependencies outside Worker B scope (blocking v71 writer eligibility, not this plan)

1. **Codex:** enclave handling of the §3.1 variants, `MAX_JOURNAL_RECORD_BYTES`, `MAX_V71_TAIL_RECORDS`, the `DirectJournalCheckpoint` format, the predecessor values for the first record at `B+1`, and writer-epoch derivation and authorization.
2. **Codex:** `committed_state_root` semantics under v71. External-effect intents bind a v70 full-state root (3706, 3754, 3836, 5061). v71 records carry only `transition_root` by design (contract lines 94-97). The parent must not substitute one for the other silently, so v71 writer mode stays blocked until this is decided.
3. **Codex:** receipt lineage for `load_committed` consumers (1659-1664, 3736, 3816, 5418, 5545, 5631) and `receipt_sequence` (1673-1682) after compaction.
4. **Codex / verification:** the v70 rollback export must target a fresh prefix (consequence of §2).
5. **Infrastructure (not changed here):**
   - IAM deny on `s3:DeleteObject` for runtime principals on the archive prefix (N5).
   - `s3:ListBucketVersions` for R1. Without it, v71 restore fails closed by design.
6. **Verification worker:** shadow command feed and comparison, and handoff and crash-injection harnesses above the parent unit level.

Non-goals: any change to v70 keys, artifacts, checkpoints, `write_once`, matching, custody, receipts, projection schema, or deployment configuration.
