# v71 Request-History Compaction Invariants (Worker A audit)

Status: audit only. No Rust, Cargo, parent, enclave-binary, AWS, or deployment
file was changed. This document does not authorize any rollout.

Codex integration decision after this audit: the never-pruned logical key set
is represented inside the enclave by the authenticated sparse root implemented
in `src/request_index.rs`, not by the in-enclave `BTreeMap` sketched in Section
5. The field and replay requirements below apply to authenticated leaves and
archive records. This keeps enclave bytes bounded while preserving every
load-bearing request identity identified by the audit.

- Contract: `FULL_STATE_JOURNAL_V71_CONTRACT.md` ("Compact request history",
  "Existing v70 invariants", "Rollback").
- Code audited: branch `claude/layrs-v71-compaction-audit-20260928`, HEAD
  `200d90e`, clean tree.
- All references are `enclave/direct-execution-v1/src/lib.rs:LINE` (written
  `lib.rs:LINE`) unless stated otherwise. One production read is in the child
  module `src/quest_receipts.rs`. That module can read the private field, so it
  is in scope for the enumeration. No other file in `src/` references
  `.requests` (grep).
- Scope: only request-history compaction. Matching, custody design, UI,
  publisher, and parent transport are out of scope.

## 1. Data shapes involved

| Item | Location | Note |
|---|---|---|
| `DirectRuntime.requests: BTreeMap<(account_id, request_id), (request_hash, DirectResult)>` | `lib.rs:1117` | Live dedup, replay, and sequence source. |
| `DirectState.requests` (same type) | `lib.rs:1327` | Serialized as the last field. It has **no** `#[serde(default)]`, so every v70 state CBOR must contain it. |
| `DirectResult {status, effect, genesis_ordinal, receipt}` | `lib.rs:964-969` | `status`/`effect`/`genesis_ordinal` duplicate receipt fields. Current code sets both ordinals to `0` (`lib.rs:2282`, `lib.rs:2289`). |
| `DirectReceipt` | `lib.rs:932-951` | Unbounded parts: `execution.trades` (`lib.rs:1000`), `projection_balance_updates` (`lib.rs:948`, one row per touched identity × bucket; a resolution touches every holder, `lib.rs:2669-2688`), `resolution` (`lib.rs:944`). |
| `receipt_id` | `lib.rs:2268-2270` | Derivable: `sha256("{EPOCH_ID}:{account}:{request_id}")`. |
| Terminal status mapping | `lib.rs:2240-2244` | `WITHDRAWAL_REVERTED` becomes `RejectedEffectNone`; every other committed effect becomes `Applied`. |
| v70 per-request archive object | `lib.rs:1126-1136`, `lib.rs:1493-1496` | `DirectStateArtifact.receipt` holds the signed receipt. The filesystem store keys objects by `request_hash`. The in-memory store does too (`lib.rs:1458-1463`). |
| v70 checkpoint receipt lineage | `lib.rs:1144-1153` | `receipt_records` holds every signed receipt with its sequence and is MAC-bound (`lib.rs:2449`). |

## 2. Every production read/write of `requests`

Classes: **ER** = exact replay; **PD** = permanent financial dedup / conflicting-id
fail-closed; **AR** = active-state reconstruction or validation; **CV** =
checkpoint/artifact validation or hashing; **SQ** = sequence coupling;
**RC** = receipt-content read (needs full receipt body).

### 2a. `DirectRuntime.requests`

| # | Ref | Op | Function | Class | What depends on it |
|---|---|---|---|---|---|
| 1 | `lib.rs:1117` | decl | struct | – | – |
| 2 | `lib.rs:1664` | write (init empty) | `new` | SQ | `committed_sequence()==0` is what `restore_checkpoint` treats as "fresh runtime" (`lib.rs:2456`). |
| 3 | `lib.rs:1679-1686` | read | `execute` | ER, PD | Same hash returns the stored `DirectResult`; a different hash returns `RequestReuse`. This runs **before** the mode, identity, and action checks (`lib.rs:1687-1708`), so replay works in `Dormant`, as shown by the test at `lib.rs:6763-6781`. |
| 4 | `lib.rs:2292-2293` | write (insert) | `execute` | ER, PD, SQ | This is the **only** production insertion. It happens after all validation, so an erroring command inserts nothing (`lib.rs:6844-6853`). No production code removes entries. |
| 5 | `lib.rs:2303-2310` | read | `existing_result` | ER, PD | Pre-candidate replay used by the VSOCK handler (doc comment `lib.rs:2296-2298`). |
| 6 | `lib.rs:2320-2327` | read | `execute_committed` | ER, PD | Replay returns before `prepare_candidate` or any store write. |
| 7 | `lib.rs:2345-2360` | read | `prepare_candidate` | ER, PD, RC, SQ | Replay path: it re-seals the **current** head with the *old* receipt (`lib.rs:2350-2355`). The test at `lib.rs:6751-6757` characterizes this. Needs the full receipt. |
| 8 | `lib.rs:2484-2490` | read | `validate_checkpoint_records` | CV | Every checkpoint receipt must be in the map with an equal `request_hash` and **full receipt equality** `result.receipt == *receipt` (`lib.rs:2489`). Record count must equal sequence (`lib.rs:2474`). |
| 9 | `lib.rs:2527` | read (clone) | `snapshot` | CV | Full map goes into `DirectState`. This feeds `state_hash` (`lib.rs:2530-2532`) and the artifact plaintext (`lib.rs:2550`). |
| 10 | `lib.rs:2543` | read (`len`) | `seal_artifact` | SQ | `sequence = requests.len()`. Sequence also seeds the nonce (`lib.rs:2545-2546`). |
| 11 | `lib.rs:2609` | write (replace) | `apply_artifact` | AR, CV | Replaced wholesale from decrypted state after the two validators run (`lib.rs:2589-2590`). |
| 12 | `lib.rs:3481-3483` | read (`len`) | `committed_sequence` | SQ | Callers: `restore_next_committed` (`lib.rs:2425`, `lib.rs:2431`), `seal_checkpoint` (`lib.rs:2438`), `restore_checkpoint` (`lib.rs:2456`, `lib.rs:2465`), `portfolio().genesis_ordinal` (`lib.rs:3448`), `quest_receipts.rs:291`. |
| 13 | `quest_receipts.rs:212-226` | read | `public_quest_receipt` | RC | Re-verifies HMAC and status/effect/account/request/hash consistency. Reads `identity_commitment`, `execution.trades` (`quest_receipts.rs:229-241`) and `projection_balance_updates` (`quest_receipts.rs:250-253`). |

`lib.rs:3190` contains the word "requests" in a comment only, so it is not an access.

### 2b. `DirectState.requests`

| # | Ref | Op | Function | Class | What depends on it |
|---|---|---|---|---|---|
| 1 | `lib.rs:1327` | decl | struct | CV | Part of the canonical v70 state CBOR and therefore of every v70 `state_hash`. |
| 2 | `lib.rs:1337-1369` | iterate | `validate_conditional_deposits` | AR, CV | For each `usdc-bus-deposit-credit:{op}` entry it verifies the receipt HMAC, identity, amount ≥ 5 USDC, and both custody references in `credited_custody_references`. |
| 3 | `lib.rs:1351-1361` | lookup | same | AR, CV | A finalize entry, if present, must match the credit on identity and amount and pass HMAC. Its reference must be credited, and the op must no longer be pending. Otherwise the pending map entry must match the credit receipt (`lib.rs:1363-1368`). The pending count must equal the non-finalized credit count (`lib.rs:1371`). |
| 4 | `lib.rs:1379-1423` | iterate | `reconstruct_bus_holds` | AR, CV | **The only source of `usdc_bus_withdrawals`**, which is never serialized (`lib.rs:1115` vs `DirectState`; the test at `lib.rs:5321-5337` asserts this). Destination, chain, and asset come from the signed reservation `custody_reference` (`lib.rs:1402-1409`). Amount comes from the receipt (`lib.rs:1410-1413`). |
| 5 | `lib.rs:1389-1400`, `lib.rs:1394` | lookup | same | CV | A settle/revert entry must point to an original `WITHDRAWAL_RESERVED` receipt with the same identity and amount. |
| 6 | `lib.rs:1414-1415` | `contains_key` | same | AR | The existence of `usdc-bus-settle:{id}` or `usdc-bus-revert:{id}` is what marks a reservation inactive. |
| 7 | `lib.rs:1426-1432` | (derived) | same | AR, CV | `USER_WITHDRAWAL_HOLD` per identity and asset must equal the sum of active reservations. |
| 8 | `lib.rs:2527`, `lib.rs:2550`, `lib.rs:2584-2609` | construct / serialize / decode | `snapshot`, `seal_artifact`, `apply_artifact` | CV | The full map is encrypted on **every** commit. This is the O(N) per-commit cost measured by `lib.rs:7069-7082`. |

Test-only mutations (not production): `lib.rs:5088`, `lib.rs:5344`,
`lib.rs:5347-5352`, `lib.rs:6860-6863`. Test-only reads: `lib.rs:6830`,
`lib.rs:6835`, `lib.rs:6839`, `lib.rs:6852`, `lib.rs:7028`, `lib.rs:7034`,
`lib.rs:7077`.

## 3. Coupling findings that constrain compaction

1. **Sequence comes from cardinality.** See 2a#10 and 2a#12. Removing one entry
   rewinds the sealed sequence and forgets the dedup key (`lib.rs:6855-6869`).
   The sequence also feeds nonce derivation (`lib.rs:2545`). In v71 the
   sequence must be an explicit field that drives the artifact/journal sequence
   and the nonce. `request_index.len() == sequence` may remain as a consistency
   *check* only.
2. **Replay precedes authority.** Any compacted-entry hit must also be handled
   before the mode checks (`lib.rs:1687`) and must never fall through to
   execution.
3. **Active bus holds exist only inside the request history** (2b#4–7). If a
   `WITHDRAWAL_RESERVED` receipt is dropped, the hold is not reconstructed, and
   restore fails because the `USER_WITHDRAWAL_HOLD` total no longer matches
   (`lib.rs:1429`). Dropping a settle/revert *key* would silently re-activate a
   completed hold.
4. **Pending conditional deposits are validated against request receipts**
   (2b#2–3). Dropping a non-finalized credit entry fails restore at
   `lib.rs:1371`.
5. **The v70 checkpoint validator needs full receipt equality** (2a#8). It
   cannot run against compact entries.
6. **Request-hash tag sharing is part of exact-replay semantics.** The following
   pairs hash identically for the same request id and fields:
   - `ReserveZenWithdrawal` / `RecordZenWithdrawalReverted` (both
     `"RESERVE_ZEN_WITHDRAWAL"`, `lib.rs:3883-3888`);
   - `ReserveWithdrawal` / `RecordWithdrawalReverted` with a `lei-` reference
     (both `"RESERVE_WITHDRAWAL"`, `lib.rs:3946`, `lib.rs:3968`);
   - `SettleRelayWithdrawal` / `RecordRelayWithdrawalReverted` with a `lei-`
     reference (both `"SETTLE_RELAY_WITHDRAWAL"`, `lib.rs:3995`).

   A revert that arrives under an already-committed id therefore returns the
   original result. The compact entry must keep `request_hash` verbatim. It must
   never be recomputed from a re-derived action.
7. **The v70 state root includes the full request map** (2b#8). A v70 rollback
   export at head `H` must rebuild every `(request_hash, DirectResult)` exactly.
   Rollback therefore requires every archived receipt for 1..H to be present and
   to verify.

## 4. Per-`DirectAction` dedup and compact-field requirements

In the tables below, "Live-state permanent dedup" asks whether a **never-pruned**
structure other than `requests` rejects a second execution of the same
financial effect. No production code removes from `credited_custody_references`,
`orders`, `markets`, `resolved_markets`, `subject_identities`, or
`subject_wallets` (grep for `remove`/`retain` finds only the test at
`lib.rs:4891`).

Every compact entry must keep the base fields `(account_id, request_id)` key,
`request_hash`, `status`, `effect`, `receipt_digest`, and `archive_locator`, as
the contract requires (`FULL_STATE_JOURNAL_V71_CONTRACT.md:59-66`). The
"Extra compact fields" column lists only what goes beyond that base.

### 4a. Identity, market, and governance actions

| Action (dispatch) | request_id constraint | Permanent dedup key(s) | Live-state permanent dedup? | Re-execution if key dropped | Extra compact fields | Active-state dependency |
|---|---|---|---|---|---|---|
| `AdmitIdentity` (`lib.rs:1771-1801`) | none | subject, identity, wallet (`lib.rs:1781-1786`) | **Yes** | Fails with `IdentityAlreadyAdmitted`; loses the original result | none | none |
| `RegisterMarket` (`lib.rs:1802-1829`) | none (`registration_id` not deduped) | `market_id` (`lib.rs:1808`) | **Yes** (per market) | Fails with `InvalidMarket`; loses the result | none | none |
| `ResolveMarket` (`lib.rs:1830-1849`, `lib.rs:2612-2716`) | `== resolution_id` (`lib.rs:1840`) | market once (`lib.rs:2621`); `resolution_id` | **Partial.** Market exactly-once: yes. `resolution_id` is **not** stored in `resolved_markets` (`lib.rs:1067-1071`); only the request key holds it. | Same market fails with `InvalidMarket`. The same id on another market is blocked only by the request key. | none (the key is the resolution id) | none |
| `GovernedBalanceRecovery` (`lib.rs:1850-1878`) | `== recovery_id`, account bound (`lib.rs:1860-1862`) | `(account, recovery_id)` | **No.** Only the expected-balance precondition (`lib.rs:1863-1867`) and expiry (`lib.rs:783`) apply. | **Credits again** if the balance equals the expected value before expiry | none (the key is the dedup key) | none |

### 4b. Deposit and wallet actions

| Action (dispatch) | request_id constraint | Permanent dedup key(s) | Live-state permanent dedup? | Re-execution if key dropped | Extra compact fields | Active-state dependency |
|---|---|---|---|---|---|---|
| `CreditDeposit` (`lib.rs:1879-1902`) | none | lower-cased custody reference (`lib.rs:1890-1895`) | **Yes** | Fails with `CustodyReferenceReuse` | none | none |
| `CreditZenDeposit` (`lib.rs:1903-1909`) | none | `horizen-zen-deposit:{lower}` (`lib.rs:1906`) | **Yes** | Fails with `CustodyReferenceReuse` | none | none |
| `CreditHorizenUsdcDeposit` (`lib.rs:1910-1926`) | none | `horizen-usdc-deposit:{lower}` (`lib.rs:1919-1924`) | **Yes** | Fails with `CustodyReferenceReuse` | none | none |
| `CreditArbitrumUsdcBusDeposit` (`lib.rs:1927-1949`) | `usdc-bus-deposit-credit:{op}` (`lib.rs:1930`) | boarding reference and `arbitrum-usdc-bus-operation:{op}` (`lib.rs:1935-1944`) | **Yes** | Fails with `CustodyReferenceReuse` | `identity_commitment`, `amount_atomic`, `custody_reference` | **Yes**, while `op` is in `conditional_usdc_deposits` (2b#2–3) |
| `FinalizeArbitrumUsdcBusDeposit` (`lib.rs:1950-1964`) | `usdc-bus-deposit-finalize:{op}` (`lib.rs:1952`) | Horizen deposit reference (`lib.rs:1960-1961`); pending entry removed (`lib.rs:1962`) | **Yes** | Fails with `InvalidRequest` (no pending entry) | `identity_commitment`, `amount_atomic`, `custody_reference` (for the `lib.rs:1351-1361` check) | Pair check only |
| `LinkFinancialWallet` (`lib.rs:1965-1976`) | none | none (no money effect) | N/A. Re-linking the same wallet to the same subject **succeeds again** (`lib.rs:1971-1974`). | **New commit** (a non-financial duplicate) | none | none |

### 4c. Bus withdrawal actions

| Action (dispatch) | request_id constraint | Permanent dedup key(s) | Live-state permanent dedup? | Re-execution if key dropped | Extra compact fields | Active-state dependency |
|---|---|---|---|---|---|---|
| `BeginUsdcBusWithdrawal` (`lib.rs:1977-1998`) | `== withdrawal_id` (`lib.rs:1979`) | `(account, withdrawal_id)` | **No.** `usdc_bus_withdrawals` blocks only while the hold is active (`lib.rs:1980`, removed at `lib.rs:2032`). A `WITHDRAWAL_REJECTED` result (`lib.rs:1986-1989`) leaves **no** other trace. | **New hold, and later a payout, after funding.** This is exactly what the test at `lib.rs:5153-5173` guards against. | `identity_commitment`, `amount_atomic`, `custody_reference` (reservation binding `lib.rs:1996`) | **Yes**, while no settle/revert key exists (2b#4) |
| `SettleUsdcBusWithdrawal` / `RevertUsdcBusWithdrawal` (`lib.rs:1999-2034`) | `usdc-bus-{settle\|revert}:{id}` (`lib.rs:2003-2005`) | custody, pool, delivery, and seat references (`lib.rs:2016-2031`); hold removed | **Yes** | Fails (`InvalidRequest` with no hold, or `CustodyReferenceReuse`) | `identity_commitment`, `amount_atomic`, `custody_reference` (for `lib.rs:1395-1397`). The **key itself** is load-bearing (`lib.rs:1414-1415`). | The key marks the reservation inactive |

### 4d. Order and market-position actions

| Action (dispatch) | request_id constraint | Permanent dedup key(s) | Live-state permanent dedup? | Re-execution if key dropped | Extra compact fields | Active-state dependency |
|---|---|---|---|---|---|---|
| `PlaceOrder` (`lib.rs:2035-2078`) | none | `order_id` (`lib.rs:2742`) | **Yes** (orders are never removed) | Fails with `InvalidOrder` | none. Trades and projections go to the archive only. | none |
| `CancelOrder` (`lib.rs:2079-2082`, `lib.rs:3178-3244`) | none | none (no new money) | N/A. A FOK-rejected order can be "cancelled" again harmlessly (`lib.rs:3187-3202`). A book order's second cancel depends on `PriceTimeBook::cancel`, which is **not verifiable from lib.rs**. | Harmless `ORDER_CANCELLED` with 0, **or** `InvalidOrder` | none | none |
| `RedeemCompleteSet` (`lib.rs:2083-2105`) | none | `(account, request_id)` | **No** | **Redeems again** if claims remain | none | none |

### 4e. Immediate withdrawal and transfer actions

| Action (dispatch) | request_id constraint | Permanent dedup key(s) | Live-state permanent dedup? | Re-execution if key dropped | Extra compact fields | Active-state dependency |
|---|---|---|---|---|---|---|
| `ReserveWithdrawal` (`lib.rs:2106-2136`) | none | `(account, request_id)`. The hash binds only the `lei-` intent (`lib.rs:3932-3953`). | **No.** The custody reference is **not** inserted into `credited_custody_references`. | **Debits again** | none | none |
| `ReserveZenWithdrawal` (`lib.rs:2137-2149`) | none | `(account, request_id)` (hash `lib.rs:3883-3888`) | **No** | **Debits again** | none | none |
| `RecordZenWithdrawalReverted` (`lib.rs:2137-2148`) | none | none (no money) | N/A | New money-free commit | none | none |
| `SettleRelayWithdrawal` (`lib.rs:2150-2178`) | none | `(account, request_id)` (hash `lib.rs:3976-4002`) | **No** | **Debits again** | none | none |
| `RecordWithdrawalReverted` (`lib.rs:2179-2196`) | none | none (no money) | N/A | New money-free commit | none | none |
| `RecordRelayWithdrawalReverted` (`lib.rs:2197-2212`) | none | none (no money) | N/A | New money-free commit | none | none |
| `Transfer` (`lib.rs:2213-2238`) | none | `(account, request_id)` | **No** | **Transfers again** | none | none |

### 4f. Consequences

- For seven families the request key is the **only** permanent financial dedup:
  - `GovernedBalanceRecovery`
  - `BeginUsdcBusWithdrawal`
  - `RedeemCompleteSet`
  - `ReserveWithdrawal`
  - `ReserveZenWithdrawal`
  - `SettleRelayWithdrawal`
  - `Transfer`

  In addition, `ResolveMarket` relies on the request key alone for the
  `resolution_id` identifier. So the `(account_id, request_id) → request_hash`
  index can **never** be pruned, only slimmed. Any design that evicts keys
  violates `FULL_STATE_JOURNAL_V71_CONTRACT.md:30-33`.
- For every family, exact replay of the *original* result needs either the full
  result or archive bytes. None of the live structures reproduces the receipt.
- Existing live state already preserves permanent dedup for these families:
  - `AdmitIdentity`
  - `RegisterMarket` (per market)
  - `ResolveMarket` (per market)
  - `CreditDeposit`
  - `CreditZenDeposit`
  - `CreditHorizenUsdcDeposit`
  - `CreditArbitrumUsdcBusDeposit`
  - `FinalizeArbitrumUsdcBusDeposit`
  - `SettleUsdcBusWithdrawal`
  - `RevertUsdcBusWithdrawal`
  - `PlaceOrder`

  Compaction must not prune the structures those families depend on.
- Observed and not changed: the immediate-withdrawal families accept the same
  `lei-` intent under a *different* request id in lib.rs. Any cross-request
  intent dedup lives outside lib.rs. That is v70 behavior and is outside this
  scope.

## 5. Smallest data split

"Bounded" here means **bounded bytes per historical request**. The entry count
stays O(committed sequence), because Section 4 shows the key set is
load-bearing. Other unbounded live sets (`orders` including terminal orders,
`credited_custody_references`, `markets`) are outside request-history scope and
are not bounded by this change.

v71 live state replaces the single map with three parts:

```text
sequence: u64                                   // explicit and authoritative; drives journal seq and nonce
request_index: BTreeMap<(account_id, request_id), RequestTerminal>   // never pruned
active_results: BTreeMap<(account_id, request_id), (request_hash, DirectResult)>  // full, bounded by pending entitlements

RequestTerminal {
  request_hash: String,           // verbatim; never recomputed (§3.6)
  status: TerminalStatus,         // DirectResult.status, verbatim
  effect: String,                 // DirectResult.effect, verbatim
  genesis_ordinal: u64,           // DirectResult.genesis_ordinal, verbatim (not assumed 0 for old lineage)
  receipt_digest: [u8; 32],       // sha256(serde_cbor(DirectReceipt)) including signature
  locator: ArchiveLocator,        // v70: {epoch_id, sequence, request_hash}; v71: {epoch_id, sequence, record_hash}
  identity_commitment: Option<String>,  // Some(..) only for families marked in §4
  amount_atomic: Option<String>,        // idem
  custody_reference: Option<String>,    // idem
}
```

Rules:

1. **Compaction eligibility.** An entry may move from `active_results` to
   compact-only when it is **not** one of the following:
   - (a) a `WITHDRAWAL_RESERVED` entry with no `usdc-bus-settle:`/`usdc-bus-revert:`
     key for the same account and id;
   - (b) a `usdc-bus-deposit-credit:{op}` entry whose `op` is still in
     `conditional_usdc_deposits`.

   `active_results` is therefore bounded by the number of pending holds and
   pending conditional deposits. There is at most one active bus hold per
   identity (`lib.rs:1981`) and at most one pending conditional deposit per
   wallet (`lib.rs:1939`). Before compacting, the implementation must run
   `verify_receipt` on the entry, compute `receipt_digest`, and fill the header.
   Its `RequestTerminal` must be equal to the header derived from the full entry.
2. **Replay lookup** (all of `execute`, `existing_result`, `execute_committed`,
   `prepare_candidate`, `public_quest_receipt`):
   - Index miss: execute as today.
   - Hash mismatch: `RequestReuse`.
   - Hash match with the full entry in `active_results`: return it.
   - Hash match with a compact-only entry: return a new error that carries
     `locator`/`receipt_digest`, and **never** execute.

   Retrieval is two-phase. The handler obtains bytes from the untrusted parent
   and calls a verifier that does all of the following:
   - decodes the `DirectReceipt`;
   - requires `sha256(bytes) == receipt_digest`;
   - requires `verify_receipt`;
   - requires account, request id, `request_hash`, status, effect, and any
     retained header fields to equal the index;
   - rebuilds `DirectResult {status, effect, genesis_ordinal, receipt}` from the
     header.

   Any failure or missing bytes fails closed, with no state change and no
   artifact. The ordering before mode checks (`lib.rs:1680` vs `lib.rs:1687`)
   must be kept.
3. **Restore validators.**
   - `reconstruct_bus_holds` iterates `active_results` for active reservations,
     with its current HMAC and binding checks unchanged.
   - `validate_conditional_deposits` does the same for pending credits.
   - Terminal settle/revert and finalized credit/finalize pairs are checked
     against `request_index` header fields: effect, identity, amount, custody
     reference validity, and credited-reference membership. This covers
     `lib.rs:1389-1400` and `lib.rs:1351-1361` **without** re-running HMAC on
     every restore.

   This is a reduction from v70, which re-verifies HMAC on every apply. It needs
   **explicit sign-off from the contract owner (Codex)**. The alternative that
   keeps HMAC re-verification is to retain those pairs in full, but that makes
   them unbounded.
4. **Sequence.**
   - Use the explicit `sequence` for `seal_artifact`/journal, the nonce,
     `committed_sequence()`, `restore_checkpoint`'s fresh check (`lib.rs:2456`),
     `portfolio` (`lib.rs:3448`), and quest (`quest_receipts.rs:291`).
   - Assert `request_index.len() as u64 == sequence` at commit and restore as a
     consistency check only.
5. **Archive.** For v70-lineage entries, the signed receipt already exists in
   two places:
   - the per-request artifact (`lib.rs:1135`, keyed by `request_hash`,
     `lib.rs:1495`);
   - the MAC-bound checkpoint `receipt_records` (`lib.rs:1148`).

   For v71 entries, the journal record commits the signed-receipt hash
   (`FULL_STATE_JOURNAL_V71_CONTRACT.md:83-90`). `receipt_digest` must use the
   same hash so that a journal record can serve as the archive source.
6. **v70 rollback export.** To rebuild `DirectState.requests`, take every index
   entry and apply rule 2's verifier to its archived bytes. Use `active_results`
   verbatim. Leave `usdc_bus_withdrawals` unserialized (`lib.rs:5321-5337`). Then
   serialize with the v70 `DirectState`. The resulting `sha256` must equal
   v70's. A missing or mismatched receipt aborts the export.

Decisions left to the contract owner (not invented here):

- Rule 3's validation reduction.
- Whether `prepare_candidate`'s replay re-seal path (`lib.rs:2346-2357`)
  survives in v71, or is replaced by the two-phase replay.
- The exact canonical encoding for `receipt_digest` (this document proposes
  `serde_cbor` to match the existing `artifact_hash`, `lib.rs:1269-1271`).
- The meaning of `state_root` in `public_quest_receipt` (`quest_receipts.rs:292`)
  once the state root differs from the v70 full-state hash.

## 6. Migration checklist

1. Keep all v70 characterization tests green and unchanged:
   - `lib.rs:6741`
   - `lib.rs:6785`
   - `lib.rs:6825`
   - `lib.rs:6873`
   - `lib.rs:6927`
   - `lib.rs:7069`
2. Add the types behind a v71 state version. v70 `DirectState` decode and encode
   stay byte-identical.
3. Bootstrap from v70 head `H`:
   - restore the full v70 state (v70 path unchanged);
   - validate the v70 checkpoint (`lib.rs:2472-2500`);
   - map each request key to its `sequence` using the validated
     `receipt_records` order;
   - build `request_index` and `active_results`;
   - set `sequence = H`;
   - assert `index.len() == H`;
   - verify that every `receipt_digest` matches `receipt_records[i].receipt`.
4. Compact only at committed boundaries. Compaction is deterministic and a pure
   function of state, so shadow and writer produce identical state.
5. The rollback export (rule 6) must succeed at `H` and at a later compacted
   head before cutover eligibility.
6. Parent/handler changes for two-phase archive fetch belong to other workers.
   This audit specifies only the lib-level API contract.

## 7. Test checklist

Run each item against three runtimes: live, restored-from-journal, and
restored-from-checkpoint. Run each both before and after compaction.

- [ ] **Exact replay, all 23 `DirectAction` families**:
  - With the archive present, the result is byte-equal to the original,
    including the signature.
  - No successor is created; sequence and state hash are unchanged.
  - This also holds in `Dormant` mode (extends `lib.rs:6741-6782`).
- [ ] **Archive absent, wrong digest, bad HMAC, or header field mismatch**:
  - Fails closed with no store write.
  - Balances, holds, positions, and sequence are unchanged.
  - Explicitly asserts **no re-execution** for the families that would
    re-execute successfully:
    - `GovernedBalanceRecovery`
    - `BeginUsdcBusWithdrawal` rejected-then-funded (`lib.rs:5153`)
    - `RedeemCompleteSet`
    - `ReserveWithdrawal`
    - `ReserveZenWithdrawal`
    - `SettleRelayWithdrawal`
    - `Transfer`
    - `LinkFinancialWallet`
    - `CancelOrder` on a FOK order
    - the money-free revert families
- [ ] **Conflicting request id** on a compacted entry returns `RequestReuse`
  from all four entry points (extends `lib.rs:6785-6822`).
- [ ] **Shared request-hash pairs** (§3.6) replay the original result after
  compaction.
- [ ] **Permanent dedup after compaction with a new request id**:
  - Each deposit reference class fails with `CustodyReferenceReuse` (extends
    `lib.rs:5402`, `lib.rs:4859`).
  - Bus terminal pool, delivery, and seat references fail with
    `CustodyReferenceReuse` (extends `lib.rs:5257`, `lib.rs:5267`,
    `lib.rs:5286`).
  - `order_id` reuse fails with `InvalidOrder`.
  - Re-admission fails with `IdentityAlreadyAdmitted`.
  - A second resolution of the same market fails with `InvalidMarket`. **No
    existing lib.rs test covers a second `ResolveMarket` with a different
    `resolution_id`; add one.**
  - Reusing a `resolution_id` or `recovery_id` fails with `RequestReuse`.
- [ ] **Active entitlements**:
  - A pending bus hold and a pending conditional deposit survive compaction plus
    checkpoint-plus-tail restore.
  - Compaction refuses active entries.
  - The negative variants from `lib.rs:5339-5359` and `lib.rs:4884-4899` still
    fail against `active_results`.
  - Deleting a compacted settle/revert key from the index fails restore. It
    must not re-activate the hold.
- [ ] **Sequence**:
  - Compaction never changes `sequence`.
  - Index/sequence mismatch fails restore.
  - The nonce is unique across compaction.
  - `restore_checkpoint` rejects a non-fresh runtime by explicit sequence.
- [ ] **v71→v70 export**:
  - The v70 `DirectState` from the export is byte-equal to an uncompacted
    twin's `snapshot()`.
  - It restores through `restore_committed`, `restore_next_committed`, and
    `restore_checkpoint`.
  - Export with one missing receipt fails closed.
- [ ] **`public_quest_receipt`** after compaction:
  - It uses verified archive bytes or fails closed.
  - Its output is unchanged for `ORDER_EXECUTED` fills (`quest_receipts.rs:229-253`).
- [ ] **Size**:
  - Per-entry compact bytes are independent of trade count and touched-identity
    count. Test with a multi-fill order and with a resolution across many
    holders.
  - Repeat `lib.rs:7069-7082` to show that request-history growth per entry is
    constant and small.

## 8. Evidence limits

- `PriceTimeBook::cancel` behavior on a non-resting order lives in the matching
  crate, which was not inspected. The `CancelOrder` re-execution outcome is
  therefore stated as unverified.
- It was not proven, for the historical production lineage, that
  `DirectResult.{status,effect,genesis_ordinal}` always equals the receipt's
  fields. The proposal therefore stores them verbatim instead of deriving them.
- `journal.rs`, `enclave.rs`, `parent.rs`, and the fixtures were not inspected,
  per scope. Compatibility of `ArchiveLocator` with the v71 journal record
  format must be confirmed by the contract owner.
