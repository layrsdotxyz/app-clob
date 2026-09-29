# v71 current-frontier V1 — 2026-09-30 05:08 IST

Result: **PASS** for handoff preparation. This evidence is read-only and must
be refreshed immediately before the candidate change set is executed.

- Live bridge host `i-0703876e6c51483dc` is the sole ASG instance, healthy and
  `InService`; the parent is active with zero restarts and approximately
  2.13 GB `MemoryCurrent`.
- Runtime status reports writer enabled, admission enabled, no lock waiters,
  grant commitment `c084d333...a361`, and key-release artifact
  `2dba8aa7...39025`.
- Immutable archive head observed at sequence 43,192, artifact
  `9869bdcc9d08075d48a606beb4c90dc7cd4eacef30717925d4ff0d63502acbd8`,
  168,456,728 bytes. Latest checkpoint observed at sequence 43,188,
  state hash `760140ee66eef1a20653243b6da79912cb7967a224b51f51de2008a40b6b12b0`,
  248,651,546 bytes.
- Projection had 43,188 receipts at 05:06 IST and remained continuous with
  the immutable head as commits advanced.
- Projection authority is exactly one fence and one grant, both bound to live
  bridge activation `layrs-v70-bridge-d5e65d7-20260929-2e8c50ea`;
  `old_writer_authorized=false`, `target_writer_enabled=true`.
- Exactly one active direct withdrawal exists: the explained mm01 hold
  `dff330c1-4ca3-46de-bb86-d192b8ddcc67`, `BOARDED`, 20,000,000 atomic,
  reservation receipt `323fada4...41e`, and existing Base delivery transaction
  `0x29a807...c62e5`. It is carried forward unchanged and must not be paid twice.
- There are zero other active direct withdrawals. The 54 `BALANCE_PENDING`
  deposit-index rows are passive watchers: zero source-transaction bindings
  and zero balance bindings.
- Two legacy `DEPOSIT_EOA` rows remain `DETECTED` from 5–6 September for
  10,000 and 9,993 atomic. Neither has a destination transaction or later
  mutation; neither is an enclave external-effect intent. They are recorded,
  not reclassified or changed by this rollout.
- Previously reconciled immutable external-effect inventory remains 10 intents
  plus one reconciliation, with no new mm01 payout intent. No unexplained hold
  or new unresolved enclave external effect was found.

The handoff refresh must re-read the sole host, target health, projection
authority, active withdrawals/deposits, newest head and newest checkpoint. Any
second writer, unexplained hold, projection discontinuity, lineage mismatch or
new unresolved external effect is a no-go.
