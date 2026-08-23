# Private order hold/release postings

E09-S03 keeps order accounting inside the attested private core. No wallet,
email, opaque owner, individual order, price, quantity, balance, or posting leg
is added to a public API, database projection, depth feed, receipt, or proof.

## Accounting boundary

Every internal `Transfer` now emits an enclave-local general-ledger pair:

```text
DEBIT  source account
CREDIT destination account
```

The amount and asset are identical. For a BUY order the reserve is therefore:

```text
DEBIT  UserAvailable(asset, custody domain)
CREDIT UserOrderHold(asset, market, outcome, custody domain)
```

The current unified custody mapping is `USDC -> base-usdc` and `ZEN ->
horizen-zen`; the source network used for a deposit is not a second trading
balance. Consequently an account's asset plus the registered market settlement
asset deterministically selects one custody domain and cannot cross domains
during reserve, fill, or release.

A cancellation or expired/resolved-market cleanup emits the exact reverse for
the remaining quantity. A fill consumes only the filled portion; a partial fill
leaves the exact required remainder in `UserOrderHold`. SELL orders apply the
same invariant to private claim inventory instead of cash.

`Ledger::apply` computes all debits and credits against a cloned balance map,
checks subtraction/addition, and commits only after every leg succeeds. Thus a
failed, insufficient, duplicate, precision-invalid, cancel-loses, or fill-loses
transition changes neither balances, sequence nor state root. The private core
also executes each command on cloned ledger/book/session state and journals the
new root before replacing live state.

## Replay and lost-response boundary

The enclave command idempotency key is part of the encrypted command and its
receipt commitment. Live retries return the cached response. Snapshot-restored
retries return `PREVIOUSLY_PROCESSED`; the public API must recover the immutable,
subject-owned receipt by idempotency key before redispatch. It may expose only
signed receipt/journal commitment evidence, never private order fields.

## Certification matrix

| Case | Evidence |
|---|---|
| atomic reserve, debit equals credit | `ledger_is_atomic_conservative_and_idempotent`; `order_hold_postings_are_atomic_exact_and_race_safe` |
| insufficient/rejected command leaves no mutation | `insufficient_transfer_does_not_partially_mutate_ledger`; `fok_rejects_without_mutating_resting_liquidity` |
| single reserve/replay | `order_hold_postings_are_atomic_exact_and_race_safe`; private-core command replay tests |
| partial fill and exact remainder | `native_clob_partial_fill_locks_remainder_and_cancel_releases_once` |
| full fill | `private_core_executes_collateralized_trade_and_profit_fee_resolution` |
| explicit cancel and duplicate cancel | `native_clob_partial_fill_locks_remainder_and_cancel_releases_once` |
| market expiry/resolution cancellation | `expired_market_rejects_position_close_but_allows_unfilled_hold_release`; resolution tests |
| one-atomic-unit dust | `order_hold_postings_are_atomic_exact_and_race_safe`; `complementary_rounding_dust_does_not_poison_a_price_level` |
| concurrent cancel/fill serialization | `order_hold_postings_are_atomic_exact_and_race_safe` |
| snapshot/replay recovery | encrypted snapshot restore and complete-set replay tests; backend immutable-receipt recovery tests |

This story does not introduce a plaintext backend order ledger. Backend retry
and read projections remain receipt commitments keyed to the authenticated
subject; the authoritative balances and posting legs remain enclave-only.
