# E10-S02 — Complementary MINT matching certification

## Scope

This evidence certifies the private-core path that matches a resting `BUY UP`
with an incoming `BUY DOWN` and atomically mints one fully collateralized
complete set. It does not deploy an EIF, alter production state, or move funds.

The vectors are funded through the same evidence-bound external-flow entrypoint
used by production deposits. They use opaque enclave-local principals and never
introduce privileged balance mutation.

## Acceptance matrix

| Invariant | Executable evidence |
|---|---|
| Exact boundary crossing | `complementary_buy_boundary_partial_and_fok_semantics_are_deterministic` and `mint_then_merge_conserves_collateral_and_charges_only_the_taker` |
| Better crossing price | `better_price_mint_refunds_limit_improvement_and_replays_exactly_once` proves a 70c DOWN limit executes at the 60c complement of a resting 40c UP order |
| Non-cross and FOK semantics | `complementary_buy_boundary_partial_and_fok_semantics_are_deterministic` |
| Partial execution | `live_shape_partial_mint_is_ready_for_resolution_after_cancelling_remainder` and `partial_mint_survives_encrypted_snapshot_and_releases_remainder_once` |
| Self-trade prevention | `complementary_self_trade_is_prevented_across_outcomes` |
| Fee correctness | `better_price_mint_refunds_limit_improvement_and_replays_exactly_once` checks the exact charged fee, unused limit/fee-reserve refund, and no maker fee |
| Asset conservation | The better-price and snapshot vectors reconcile both funded balances, order holds, market collateral and fee revenue to the original funded total |
| Claim solvency | `mint_then_merge_conserves_collateral_and_charges_only_the_taker` and `complementary_mint_at_live_prices_remains_fully_collateralized_through_resolution` |
| Same-command replay | `better_price_mint_refunds_limit_improvement_and_replays_exactly_once` proves an identical response and unchanged state root/fee balance |
| Snapshot replay safety | `partial_mint_survives_encrypted_snapshot_and_releases_remainder_once` restores the encrypted checkpoint, rejects an archived pre-snapshot command without mutation, and continues with a newly signed cancellation |
| Settlement precision | `fok_ignores_complete_set_quantity_that_cannot_split_at_settlement_precision`, `complementary_rounding_dust_does_not_poison_a_price_level`, and precision-safe randomized crossing vectors |
| Determinism | Fresh-run state-root/audit equality plus randomized order-book replay equality |

## Required gates

Run from the repository root:

```bash
cargo fmt --check
cargo test --test complete_set_matching
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The authoritative GitLab merge-request pipeline must also pass every required
Rust job before the story may be marked complete. A local pass is necessary but
not sufficient.

## Audit conclusions

- Crossing is `maker_price + taker_limit >= 1.000000`; execution uses the exact
  complement of the maker price, so better taker limits receive improvement.
- Only the incoming order pays the deterministic taker fee. A resting BUY holds
  principal only; its temporary fee reserve is refunded when it becomes maker
  liquidity.
- MINT debits exactly one settlement unit per share into market collateral and
  issues exactly one UP plus one DOWN claim. All changes are applied to a
  command-local clone and committed only if every leg succeeds.
- Same-instance retries return the archived response. After snapshot restore,
  processed hashes prevent duplicate execution even when the response must be
  recovered from the external receipt archive.
- Below-precision complete-set candidates are skipped without poisoning later
  executable liquidity at the same price.

## Exclusions

This story does not certify complementary SELL/SELL MERGE, normal BUY/SELL
matching, live funded production trading, EIF measurements, deployment, or
soak. Those are separate checklist stories.
