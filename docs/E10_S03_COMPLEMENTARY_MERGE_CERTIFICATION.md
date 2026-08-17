# E10-S03 — Complementary MERGE matching certification

## Scope

This evidence certifies the private-core path that matches a resting `SELL UP`
with an incoming `SELL DOWN`, consumes both users' opposite-outcome claims,
burns the complete set, and returns its collateral without exposing either
principal. It does not deploy an EIF, alter production state, or move funds.

The executable vectors obtain claims through the same evidence-bound external
funding and MINT flow used by the core. They do not use privileged balance
mutation or synthetic claims.

## Acceptance matrix

| Invariant | Executable evidence |
|---|---|
| Exact boundary crossing | Existing `complementary_sell_boundary_crosses_but_price_sum_above_one_does_not` and `mint_then_merge_conserves_collateral_and_charges_only_the_taker` vectors |
| Better crossing price | `better_price_merge_burns_complete_set_charges_fee_and_replays_exactly_once` proves a 50c DOWN sell limit executes at the 60c complement of a resting 40c UP seller |
| Partial execution and cancellation | `partial_merge_survives_encrypted_snapshot_and_cancel_releases_claims_once` |
| Self-trade prevention | `merge_self_trade_and_below_precision_liquidity_fail_closed` |
| Fee and rebate correctness | The better-price vector checks the current Layrs curve fee, maker rebate accrual, taker proceeds, and absence of duplicate fee on replay |
| Complete-set burn conservation | Better-price and partial vectors reconcile user settlement balances, fee revenue, and remaining market collateral to the funded total |
| Claim conservation | Both vectors prove one UP and one DOWN claim are consumed per burned set; the partial vector retains and releases exactly the unmatched claim quantity |
| Same-command replay | The better-price vector proves byte-identical response, unchanged state root, and unchanged fee balance |
| Snapshot replay safety | The partial vector restores the encrypted checkpoint, rejects an archived pre-snapshot MERGE without mutation, and continues with a newly signed cancellation |
| Settlement precision and dust | `merge_self_trade_and_below_precision_liquidity_fail_closed` plus precision-safe randomized MERGE vectors |
| Determinism | Fixed replay equality plus randomized book replay equality |

## Required gates

Run from the repository root:

```bash
cargo fmt --check
cargo test --locked --test complementary_merge_matching -- --nocapture
PROPTEST_CASES=10000 cargo test --locked --test complementary_merge_matching \
  complementary_merge_crossing_is_deterministic_for_precision_safe_vectors \
  -- --exact --nocapture
cargo test --all-targets --all-features
cargo clippy --all-targets --locked -- -D warnings \
  -A dead-code \
  -A clippy::too-many-arguments \
  -A clippy::type-complexity \
  -A clippy::large-enum-variant \
  -A clippy::needless-range-loop \
  -A clippy::empty-line-after-doc-comments \
  -A clippy::wrong-self-convention \
  -A clippy::enum-variant-names
```

The authoritative GitLab merge-request pipeline must pass every required Rust
job before the story may be marked complete. Local success is necessary but is
not sufficient.

## Audit conclusions

- MERGE crossing is `maker_price + taker_limit <= 1.000000`; execution pays the
  taker the exact complement of the maker price, so lower sell limits receive
  price improvement.
- Both SELL legs reserve claim quantity, never settlement cash. Each fill
  restores the claims under one owner, burns exactly one complete set, then
  divides the released collateral between maker, taker, and fee revenue.
- The incoming taker alone pays the configured deterministic fee. Resting maker
  liquidity accrues the configured private rebate entitlement.
- Every accounting leg is applied to a command-local clone and commits only if
  claim consumption, complete-set burn, payout, and fee transfer all succeed.
- Same-instance retries return the archived response. After snapshot restore,
  processed hashes prevent a second burn even without the response archive.
- Below-precision complete-set candidates are skipped without poisoning later
  executable MERGE liquidity at the same price.

## Exclusions

This story does not certify complementary BUY/BUY MINT, normal BUY/SELL
matching, live funded production trading, EIF measurements, deployment, or
soak. Those are separate checklist stories.
