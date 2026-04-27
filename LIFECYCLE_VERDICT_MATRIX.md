# Lifecycle Verdict Matrix

This matrix captures the current milestone verdict for the validated lifecycle slices and the CLOB orderbook scenarios covered in this pass.

Verdict legend:

- `Green`: automated coverage exists and is currently passing.
- `Yellow`: core behavior is covered, but an operational or automation gap remains.
- `Red`: missing coverage or known incorrect behavior.

| Surface | Scenario | Harness | Evidence | Verdict | Notes |
| --- | --- | --- | --- | --- | --- |
| Prediction market | Deposit lifecycle | Existing focused lifecycle slice | Prior passing PM lifecycle slice | Green | Included in the already-green PM deposit/order/settlement/withdraw coverage baseline. |
| Prediction market | Order commit lifecycle | Existing focused lifecycle slice | Prior passing PM lifecycle slice | Green | Covered before this pass; used as baseline input to this matrix. |
| Prediction market | Trade settlement lifecycle | Existing focused lifecycle slice | Prior passing PM lifecycle slice | Green | Existing PM settlement slice remained green while CLOB durability work landed. |
| Prediction market | Withdraw lifecycle | Existing focused lifecycle slice | Prior passing PM lifecycle slice | Green | Existing withdraw slice remained green. |
| Prediction market | Claim lifecycle | Existing focused lifecycle slice | Prior passing PM claim slice | Green | Claim coverage was completed before the CLOB hardening pass. |
| Yield | Distribution / claim lifecycle | Existing focused lifecycle slice | Prior passing yield slice | Green | Yield lifecycle was completed before the CLOB orderbook work began. |
| CLOB durability | Immediate full fill persists terminal taker snapshot | Mini-redis compat unit test | `matching::tests::test_lifecycle_full_fill_persists_terminal_order_snapshot` | Green | Verifies taker full-fill snapshot is durable and terminal (`Filled`, remaining `0`). |
| CLOB durability | Cancel preserves historical cancelled snapshot | Mini-redis compat unit test | `matching::tests::test_lifecycle_cancel_preserves_cancelled_order_snapshot` | Green | Verifies cancelled orders are retained for later reads instead of being deleted from history. |
| CLOB rollback safety | FOK reject preserves resting maker state | Mini-redis compat unit test | `matching::tests::test_lifecycle_fok_reject_preserves_resting_maker_order` | Green | Guards the new pre-match FOK liquidity check so the maker book is not mutated on underfilled FOK attempts. |
| CLOB orderbook | Rest-then-fill GTC | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | Validates real sorted-set book behavior plus durable DB rows for maker and taker. |
| CLOB orderbook | Partial-fill cancel | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | Validates partial maker snapshot persistence, later cancel persistence, and empty final book state. |
| CLOB orderbook | IOC tail cancel | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | Validates that the taker never rests, the filled maker is terminal, and the IOC tail is persisted as a non-resting terminal partial. |
| CLOB orderbook | FOK rollback / reject | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | Validates rejection before any maker mutation and asserts zero trade/fill rows for the failed FOK attempt. |
| CLOB persistence | Order rows must durably persist in Postgres | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | New integration suite asserts one durable `orders` row per order ID with correct final status and remaining amount. |
| CLOB persistence | Non-UUID users map into `users` correctly | Real Redis 7 + Postgres 15 Docker integration test | `tests/orderbook_real_backends.rs` | Green | DB assertions join `orders.user_id` back to `users.evm_address`, covering the `resolve_user_uuid()` fix. |
| CLOB ops | Real-backend suite enforced in PR CI | Docker-backed integration test | `.github/workflows/integration-tests.yml` + `tests/orderbook_real_backends.rs` | Green | Pull requests now run the targeted Docker-backed Redis 7 / Postgres 15 suite as an explicit job. |
| CLOB durability | Trade/fill DB persistence | Redis-backed retry worker + real backends test | `SettlementEngine::start_trade_persistence_worker()` + `tests/orderbook_real_backends.rs` | Green | Trades and fills are now queued durably in Redis and retried until PostgreSQL persistence succeeds. |

## Current verdict

The requested lifecycle matrix is now green for the validated PM slices, the yield slice, and the four real-book CLOB scenarios, including the previously-open CLOB trade/fill durability and PR-CI enforcement gaps.

## Validation commands

Focused CLOB lifecycle checks:

```bash
cargo test test_lifecycle_full_fill_persists_terminal_order_snapshot
cargo test test_lifecycle_cancel_preserves_cancelled_order_snapshot
cargo test test_lifecycle_fok_reject_preserves_resting_maker_order
```

Real-book Redis/Postgres suite:

```bash
cargo test --test orderbook_real_backends -- --ignored --test-threads=1
```