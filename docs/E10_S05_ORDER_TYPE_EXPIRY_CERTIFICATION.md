# E10-S05 — Order type and expiry certification

## Scope

This story certifies native private-CLOB GTC, GTD, FAK and FOK behavior across
partial execution, expiry, cancellation, market close, recurring-window
rollover and resolution. It does not deploy an EIF, move funds, merge a branch
or change the public API.

## Audit finding and correction

The pre-story engine excluded expired GTD orders from matching and public
depth, but left them `OPEN`, retained their grouped cash/claim hold, and counted
them against the owner position limit. A valid replacement could therefore
fail after the GTD deadline until the user explicitly cancelled the expired
order or the market resolved.

The correction is deliberately narrow. Enclave time cannot mutate state by
itself, so the next valid journalled write to a native market deterministically
cancels all elapsed orders and releases their grouped holds before position
limit validation and matching. The expiry sweep and the new command commit in
one atomic state transition. Explicit cancellation remains available, and
resolution still cancels every remaining live order.

## Acceptance matrix

| Invariant | Executable evidence |
|---|---|
| GTC | Remainders rest until explicit cancellation, close or resolution |
| GTD | Missing/past expiry fails; elapsed resting orders cancel at the next valid write boundary and release their holds |
| FAK | Available liquidity fills deterministically and the unfilled remainder is cancelled |
| FOK | Insufficient liquidity rejects without a partial fill; sufficient liquidity fills completely |
| Held collateral | GTD expiry, explicit cancellation and resolution return exactly the no-longer-required grouped hold |
| Close | New orders fail at the close boundary and public depth is empty |
| Rollover | New-window orders use a distinct market/hold domain; old-window orders cannot match or debit the new window |
| Resolution | All remaining GTC/GTD orders are cancelled before payout; post-resolution trade/cancel attempts fail closed |
| Replay | User-command retries return the archived response without mutation; two identical snapshot restores resolve to the same semantic receipt and state root while journal encryption retains fresh nonces |
| Conservation | Available plus held settlement asset remains equal to the evidence-bound inflow when no fill occurs |

## Required gates

```bash
cargo fmt --check
cargo test --locked --test order_type_expiry_lifecycle -- --nocapture
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

The authoritative GitLab merge-request pipeline must pass both Rust stages.
Local success is necessary but not sufficient.

## Exclusions

Order replacement, cancel-all API filters, WebSocket delivery, deployment,
funded production canaries and soak are separate checklist stories.
