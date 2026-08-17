# Balanced confirmed-deposit postings

`CreditDeposit` is the only enclave command that recognizes a finalized user
deposit. It now commits two normal-side postings in one private state-root
transition:

| Side | Account | Enclave bucket |
|---|---|---|
| Debit | Custody pool cash (`1000`) | `PoolCash` owned by `layrs` |
| Credit | User available liability (`2000`) | `UserAvailable` owned by an opaque private user ID |

Both legs use the same settlement asset and atomic amount. The custody asset
and user liability therefore increase together; the operation is not modeled
as a token transfer between them.

## Authority and privacy boundary

- The deposit worker may call `CreditDeposit` only after it has independently
  finalized the canonical LayrsPool receipt. Provider state, source detection,
  a Relay request, or a quote is not sufficient evidence.
- The command requires a non-zero evidence hash and a non-zero amount.
- The user account is derived from the identity commitment inside the enclave.
  Email, authentication subject, source wallet, route and provider are not
  ledger-account dimensions and are not emitted by the response.
- The idempotency key is committed before either balance is published. A retry
  cannot credit either leg twice.
- Direct, routed and late deposits use the same enclave posting once the
  canonical pool receipt is final. Below-minimum and refunded routes never call
  this command and therefore create neither leg.

## Compatibility

The historical `ExternalFlow` command retains its one-account semantics for
venue inventory and other external asset observations. Confirmed deposits have
a separate `CONFIRMED_DEPOSIT` journal type, so old snapshots and external-flow
records do not silently acquire new accounting meaning. Encrypted snapshots
include both new balances in the deterministic private state root.

Confirmed withdrawals remain a separate delivery gate. This change does not
claim that their custody posting is complete.

## Verification

`tests/balanced_deposit_postings.rs` verifies:

1. equal debit and credit amounts for pool cash and user liability;
2. exact atomic balances for USDC and ZEN;
3. duplicate evidence keys cannot mutate either leg twice; and
4. invalid direction, account class, or evidence fails before mutation.
