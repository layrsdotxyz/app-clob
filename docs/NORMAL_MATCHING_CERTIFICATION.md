# NORMAL matching certification

This evidence covers the existing `NORMAL` path only: a resting order and an
incoming order for the same market and same outcome, with opposite actions.
It does not change or certify `MINT` or `MERGE` behavior.

## Certified rules

1. A BUY crosses only same-outcome SELL liquidity at or below its limit.
2. A SELL crosses only same-outcome BUY liquidity at or above its limit.
3. The incoming order receives the best executable resting price first.
4. Equal-price resting orders execute by enclave-assigned sequence, then UUID.
5. An order owned by the same private user is removed before candidate sorting.
6. The resting order is maker, the incoming order is taker, and execution uses
   the resting maker price.
7. Partial fills update cumulative filled and remaining quantities exactly;
   FAK remainders cancel and GTC remainders continue resting.
8. FOK insufficiency rejects before mutating resting liquidity.
9. Fill IDs derive only from market ID, maker ID, taker ID and deterministic
   fill sequence; identical command input therefore yields identical fills.
10. The existing single-ledger NORMAL transition remains atomic. Maker cash,
    taker cash, fee revenue and market collateral conserve the settlement
    asset; claims transfer without minting or burning supply.
11. An encrypted snapshot restores to the identical state root and balances.

## Executable evidence

`tests/normal_matching_certification.rs` contains:

- a fixed best-price/FIFO vector with a better-priced self order and ineligible
  outcome/action orders;
- atomic FOK rejection and a partial GTC remainder vector;
- property coverage for BUY and SELL takers across valid prices and quantities;
- a full private-core NORMAL fill with deterministic IDs, legacy taker-fee
  accounting, exact claim transfer, settlement-asset conservation and encrypted
  snapshot restore;
- complete replay of the fixed core scenario with byte-identical result,
  audit statement and state root.

The property vector is exercised for both BUY and SELL takers over generated
valid prices and quantities. It asserts maker-price execution, exact filled and
remaining quantities, NORMAL classification and replay-identical output on
every generated case.

The financial vector begins with `6 ZEN` of external inflow. After a two-share
UP claim trades at `0.35`, the accounts contain exactly:

| Account | Amount |
|---|---:|
| Maker available | `1.7000 ZEN` |
| Taker available | `2.2986 ZEN` |
| Fee revenue | `0.0014 ZEN` |
| Market collateral | `2.0000 ZEN` |
| Total | `6.0000 ZEN` |

The legacy fee profile is intentionally used in this compatibility vector: it
proves that NORMAL replay retains the immutable economics selected by an
already-registered market. Fee-profile-specific economics have separate
coverage and do not alter matching priority.

## Release boundary

Source and CI evidence is not an enclave release. Shipping any source change to
the financial core still requires the standard EIF build, measurement,
signed-manifest approval, pinned-PCR rotation, attestation verification and a
funded production canary. This certification adds tests and documentation only;
it does not build or deploy an EIF.
