# E09-S07 — Resolution and payout postings

## Financial boundary

Resolution is an enclave-authoritative transaction. The enclave cancels every resting order,
releases its hold, burns every UP/DOWN claim, pays exclusively from that market's collateral,
posts the immutable market fee, journals the new private state root, and only then returns a
receipt. No user account, claim, order, or payout row is projected publicly.

The monetary legs for each settlement asset and custody domain are:

```text
DR market collateral       gross payout
  CR user available        gross payout - winning fee
  CR protocol fee revenue  winning fee
```

Claim burns are memorandum debits in the outcome-token subledger. They are not settlement-cash
legs and cannot be mixed with the cash balance proof.

## Outcome invariants

- `UP`: every UP claim is consumed and paid at one unit of collateral per contract; every DOWN
  claim is consumed at zero. The immutable `LAYRS_FEE_V2` policy may charge only the winner.
- `DOWN`: symmetric to UP.
- `PUSH`: both claims are consumed and paid at one half-unit per contract; winning fee is zero.
- `INVALID`: an exposed invalid event uses the governed, signed `PUSH_REFUND` public outcome and
  therefore the same symmetric zero-fee payout. `INVALIDATED` lifecycle state is reserved for a
  market proven to have zero volume, zero open interest and no audit fill.
- Monetary debits equal monetary credits per settlement asset; insufficient collateral aborts
  the whole transaction without mutation.
- Each claim is consumed once. Any residual sub-atomic collateral is moved to the private rounding
  reserve by the enclosing resolution transaction.

## Replay and recovery

The payout replay key is derived from canonical signed resolution evidence and is independent of
the operator idempotency key. A committed response may be recovered from the encrypted journal;
redispatching the same evidence under a different operator key returns `DuplicateCommand` and
cannot debit collateral again. The evidence replay set is included in encrypted snapshots.

## Certification

`tests/resolution_payout_postings.rs` covers:

- UP and DOWN winner/loser settlement and exact fee posting.
- PUSH and ledger-level INVALID symmetric refunds.
- explicit monetary debit/credit equality.
- same-evidence/different-key replay after serialization and restore.
- zero evidence, malformed outcome, illegal void fee and insufficient collateral atomic failure.
- 10,000 generated precision-boundary settlements.

The existing full private-core resolution suites additionally cover partial positions, cancellation
at close, fee profiles, rounding reserve, immutable resolution conflict, journal/snapshot restore,
public evidence verification and supported resolution sources.
