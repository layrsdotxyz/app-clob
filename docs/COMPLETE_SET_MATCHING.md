# Complete-set matching

The private native CLOB supports three deterministic match types:

- `NORMAL`: same outcome, opposite actions. The resting claim transfers from
  seller to buyer using the pre-existing settlement path.
- `MINT`: opposite outcomes, both `BUY`. The two buyers jointly fund exactly
  one unit of collateral and receive one outcome claim each.
- `MERGE`: opposite outcomes, both `SELL`. One claim of each outcome is burned
  and the released collateral pays the two sellers.

## Crossing and execution prices

`PRICE_SCALE` is `1_000_000`.

- A `MINT` crosses when `incoming_price + resting_price >= PRICE_SCALE`.
- A `MERGE` crosses when `incoming_price + resting_price <= PRICE_SCALE`.
- The resting order executes at its resting limit.
- The incoming order executes at `PRICE_SCALE - resting_price`.

The complementary execution prices therefore always total exactly one
collateral unit. Any crossing surplus becomes price improvement for the
incoming taker; it is never converted into extra collateral.

## Priority and roles

All eligible candidates enter one queue:

1. best effective execution price for the incoming order;
2. `NORMAL` before a complete-set operation at the same effective price;
3. resting order sequence;
4. resting order UUID.

The existing resting order is always maker and the incoming order is always
taker. Maker fee remains `0 bps`; the `20 bps` taker fee is calculated from the
incoming order's effective execution notional. Cross-outcome self-trading is
rejected before a candidate enters the queue.

This ordering avoids unnecessary collateral operations when equivalent direct
liquidity exists and is independent of hash-map iteration order.

## Ledger transitions

`Ledger::apply_complete_set` remains the only claim issuance/burn primitive.
The matching layer does not mint or burn balances itself.

For `MINT`, the engine:

1. moves the maker and taker contributions out of their existing order holds;
2. invokes `apply_complete_set(Mint)` for the exact fill quantity;
3. transfers the taker's outcome claim to the taker;
4. retains the maker's outcome claim with the maker;
5. moves only the taker fee to fee revenue.

For `MERGE`, the engine:

1. moves both held claims into the temporary complete-set owner;
2. invokes `apply_complete_set(Burn)` for the exact fill quantity;
3. pays each seller its complementary leg, net of only the taker fee.

Every sub-transition mutates only the cloned command state. The new ledger,
book, cost basis and encrypted journal record become authoritative together
only after the complete user command succeeds. Any failure discards all cloned
state.

## Compatibility

`Fill.match_type` defaults to `NORMAL` when reading pre-feature records.
NORMAL-only commands retain the original single ledger transition and sequence
behavior, preserving historical journal replay. A complete-set fill records:

- `outcome`: incoming/taker outcome;
- `maker_outcome()`: same outcome for `NORMAL`, opposite for `MINT`/`MERGE`;
- `price_micros`: resting maker price;
- `taker_price_micros()`: effective incoming price;
- `match_type`: `NORMAL`, `MINT` or `MERGE`.

This is an enclave release change. It must be shipped only through the normal
EIF build, measurement, signed release-manifest and pinned-PCR rotation flow.
