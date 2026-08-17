# Complete-set residual normalization

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 80a2cc429f0b8c71098ecd40fc7f34c7c379c79f
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true
FUNDED_CANARY_REQUIRED: true

Release owner: Layrs protocol owner, who explicitly requested deterministic
elimination of one-micro complete-set residual failures without weakening
conservation, replay, self-trade prevention or order semantics. This approval
covers the intentional state-transition change; it does not claim that a
serialized field was added.

## Deterministic policy

MINT and MERGE continue to execute the smaller of the maker and taker
remaining quantities. The engine never rounds that execution upward.

If the fill leaves a maker or incoming tail that cannot allocate at least one
settlement micro to each side of a later complete-set operation, the engine:

1. preserves the exact filled quantity;
2. marks the maker tail `CANCELLED`, or reports the incoming tail as the
   cancelled remainder;
3. removes the tail from the active price-time book; and
4. releases the corresponding grouped cash/claim hold using the authoritative
   next-book reservation calculation in the same atomic command.

The minimum payable quantity at maker price `p` is
`ceil(PRICE_SCALE / (PRICE_SCALE - p))`. Candidate selection, FOK executable
quantity and fill execution share that exact calculation. NORMAL transfers,
self-trade prevention, price bounds and the deterministic price/time/UUID tie
break are unchanged.

## Invariants and replay gate

The release test suite must demonstrate:

- exact 35/65 and adjacent 36/64 one-micro maker and taker tails;
- MINT and MERGE behavior;
- no quantity overfill and no synthetic share;
- zero stranded cash/claim hold after dust cancellation;
- settlement collateral plus user cash plus fees equals initial cash;
- identical fills, serialized books and state roots for identical inputs; and
- unchanged cross-outcome self-trade prevention, FOK/FAK and price bounds.

No serialized field is added or rewritten. Nevertheless, the transition for a
new post-upgrade command intentionally differs when it creates an unpayable
tail. Before promotion, restore the production snapshot and replay the retained
pre-upgrade journal to the identical sequence, journal head, state root,
balances, holds, positions and orders. Then run a fresh capped USDC and ZEN
35/65 canary through placement, fill, cancellation visibility, resolution and
withdrawal.

This is enclave code. Merge alone is not activation: build the EIF, record its
measurements, sign the release manifest, rotate the pinned PCR through the
governed release process, verify fresh attestation and complete the funded
canary before declaring the story live.

## Rollback plan

Before the candidate accepts a command, restore the prior parent AMI, EIF,
signed manifest and pinned PCR policy. After it accepts a command, freeze new
private mutations and retain the candidate snapshot/journal; roll back only
after balances, holds, positions, fees, rewards and custody reconcile and the
prior release proves it can restore the retained state. Never truncate or edit
the encrypted journal to force compatibility.
