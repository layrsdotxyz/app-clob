# Layrs settlement proof specification

Version: `layrs.zk.settlement.v1`

Status: Iteration 0, deployed evidence

## Normative claim

Given a bounded private witness containing the committed opening and closing
price observations for one canonical Layrs ZEN market, the
`layrs.zk.settlement.v1` program validates that witness, computes each
25-observation median as the thirteenth value after ascending integer sort,
derives `UP`, `DOWN`, or `PUSH`, and commits the result to the market, Horizen
chain, Pyth feed, evidence commitments, observation commitments and proof
program version.

The RISC Zero receipt proves execution of that statement. zkVerify verifies
and aggregates the receipt. `LayrsZkSettlementRegistry` verifies the zkVerify
aggregation on Horizen and records the public settlement statement.

## Trusted assumptions

- Boundary observations and their evidence commitments are produced by the
  approved Layrs Pyth Pro collection path.
- Pyth publisher authenticity, freshness and publisher-count enforcement
  before witness construction remain outside Iteration 0's zkVM.
- RISC Zero 2.2.0, zkVerify domain `3`, the zkVerify aggregation proxy, and the
  Horizen execution environment behave according to their published
  specifications.
- SHA-256 and Keccak-256 retain their standard collision-resistance
  properties.

## Explicit exclusions

Iteration 0 does not prove:

- Pyth publisher signatures;
- CLOB price-time-priority matching;
- deposits, withdrawals or bridge execution;
- payout or winning-fee correctness;
- the integrity of the TEE itself.

The journal contains explicit payout and fee coverage bits. Both must be zero
for this version. The guest rejects non-zero payout or fee roots and rejects
coverage claims. This makes the exclusion machine-enforced rather than copy
alone.

## Canonical units and arithmetic

- Prices are signed 64-bit integers in `E8` units.
- All accepted observations and both medians must be positive.
- The market, chain and feed identifiers are exact, versioned inputs.
- Exactly 25 observations are encoded per boundary at the Rust type level.
- Sorting uses Rust's deterministic ascending integer order.
- Median index is `25 / 2 = 12`, the thirteenth sorted observation.
- `closing > opening` is `UP`; `closing < opening` is `DOWN`; equality is
  `PUSH`.
- No floating-point arithmetic, division, rounding or tolerance is used.

## Boundary policy

- Each boundary covers exactly five seconds.
- Opening must precede closing.
- The committed publisher policy must require at least three publishers.
- Missing observations cannot be encoded because the witness requires exactly
  25 integer values.
- Duplicates are allowed and participate normally in the median.
- Observation order does not change the median but does change the committed
  observation sequence. Reordering therefore creates a different witness
  commitment.

## Private witness

Each boundary contains:

- five-second start and end timestamps in microseconds;
- minimum publisher count;
- immutable public evidence commitment;
- exactly 25 normalized `E8` observations;
- observation-sequence commitment;
- expected median.

The public market, chain, feed and proof version are supplied alongside the
private boundaries. Individual observations are not written to the journal.

## Public journal ABI

The journal is exactly 480 bytes: fifteen 32-byte big-endian words.

| Word | Value |
| ---: | --- |
| 0 | SHA-256 proof-program version |
| 1 | SHA-256 canonical market ID |
| 2 | Horizen chain ID (`26514`) |
| 3 | Pyth ZEN/USD feed identifier (`245`) |
| 4 | opening median, signed `E8` |
| 5 | closing median, signed `E8` |
| 6 | outcome: `1=UP`, `2=DOWN`, `3=PUSH` |
| 7 | opening evidence commitment |
| 8 | closing evidence commitment |
| 9 | opening observation-sequence commitment |
| 10 | closing observation-sequence commitment |
| 11 | payout root; zero in Iteration 0 |
| 12 | fee root; zero in Iteration 0 |
| 13 | payout and fee coverage bits; both zero in Iteration 0 |
| 14 | settlement commitment |

The settlement commitment is SHA-256 over a domain separator and the
length-delimited/versioned public bindings. The Horizen registry rejects any
journal with the wrong length, program version, chain, feed, prices, outcome,
coverage word or zero settlement commitment.

## Idempotency and replay resistance

- The settlement commitment binds the canonical market ID and all accepted
  public evidence commitments.
- The Horizen registry keys attestations by market-ID hash.
- A market with an existing attestation cannot be attested again.
- A proof for one market cannot attest another market because the market-ID
  hash is inside the verified journal and zkVerify leaf.

## Deployed Iteration 0 evidence

- Market: `layrs:v3:ZEN:15m:1785196800`
- Opening median: `391009849`
- Closing median: `387166933`
- Outcome: `DOWN`
- RISC Zero image ID:
  `0xd8fbc25af5314af46550bbc6c2ca5ea32378ba467496617a61b2490cf442914a`
- Proof SHA-256:
  `0x1152aad0504e4dcc0e909552bea36982dc772b9d0d6adb293d0916a10398799c`
- zkVerify transaction:
  `0xeadf51d99524d63c9d82fea27cda0cef009a7891853a5f6f883ad96361f6df82`
- zkVerify aggregation ID: `4217`
- Horizen registry:
  `0xd2A9fC93c3d9Bc284C273A6a41c84A104a5Fb7E1`
- Horizen attestation transaction:
  `0x86af286da173625279f5675dda235b692fae974039a098f6979654e791507ed3`
