# Layrs settlement proof

This additive workspace proves the deterministic part of a native ZEN market
resolution without changing the live CLOB or audited settlement contracts.

Iteration 0 proves that:

- each opening and closing boundary contains exactly 25 positive normalized
  observations;
- the published median is the 13th value after ascending sort;
- the outcome is `UP`, `DOWN`, or `PUSH` according to the two medians; and
- the result is bound to the market, Horizen chain ID, Pyth feed, public
  evidence commitments, proof program version, and settlement commitment.

It does **not** claim to verify Pyth publisher signatures inside the zkVM.
Those remain part of Layrs' immutable public boundary evidence. Payout and fee
roots have explicit coverage flags and remain disabled until their confidential
witness can be produced inside the TEE boundary.

The proof is generated asynchronously and does not delay order matching or
market settlement.

The normative claim, trusted assumptions, public ABI and explicit exclusions
are frozen in [`SPECIFICATION.md`](./SPECIFICATION.md).

The host writes zkVerify-compatible artifacts:

- `proof.cbor`: the CBOR-encoded zkVerify wrapper containing the RISC Zero
  `InnerReceipt`;
- `public-inputs.bin`: the receipt journal bytes;
- `output.json`: the decoded public settlement statement; and
- `artifact.json`: image ID, proof hash, journal hash and artifact metadata.

The public journal is exactly fifteen 32-byte big-endian words. It includes
the program-version hash, market-ID hash, Horizen chain ID, Pyth feed ID,
opening and closing medians, outcome, evidence commitments, optional root
coverage, and the final settlement commitment. This fixed ABI lets the
Horizen registry reject metadata that is not actually bound into the proof.
