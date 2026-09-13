# P0 direct-market registration preparation

Status: `SIGNED_NOT_SUBMITTED`

No production market was registered and no financial state was mutated while
preparing this evidence.

## Authoritative source

The source is the production `layrsv2.market_specs` row joined by
`release_manifest_hash` to the immutable
`layrsv2.market_release_manifests.payload`. The capture ran in a
`REPEATABLE READ READ ONLY` transaction at
`2026-09-13T19:19:26.578Z`. The selected rows all belong to production release
manifest SHA-256
`f156932795e74e5dc37089ace56bc088b8b2a006e66902d42a68fcf8bef7810a`.

The public market projection is not a sufficient registration source: it does
not carry all enclave limits, the direct execution discriminator, or the
oracle feed identifier.

Selection was intentionally bounded to the five visible, `OPEN`, future-closing
monthly crypto markets with `settlementAsset=USDC`,
`executionMode=NATIVE_ONLY`, and an existing Binance/Kraken median resolution:

- `layrs:v5:BTC:USDC:1mo:1788220800`
- `layrs:v5:ETH:USDC:1mo:1788220800`
- `layrs:v5:HYPE:USDC:1mo:1788220800`
- `layrs:v5:SOL:USDC:1mo:1788220800`
- `layrs:v5:ZEC:USDC:1mo:1788220800`

Short-lived daily/weekly markets near their close, expired markets, event
markets, externally executed markets, invisible/conflicting markets, and ZEN
collateral markets are excluded.

## Exact translation

The translation reuses the existing `enclaveMarketConfig` production contract:

- USDC has six settlement decimals.
- The production chain remains `horizen`.
- `privateCore` limits are copied without change.
- `LAYRS_CRYPTO_V2` remains the fee profile.
- `NATIVE_ONLY` plus the existing Binance/Kraken resolution maps to
  `NATIVE_CLOB`.
- Existing feed IDs are reused: BTC `9002`, ETH `9003`, SOL `9004`, ZEC
  `9005`, HYPE `9006`.

No limit, oracle ID, fee profile, market time, or market identifier was
invented.

## Signature contract and expiry

`GovernedMarketRegistration` is serialized in its Rust field order with a
blank signature. The exact bytes signed are compact JSON encoding of this
tuple:

```text
["layrs.direct-market-registration.v1\u0000", <unsigned registration>]
```

The signer is the existing
`alias/layrs/production/recovery-evidence-signing` ECC NIST P-256 KMS key using
`ECDSA_SHA_256`. Its live DER public key exactly matched the public key compiled
into the direct runtime; DER SHA-256 is
`a001a573309c778b0b1f90ecd93eaf1cb07a37f4bea501c32c43afd754871f22`.

Each signature is standard-base64 DER ECDSA. Each KMS signature was verified
by KMS and independently by Node's P-256 verifier. The accompanying Rust
verifier deserializes the actual HTTP bodies and calls the runtime's
`GovernedMarketRegistration::verify` function.

The registrations expire at `2026-09-15T00:00:00Z`, less than 30 hours after
the capture. This bounds authorization to the current cutover window. A
registration accepted before expiry becomes part of the encrypted direct
ledger; expiry does not close or modify the underlying market.

## Reproduction and review

Generate the deterministic signed evidence and HTTP request bodies:

```bash
node scripts/prepare-direct-market-registrations.mjs
```

Verify the exact signed bodies with the runtime verifier:

```bash
node scripts/prepare-direct-market-registrations.mjs \
  | cargo run --quiet \
      --manifest-path enclave/direct-execution-v1/Cargo.toml \
      --example verify_governed_market_registrations
```

The generated evidence SHA-256 is
`f619b5be495668c08b098c535f9cf00802f20cb02ff76388356f0ac69eb711e6`.
Submission, when separately reviewed, is `POST /v1/operator/markets` with one
generated `httpBody` at a time. Exact retries reuse the same deterministic
`registrationId` (`direct-market:<source-content-hash>`); conflicting reuse is
rejected by the direct runtime.
