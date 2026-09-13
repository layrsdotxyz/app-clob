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

## Bounded production transport and verification

`scripts/submit-direct-market-registrations.mjs` is the fail-closed runner for
the separately reviewed execution. Its default mode is local validation only:

```bash
node scripts/submit-direct-market-registrations.mjs --validate
```

The read-only production preflight and mutating execution additionally require
the exact reviewed candidate AMI and WriterGrant commitment. They deliberately
have no defaults:

```bash
LAYRS_EXPECTED_AMI_ID=<reviewed-ami> \
LAYRS_EXPECTED_WRITER_GRANT_COMMITMENT=<reviewed-commitment> \
  node scripts/submit-direct-market-registrations.mjs --preflight

LAYRS_EXPECTED_AMI_ID=<reviewed-ami> \
LAYRS_EXPECTED_WRITER_GRANT_COMMITMENT=<reviewed-commitment> \
  node scripts/submit-direct-market-registrations.mjs --execute
```

The runner resolves the single healthy instance from the CloudFormation-owned
Auto Scaling group. It then uses AWS Systems Manager to call only the parent's
loopback endpoint. It does not expose the operator endpoint through the NLB,
Cloudflare, or the customer BFF. No secret, session, JWT, wallet credential, or
EnvironmentFile is read or logged.

Before any submission the runner verifies:

- the immutable evidence SHA-256 and all five existing-signature flags;
- at least 15 minutes remain on both the registrations and WriterGrant;
- exactly one healthy, SSM-online runtime instance uses the reviewed AMI;
- runtime, opening epoch hash, evidence-manifest hash, enabled mode, and exact
  WriterGrant commitment;
- the immutable archive and head prefixes are one-to-one and gap-free;
- the starting archive sequence is `5` plus only an already-registered serial
  prefix of these exact five markets; and
- enclave market readback is absent or byte-for-byte equal to the signed
  configuration.

It submits in the fixed order BTC, ETH, HYPE, SOL, ZEC. After each synchronous
HTTP 200 it requires a terminal `MARKET_REGISTERED` receipt, exactly one new
artifact/head pair, the next sequence, and exact enclave readback. It first
replays any already-present prefix so a response loss after private-state
commit can repair the idempotent PostgreSQL projection. It finally replays all
five exact requests and requires that neither the archive keys nor sequence
change. The required lineage transition is therefore exactly `5 -> 10`.

An HTTP 200 from this route is emitted only after the parent has executed
`record_result`, but the following independent read-only projection query is
also required before declaring trading unblocked:

```sql
SELECT r.request_id,
       r.terminal_status,
       r.effect,
       count(a.receipt_id) AS accounting_rows
  FROM layrs_direct_v1.direct_execution_receipts r
  LEFT JOIN layrs_direct_v1.direct_execution_accounting_events a
    ON a.receipt_id = r.receipt_id
 WHERE r.epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
   AND r.request_id IN (
     'direct-market:1f9b3a006f4397cf2fa5bc2f829b7132fc837011ae97721e1be92e3d85ffeaeb',
     'direct-market:a9064871759503838b9b9b6c8cecbc733fa1ba17f34dbe69a3ff84cba95175e7',
     'direct-market:2e217e3c185a62bf4930b83a5160d590637726fe9764768534cc5fe3f1c13990',
     'direct-market:9ea85e8f788fc29bc920aaf97e31cf94d99dbfef4679b8829a6a22df6570735e',
     'direct-market:ad4adb70ef8c7f4449696f7645f372d21775453954b7808391e524308452ca82'
   )
 GROUP BY r.request_id, r.terminal_status, r.effect
 ORDER BY r.request_id;
```

Acceptance is exactly five rows, each `APPLIED`, each `MARKET_REGISTERED`, and
each with `accounting_rows=1`. The same receipt IDs must have zero rows in
`direct_execution_order_events`, `direct_execution_trade_events`, and
`direct_execution_custody_events`. PostgreSQL remains projection-only; enclave
readback and the immutable artifact lineage are the authoritative checks.
