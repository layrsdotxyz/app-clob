# Layrs private CLOB architecture

This repository preserves the Predifi-derived service as migration reference, but the production
ZEN market path is the `private_core` plus the `layrs-enclave` binary. Legacy Redis/HTTP matching,
Hedera, HCS and ZK-prover modules are not authoritative for Layrs v2 and must not be present in the
release EIF.

## Authoritative boundary

Inside the attested Nitro enclave:

- opaque private-user identities and signed sessions;
- available, held, collateral, fee and position balances;
- deterministic price-time matching and self-trade prevention;
- complete-set mint/burn and one-to-one market collateral;
- 0 bps maker and 20 bps taker accounting;
- per-position cost basis and 5% positive winning-profit fee;
- signed Pyth feed `245` resolution using exactly 25 samples in `(T-5s,T]`;
- encrypted hash-chained journal, deterministic receipts and encrypted snapshots.

Outside the enclave:

- CDP authentication and compliance eligibility;
- chain/Rhinestone/Polymarket/Pyth connectivity;
- VSOCK ciphertext transport;
- encrypted journal/snapshot storage;
- aggregate depth and public receipt publication.

The parent process cannot submit an administrative operation without the Ed25519 operator key
compiled into the EIF. Users cannot execute without a registered enclave session, signature,
unexpired request and strictly increasing sequence.

## Resolution rule

For the opening and closing boundary, the oracle adapter must collect exactly 25 authenticated
Pyth Pro samples at 200 ms spacing across the five seconds ending at the boundary. Every sample
must report at least three publishers and retain its signed EVM payload. The adapter commits those
payloads, computes the 13th sorted E8 price, signs the statement, and sends it to the enclave.

- closing median greater than opening median: UP;
- closing median less than opening median: DOWN;
- exact equality: PUSH.

There is no recovery deadline and no alternate source. A missing valid Pyth window pauses
resolution indefinitely. Binance is intentionally not a launch fallback.

## Recovery and rollback defense

The enclave exports only AEAD-encrypted snapshots. A snapshot includes the journal sequence/head
and state root. Restore rejects corruption and any snapshot older than an independently anchored
minimum sequence. Production must continuously archive receipts/journal records to Object Lock
storage and anchor checkpoint sequence plus state root to the public audit rail before advancing
the accepted recovery floor.

The test suite covers atomic ledger failure, price-time order, self-trade prevention, FOK behavior,
journal tamper detection, collateralized trading, resolution fees, snapshot restore and rollback
rejection.
