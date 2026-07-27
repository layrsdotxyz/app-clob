# 2026-07-27 — Base-destination ZEN bridge-back withdrawal

SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
BASE_RELEASE_COMMIT: 1901e5eb6f6b67d1a01c5b4a26cc7fd627849ad5
PRODUCTION_REPLAY_PLAN: true
ROLLBACK_PLAN: true

## Change

The private core withdrawal allowlist now accepts the existing `base` + `ZEN`
intent pair. The same pair is accepted when deriving the deterministic
withdrawal-reservation marker. The existing `base` + `USDC` and `horizen` +
`ZEN` pairs are unchanged.

## Reason

Base ZEN deposits are swept and bridged into the Horizen ZEN LayrsPool. A user
who requests payout on Base must therefore reserve ZEN in the private ledger,
authorize the Horizen pool payout to the controlled bridge sweeper, and bind the
final Base recipient to that authorization. The coordinator and worker already
implement that fail-closed bridge-back path. The deployed enclave rejected the
intent before reservation because its allowlist predated the coordinator path.

## State compatibility

This release does not change the encrypted journal format, snapshot schema,
ledger account layout, withdrawal authorization structure, reservation-marker
encoding, chain-signer bundle, order book, fee math, settlement math, market
state, replay cache, or public audit payload.

Existing snapshots and journals replay without transformation. Existing
withdrawal markers remain byte-for-byte identical. The additional pair only
permits future `base` + `ZEN` requests to create the same marker and signed
authorization shape already used by the other supported pairs.

## Production replay plan

Restore the latest immutable production snapshot and replay every subsequent
encrypted journal record under the existing sequence/root checks. Before
promotion:

- verify the restored sequence and state root match the current leader;
- run the focused Base-ZEN withdrawal regression;
- prove a Base-ZEN request reserves exactly the requested amount once;
- prove the coordinator maps the pool leg to Horizen and the pool destination
  to the controlled bridge sweeper;
- complete one controlled Base delivery and reconcile pool, ledger, sweeper and
  recipient balances.

## Rollback plan

If restore, replay, attestation, reservation, pool payout, bridge delivery or
reconciliation fails, freeze new withdrawals, restore AMI/PCR/release
`1901e5eb6f6b67d1a01c5b4a26cc7fd627849ad5`, and release any unbroadcast
withdrawal hold through the existing enclave system command. No snapshot or
database transformation is required.

## Approval

The Layrs protocol owner approved completing the production Base-ZEN
bridge-back rail in this release. Deployment remains fail-closed until replay,
attestation, controlled-recipient E2E and reconciliation are green.
