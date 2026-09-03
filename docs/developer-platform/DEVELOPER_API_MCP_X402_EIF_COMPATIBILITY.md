# Developer API, MCP and x402 EIF compatibility

Exact live EIF source: `97614f37c05089708f93bf50ac8831adde98ab2f`.
Cumulative candidate feature base: `c820266a0163ef807423467b26964db6763a2742`.

This is a source compatibility matrix. It does not claim deployment or live
certification.

## Compatible with the current live EIF

- Developer API key issue, list, rotate and revoke in the API/database layer.
- API-key request authentication, timestamp/nonce replay rejection and usage
  logging, provided unsupported financial routes stay disabled.
- Developer console lifecycle and usage-log UI.
- MCP capability issue/list/revoke and public market reads.
- MCP tool discovery limited to capabilities that the live backend can serve.
- x402 intent/status records may be implemented in isolation, but payment
  acceptance must remain disabled to avoid paid intents that cannot complete.

The pure transport candidate `1ce2a8082e25b37231669a7c6d3c73a509012aa3`
is also based directly on 976 and does not change private-core state. It adds
access-capability transport binding, not delegated portfolio reads or the
cumulative financial command state machine.

## Requires a new EIF

- Encrypted MCP balances, positions and open-order reads require the delegated
  portfolio-read command and bounded recipient envelope.
- Signed Developer API order, replace, cancel, cancel-all and position-close
  execution requires exact user/request context and the cumulative command
  semantics.
- MCP trading approval consumption and signed trading execution require the
  same financial command and durable receipt pipeline.
- x402 paid-order execution requires payment-to-command binding, idempotent
  completion and the cumulative durable command pipeline.
- New deposit/withdrawal accounting and exact committed-command recovery require
  cumulative ledger, journal and recovery behavior.

Do not advertise these surfaces merely because the backend route exists. They
remain unavailable until the measured EIF, PCR policy, snapshot migration,
host schema/grants, live readback and funded end-to-end certification all pass.

## Safe upgrade gate

The cumulative candidate is not safe to promote using the delegated-read
migration declaration alone. The exact-live cumulative declaration is
`enclave/snapshot-migrations/2026-08-24-live-976-to-cumulative-developer-platform.md`.
Its offline real-snapshot restore, equality, historical custody opening,
durable-manifest and rollback requirements are mandatory.
