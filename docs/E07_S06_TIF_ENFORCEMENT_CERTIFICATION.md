# E07-S06 — API time-in-force enforcement certification

## Scope

This story certifies the API and native private-CLOB GTC, GTD, FAK and FOK behavior across
partial execution, expiry, cancellation, market close, recurring-window
rollover and resolution. It does not deploy an EIF, move funds, merge a branch
or change live production.

## Audit finding and correction

The pre-story engine excluded expired GTD orders from matching and public
depth, but left them `OPEN`, retained their grouped cash/claim hold, and counted
them against the owner position limit. A valid replacement could therefore
fail after the GTD deadline until the user explicitly cancelled the expired
order or the market resolved.

The correction is deliberately narrow. Enclave time cannot mutate state by
itself, so the next valid journalled write to a native market deterministically
cancels all elapsed orders and releases their grouped holds before position
limit validation and matching. The expiry sweep and the new command commit in
one atomic state transition. Explicit cancellation remains available, and
resolution still cancels every remaining live order. Expiry is recorded as the
distinct terminal state `EXPIRED`, not conflated with a user cancellation.

The story also retires every legacy plaintext order route with a state-free
`410 PRIVATE_ENCLAVE_REQUIRED` tombstone. Live commands use the encrypted
enclave relay exclusively.

## Lost-response recovery boundary

Each committed SubmitOrder retains a compact, size-bounded encrypted recovery
capsule until the API durably archives the original padded opaque response.
The archive is bound to subject, idempotency key, encrypted request hash,
recovery-context hash, private result commitment and deployment environment.
Only then may the governed operator send an exact archive ACK; the ACK is
journaled/rooted and removes only the matching capsule. A full bridge rejects
new orders before collateral mutation. There is no TTL-only eviction and no
plaintext order/result projection.

## Acceptance matrix

| Invariant | Executable evidence |
|---|---|
| GTC | Remainders rest until explicit cancellation, close or resolution |
| GTD | Missing/past expiry fails; elapsed resting orders become `EXPIRED` at the next valid write boundary and release their holds |
| FAK | Available liquidity fills deterministically and the unfilled remainder is cancelled |
| FOK | Insufficient liquidity rejects without a partial fill; sufficient liquidity fills completely |
| Held collateral | GTD expiry, explicit cancellation and resolution return exactly the no-longer-required grouped hold |
| Close | New orders fail at the close boundary and public depth is empty |
| Rollover | New-window orders use a distinct market/hold domain; old-window orders cannot match or debit the new window |
| Resolution | All remaining GTC/GTD orders are cancelled before payout; post-resolution trade/cancel attempts fail closed |
| Replay | User-command retries recover the exact signed semantic order result and receipt without mutation; replay does not promise byte-identical journal/snapshot ciphertext because authenticated encryption uses fresh nonces |
| Conservation | Available plus held settlement asset remains equal to the evidence-bound inflow when no fill occurs |
| Lost response | Partial FAK and rejected FOK recover the exact opaque result after restart without a second mutation |
| Archive ACK | Premature, forged, cross-user, cross-environment or wrong-digest ACKs fail closed; crash/retry converges |
| Legacy routes | Plaintext create/read/cancel/commit/reveal routes return the same generic state-free 410 response |
| Browser UI | Limit orders expose GTC, GTD, FAK and FOK; protected market orders expose FAK and FOK; GTD requires a future expiry strictly before market close |

## Capacity and privacy disclosure

The response capsule is bounded to 256 pending results and 16 MiB total
serialized capsule state, with a per-result fill ceiling. The implementation
clones the private core before the command so response/snapshot construction
failure can roll back without leaving financial state live. This copy is a
deliberate safety cost: the production load gate must record p95/p99 latency and
peak enclave memory at the configured maximum state before promotion. A
failure to remain within the EIF memory budget blocks release; it is not
silently converted to an in-place mutation.

Encrypted snapshots are trusted-parent artifacts rather than public evidence.
Their ciphertext is not fixed-size padded, so snapshot byte length can reveal
coarse aggregate state growth to the parent/infrastructure operator. It never
exposes an order, identity, balance or result value and is not returned through
the public API. Public recovery archives retain only the already padded opaque
client response.

Response payloads remain recoverable for 24 hours. Immutable signed metadata
is retained for 90 additional days and rooted SQL ACK markers for 365 days;
database triggers prohibit payload or metadata deletion without an exact ACK.
The pre-existing processed-command commitment marker remains the minimal
permanent replay fence and its measured compaction/capacity work is explicitly
owned by E18.

## Required gates

```bash
cargo fmt --check
cargo test --locked --test order_type_expiry_lifecycle -- --nocapture
cargo test --all-targets --all-features
cargo clippy --all-targets --locked -- -D warnings \
  -A dead-code \
  -A clippy::too-many-arguments \
  -A clippy::type-complexity \
  -A clippy::large-enum-variant \
  -A clippy::needless-range-loop \
  -A clippy::empty-line-after-doc-comments \
  -A clippy::wrong-self-convention \
  -A clippy::enum-variant-names
```

The authoritative GitLab merge-request pipeline must pass both Rust stages.
Local success is necessary but not sufficient.

## Exclusions

WebSocket delivery, deployment,
funded production canaries and soak are separate checklist stories. Durable
two-phase acceptance before any response/capsule escapes the enclave remains
E07-S07; E07-S06 does not claim that stronger boundary.
