# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue C: finalized Horizen settlement boundary for unified withdrawals. |
| What's done | Added canonical EIP-712 verification and nonce-stable request IDs; per-operation USDC reserve, settlement and finalized-expiry release actions; restart reconstruction from authenticated receipts; accepted-reserve-only public command commitments; Rust/Solidity golden vectors. Added the policy-free pool-wallet link and reserve boundary. The parent now accepts the worker's terminal action only after independently verifying chain 26514, canonical confirmation depth, the exact LayrsPool call, sender/route wallet, and exactly one matching public `Withdrawal` event. The enclave then consumes only the matching account's hold. Rust signed-withdrawal and custody tests pass. No Durable Commands or new signing authority were added. |
| What's next | Add finalized-expiry release verification, then prove journal/checkpoint compatibility for the active-hold and terminal paths. |
| Blockers | No engine blocker. Route activation is gated on exact Relay plus Stargate route verification. |
| Production-affecting action pending approval | None. No production deploy or funds movement during implementation. |
| Last updated (IST) | 2026-09-30 21:03 IST |
