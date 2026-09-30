# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue C: v71 engine support for unified user-signed withdrawals. |
| What's done | Added canonical EIP-712 verification and nonce-stable request IDs; per-operation USDC reserve, settlement and finalized-expiry release actions; restart reconstruction from authenticated receipts; accepted-reserve-only public command commitments; Rust/Solidity golden vectors. Added a policy-free pool-wallet link action and wired the public parent boundary for reserve only: it requires the nonce-derived idempotency key, assigned route-wallet session binding, an unexpired intent and a valid user signature. Settlement and release remain impossible through the public action enum. Live read-only calls prove both LayrsPool.asset() and Stargate.token() are 0xdf7108...; corrected the shared EIP-712 vector to chain truth. Signed-withdrawal tests pass 6/6 across library and parent. No Durable Commands or new signing authority were added. |
| What's next | Add the dedicated BFF withdrawal API/store, then wire finalized Horizen payout verification and prove journal/checkpoint compatibility for the new active-hold path. |
| Blockers | No engine blocker. Route activation is gated on exact Relay plus Stargate route verification. |
| Production-affecting action pending approval | None. No production deploy or funds movement during implementation. |
| Last updated (IST) | 2026-09-30 20:22 IST |
