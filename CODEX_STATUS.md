# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue C: v71 engine support for unified user-signed withdrawals. |
| What's done | Added canonical EIP-712 verification and nonce-stable request IDs; per-operation USDC reserve, settlement and finalized-expiry release actions; restart reconstruction from authenticated receipts; accepted-reserve-only public command commitments; Rust/Solidity golden vectors. Added a simple policy-free pool-wallet link action: the existing authenticated direct session must bind the exact database-assigned address, and the engine rejects cross-user wallet reuse. Focused pool-link tests pass 2/2 and the parent compiles. No Durable Commands or new signing authority were added. |
| What's next | Wire the backend assignment observer to the session-bound pool link, then add finalized Horizen payout verification and prove journal/checkpoint compatibility for the new active-hold path. |
| Blockers | No engine blocker. Route activation is gated on exact Relay plus Stargate route verification. |
| Production-affecting action pending approval | None. No production deploy or funds movement during implementation. |
| Last updated (IST) | 2026-09-30 20:01 IST |
