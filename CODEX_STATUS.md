# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue C: Stargate Horizen-to-Arbitrum leg after unified withdrawal payout. |
| What's done | Added canonical EIP-712 verification and nonce-stable request IDs; per-operation USDC reserve, settlement and finalized-expiry release actions; restart reconstruction from authenticated receipts; accepted-reserve-only public command commitments; Rust/Solidity golden vectors. Added the policy-free pool-wallet link and reserve boundary. The parent independently verifies chain 26514, canonical confirmation depth, the exact LayrsPool payout event, and—before an expiry release—a canonical post-expiry block where `consumedWithdrawalNonces(account,nonce)` is false. The enclave then consumes or releases only the matching account's hold. Full direct-execution suite passes: 117 library, 33 enclave and 122 parent tests, with 3 benchmark-only tests ignored. No Durable Commands or new signing authority were added. |
| What's next | Implement and verify the per-operation pinned Stargate V2 Horizen-to-Arbitrum delivery leg, then the destination Relay leg. |
| Blockers | No engine blocker. Route activation is gated on exact Relay plus Stargate route verification. |
| Production-affecting action pending approval | None. No production deploy or funds movement during implementation. |
| Last updated (IST) | 2026-09-30 21:14 IST |
