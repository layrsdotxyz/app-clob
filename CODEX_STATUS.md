# CODEX status

| Field | Status |
| --- | --- |
| Current step | Queue C: v71 engine support for unified user-signed withdrawals. |
| What's done | Added canonical EIP-712 verification and nonce-stable request IDs; per-operation USDC reserve, settlement and finalized-expiry release actions; restart reconstruction from authenticated receipts; accepted-reserve-only public command commitments; Rust/Solidity golden vectors. Full library result: 115 passed, 0 failed, 3 explicit benchmarks ignored. No Durable Commands were added. |
| What's next | Wire the parent/BFF request and finalized-chain verification boundaries, generalize the proof publisher naming away from Quest, and prove v71 journal/checkpoint compatibility for the new active-hold path. |
| Blockers | Relay cannot currently bridge to or from Horizen 26514; this blocks end-to-end movement but not local engine semantics and tests. |
| Production-affecting action pending approval | None. No production deploy or funds movement during implementation. |
| Last updated (IST) | 2026-09-30 19:47 IST |
