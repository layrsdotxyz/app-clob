# v71 production rollout evidence — 2026-09-30

## Release identity

- Source commit: `80de99c219a356191efdb41e306ddd2c19a9813e`
- AMI: `ami-0f025eaf79f9f49c8`
- Parent SHA-256: `167e6ce4083920440661bb5401152b818ade1a5d2a285a669d83b043f05bfa5c`
- EIF SHA-256: `18981980a420f63fd9468809abc7e8a692be98349799c520d4751590ea809c29`
- PCR0: `980bb75292d53c11a98614bab7bbc87c8c1b8f61bd0e2a2a0a87b5ed16d0c68e026a0cd1246a0e2907c5c20f40aefe7d`
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2: `3d5d8db471f3eb8dd7b74972f6f1079b69277c254d58ab99b40448ef9663f78d3d8003750092057cc1565cbbe1fe3ac9`
- Forward writer grant: `layrs-v71-80de99c-20260930-bd3e8c26`, signed minimum authenticated checkpoint 45,017.
- Separate rollback grant: `layrs-v70-rollback-5dad5a0-20260930-0c4951e2`, never supplied to the candidate and therefore unconsumed.
- Both grants expire at 2026-10-01 17:30 IST.

## Promotion and continuity

- Authenticated checkpoint 45,017 verified at 17:28:46 IST.
- Successor restore 45,017 through exact pre-handoff v70 head 45,031 completed at 17:31:01 IST.
- Shadow replay matched four additional live v70 commits through 45,035.
- Non-writer checkpoint restore verified sequence 45,031 at 17:36:17 IST.
- Cutover marker became durable at 17:37:18 IST.
- `V71_HOT_PROMOTION_COMPLETE run_id=v71-80de99c-bcfa336e sequence=45035` was logged at 17:37:17 IST.
- The v70 full-state namespace ends at sequence 45,035, last modified 17:32:30 IST.
- At 18:07 IST, v71 records were contiguous from 45,032 through 45,305: 274 records present, 274 expected, 10,338,909 bytes total.
- A new authenticated v71 checkpoint was published at sequence 45,281 (38,398,864 bytes) at 18:01:52 IST.

## Single writer and runtime health

- The production ASG is desired 1, maximum 1, and contains exactly one healthy InService instance: `i-0cf5d486a62a2ce94`, launch-template version 79.
- The instance runs the expected AMI and is the only running EC2 instance in the direct-execution production ASG.
- The target group reports that instance healthy on port 8443.
- The parent has remained active with PID 27345 and zero restarts since 17:13:03 IST.
- The enclave is RUNNING with 8,192 MiB and the expected PCR0/PCR1/PCR2.
- At the 32-minute post-promotion check, parent RSS was 2,690,784 KiB (2.57 GiB).

## Rollback safety

- The distinct rollback grant remains unconsumed.
- Both rollback change sets remain `CREATE_COMPLETE` / `AVAILABLE`.
- Each rollback change set contains exactly the three approved resources: `DormantAutoScalingGroup`, `DormantLaunchTemplate`, and `RuntimeRole`.
- The rollback materialization prefix is empty, as expected until an operator deliberately triggers exact-head rollback materialization. No rollback signal has been sent.

## Identity consumers

- All identity-consumer stacks are `UPDATE_COMPLETE`.
- BFF: task definition revision 191, 1 desired / 1 running, rollout completed.
- Public proof publisher: revision 34, 1 desired / 1 running, rollout completed.
- Direct-market resolver: publisher revision 34, 1 desired / 1 running, rollout completed.
- Quest administration: revision 89, 1 desired / 1 running, rollout completed.
- The public release manifest signature validates with the existing signer, binds source commit `80de99c`, binds the production PCR0, and expires 2026-10-07.
- A fresh public Nitro attestation validated its signature, nonce, freshness and PCR0, and reported `writerEnabled=true`.

### BFF correction during rotation

The first new BFF task could not retrieve its runtime secret because the helper had assigned the restricted USDC customer-managed KMS key to a secret whose source used the AWS-managed Secrets Manager key. Revision 189 remained healthy throughout because the service is rolling 100/200. The failed stack update was cancelled, an immutable replacement runtime secret was created with the source encryption mode and semantic readback verification, and a corrected change set was inspected before execution. The only parameter changes were `RuntimeSecretArn`, `UsdcRuntimeSecretArn`, and `UsdcConfigurationSha256`; the only resources were `ExecutionRole`, `Service`, and `TaskDefinition`. No IAM or KMS scope was widened. Revision 191 then reached steady state without the KMS error.

## User-visible checks

- `GET /v1/markets` returned HTTP 200 with 53 open markets and 53 `tradingAvailable=true`.
- The current BFF task serves successful trading-account, order, position and portfolio requests.
- Successful order creates observed on the current BFF task: 10 samples, p50 399 ms, p99 465 ms, minimum 348 ms, maximum 559 ms.
- The current public-proof-publisher task recorded new Horizen confirmations and zero `QUEST_PUBLIC_RECEIPT_BINDING_INVALID` events after startup. Example latest observed confirmation at 18:04:29 IST: transaction `0x4377958790b745c39447db41b6d995d8cb1b05258457403333c14f65a6eaad17`.
- The current resolver recorded successful warm cycles and zero `DIRECT_MARKET_RESOLUTION_CAPABILITY_UNAVAILABLE` events in the final verification interval.

## Result

v71 is authoritative in production, the compact journal is advancing, the full-state-per-commit lineage has stopped, one writer is active, the zero-loss rollback safety net remains available and unconsumed, and trading/proof/market consumers are operating on the v71 identity.
