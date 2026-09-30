# Retained-v70 rollback identity-consumer rotation

Date: 2026-09-30 IST

## Approved boundary

The production change was limited to the three approved consumers:

- `layrs-production-direct-bff-readonly`
- `layrs-production-public-proof-publisher`
- `layrs-production-usdc-quest-administration-Service-mpAfFDYO89Ja`

No engine, ledger, market-maker, v71, unified-flow, image, route, feature-flag,
desired-count, PCR allowlist, or financial-state change was made.

## Live identity readback

Fresh nonce-bound Nitro attestation on sole writer
`i-091fc1eb35b3542eb` passed its COSE ES384 signature, five-certificate chain,
nonce, binding commitment, and exact PCR tuple checks:

- PCR0: `59beb72420f56eb9b6a794b7d9ac4aced2c191ee964381cbc01d2d73e386645abe4eaa9af8757984ad52e79916029572`
- PCR1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- PCR2: `28a6c5946a520ea6f72ace25a5cf9b57a8949c84377858e1c81457edaadd188e2b11b2eaafcb8c3352bf9e4a9f012ced`
- writer-grant commitment: `1ca7974e3d78c37b6248e68c0c36c0100430b3a52f507dd655f3aefd40d72b5b`
- key-release artifact: `cfc099549f590066dbb3d8682d7abd383f0d6df02f6b91e6899916f6ac9c0149`
- attestation command: `6cad7b94-67e1-4be4-a046-defba288082c`
- runtime-status command: `54b775f2-2be0-47ac-b20c-849f654b0e91`

The enclave remained writer-enabled and admission-enabled with one writer.

## Immutable successors

The existing release signer public key remained
`2d8df77c21ebc8c88c3e061065ac21852d2e5cdb1955194432a17c69adebc1a9`.
The new manifest was signed by the existing corresponding signer only and was
independently signature-verified. Its release commit is
`b980988e0fb5b538299b4403fe5500a5a1a134a9`; its hash is
`67521ab0b0b75c9a83b90b1d0e7dbbc3132d47866d1c2eaea22c6c120c80897a`.

The successor Phase-1 configuration hash is
`8ef59fbd0afeb37787c845be609bc992ae187423e778d643dcf2b4b96b9b711a`.
Compared with each predecessor, only the release-identity object changed.
PCR0/PCR1/PCR2 and schema digest remained equal; the release-manifest hash,
writer-grant commitment, and key-release artifact were rotated. The
`maximumSubsidyAtomic` value remains `50000`.

Immutable successor names:

- runtime manifest: `layrs/production/runtime/rollback-b980988-67521ab0b0b75c9a`
- BFF Phase-1: `layrs/production/direct-usdc-quest/v1/bff-rollback-b980988-8ef59fbd0afeb377`
- publication successor: `layrs/production/direct-usdc-quest/v1/publication-release-8ef59fbd0afeb377-eda9d64415585db0`
- administration Phase-1: `layrs/production/direct-usdc-quest/v1/administration-rollback-b980988-8ef59fbd0afeb377`

All predecessor secrets remain untouched for undo. The publisher stack's
`PublicationSecretArn` is the active publication-successor pointer. Its
successor naming includes both configuration and publication-manifest hashes,
and the standard later-deploy path derives the next configuration from the
BFF's active Phase-1 secret.

## Exact CloudFormation deltas

Change sets:

- `rollback-identity-bff-20260930101443`
  - parameters: `RuntimeSecretArn`, `UsdcRuntimeSecretArn`,
    `UsdcConfigurationSha256`
  - resources: `ExecutionRole`, replacement `TaskDefinition`, `Service`
- `rollback-identity-proof-20260930101443`
  - parameters: `PublicationSecretArn`, `ConfigurationSha256`
  - resources: `PublicationExecutionRole`, replacement
    `PublicationTaskDefinition`, `PublicationService`
- `rollback-identity-admin-20260930101443`
  - parameters: `AdministrativeRuntimeSecretArn`, `ConfigurationSha256`
  - resources: `ExecutionRole`, replacement `TaskDefinition`, `Service`, and
    the dormant replacement `PolicyRotationTaskDefinition`

The dormant policy-rotation task was not run. Its definition changed only
because it shares the same configuration hash and immutable secret pointer.
All service deployment settings remained 100/200.

## Deployment result

- BFF execution began 10:16:38 IST and reached steady state at 10:19:57.
  It never fell below one running task. Final task definition: `:189`.
- Publisher and administration execution began 10:20:30 IST.
  Final publisher task definition: `:33`; final administration task
  definition: `:88`.
- All three stacks are `UPDATE_COMPLETE`; all three services are one desired,
  one running, zero pending, and rollout `COMPLETED`.
- During IAM-pointer ordering, replacement attempts for the already-unhealthy
  old publisher/admin definitions tried their old secrets after the execution
  roles had moved. Those attempts failed closed. The new definitions started
  with the new pointers. BFF availability was unaffected.
- Quest administration had already been in an old-identity readiness/ELB
  replacement loop before this rollout. It briefly had zero running tasks while
  ECS drained the unhealthy old tasks, then `:88` registered healthy. This did
  not affect the financial writer or BFF.

## Post-state verification

Passed:

- Public release manifest signature, hash, release commit and PCR0 verify.
- Public nonce-bound Nitro attestation verifies the same manifest PCR0 and the
  active grant/key-release binding; writer and admission flags are true.
- `https://api.layrs.xyz/healthz`, `/v1/privacy/release`, `/v1/attestation`,
  and `/v1/markets` return HTTP 200.
- Authenticated portfolio reads returned HTTP 200 after the rotation; trading
  API reads and existing market-maker operations continued.
- New publisher task has zero `QUEST_PUBLIC_RECEIPT_BINDING_INVALID` failures.
- The publisher submitted and confirmed 23 Horizen batches between its start
  and the final evidence read; confirmations continue advancing through the
  backlog.
- Quest administration target is healthy and verifies the rotated release.

Failed release bar, outside the approved identity-only scope:

- BFF logs show `QUEST_PREFLIGHT_RESERVE_SHORTFALL` for both deposit and
  withdrawal preflights after identity verification recovered.
- Read-only on-chain reserve checks identify the shared Horizen native floor:
  company balance `91636664139358` wei, required `102000000000000` wei,
  shortfall `10363335860642` wei.
- Arbitrum company native, Arbitrum company USDC, Horizen company USDC, and
  Horizen pool USDC all pass their configured floors.
- Because signup wallet setup calls the admission preflight, setup, new
  deposits, and new withdrawals cannot pass while this shared floor is short.
  No internal account mutation or financial test was attempted after the
  deterministic preflight failure.

No wallet was funded and no threshold/configuration was changed. Correcting
the native reserve requires a separate user-authorized funds movement, which
is outside this rotation's scope.
