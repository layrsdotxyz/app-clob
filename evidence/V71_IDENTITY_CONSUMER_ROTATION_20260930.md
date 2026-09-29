# v71 identity-consumer inventory and rotation packet

Current consumers:

1. `layrs-production-direct-bff-readonly`, task definition 188, one of one
   healthy, rolling 100/200. It pins Phase-1 hash `4d51cc44...a53a` and the
   signed bridge release-manifest secret. Direct withdrawals remain disabled;
   the normal USDC lane remains enabled.
2. `layrs-production-public-proof-publisher`, task definition 32, one of one
   healthy, rolling 100/200. It pins the same Phase-1 hash and immutable
   publication-release secret, including manifest hash `eda9d644...7c4`.
3. `layrs-production-direct-market-resolver`, publisher task definition 33,
   one of one healthy. It pins bridge PCR0 `59beb724...29572`.

Prepared rotation:

- After the candidate attests, read its exact key-release artifact hash.
- Create a new immutable Phase-1 configuration from the current configuration,
  changing only candidate PCR0/PCR1/PCR2, release-manifest hash, writer-grant
  commitment and key-release artifact hash. Preserve schema digest and the
  50,000-atomic subsidy cap.
- Create a new immutable publication-successor secret from the current
  publication secret. Change its configuration and manifest binding only;
  preserve the private publication key without printing it. Update the
  successor pointer to the new immutable secret. Keep all predecessor secrets
  untouched for rollback.
- Register a new BFF task definition with backend image
  `sha256:55510ccc6cf84bf1bc3b9e650339c22bfedbab14085c733164becc128bc14638`,
  the new Phase-1 secret/hash and the signed v71 manifest secret. Preserve every
  unrelated environment value, secret and 100/200 deployment setting.
- Register a new proof-publisher task definition using the same backend image
  and the new publication-successor secret/hashes. Preserve all unrelated
  values.
- Register a new resolver task definition whose PCR0 allowlist is candidate
  first and bridge second. Preserve its image and all other settings.
- Redeploy only these three services. Stop if any task-definition diff exceeds
  the listed values.

Required post-rotation gates: BFF never reaches zero tasks; normal-user browser
attestation says verified and trading enabled; private portfolio is readable;
resolver capability succeeds and markets remain open/resolving; proof frontier
advances and backlog drains; zero new receipt-binding/attestation errors;
deposits and normal-lane withdrawals remain healthy.
