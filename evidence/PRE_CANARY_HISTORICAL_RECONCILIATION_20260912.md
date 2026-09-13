# Pre-canary historical reconciliation — 2026-09-12

The frozen post-P0-3 customer state, sealed opening epoch, restarted dormant
runtime, isolated PostgreSQL projection, and two real public authenticated
balance reads reconcile without an unexplained financial or identity variance.

## Account preservation

- 438 identities were compared account by account.
- 437 retained identical financial buckets.
- One identity retained the same total liability while applying the governed
  4,840,000 atomic USDC withdrawal-hold-to-available reclassification.
- There are zero missing, unexpected, or unexplained account mismatches.
- The opening state and the live `layrs_direct_v1` projection match exactly:
  438 identities, 322 balance rows, and 414 valid embedded EVM mappings.
- The equality check passed both before and after restarting the final dormant
  parent and enclave.

Canonical current-projection digests are:

- identities: `db3a27a44eb5a297df6b63e1938dfd8d5dd757609dac47a0866f1661978a14d6`
- balances: `77f1f0f79bae5c6a1c686e16d869a0c0a28e0e51a9013bc0aa0cef300c6b710e`
- wallet mappings: `0f6a5068f689f99f54a4afe24982ca975e1b4b5fbc968f7b38016f16c6e63e16`

## Aggregate preservation

The direct opening/runtime state contains 238,747,549 atomic USDC and
3,000,000,000,000,000,000 atomic ZEN. The separately classified off-TEE
customer obligations remain 40,761 atomic USDC. P0-1 remains 5,000,000 atomic
USDC, P0-2 remains 5,100,000 atomic USDC, and P0-3 remains closed with zero
outstanding liability. No economically open position, order, or nonterminal
withdrawal was imported.

The historic Base custody equation remains:

`263,212,620 controlled = 238,788,310 classified obligations + 24,424,310 unclassified custody`.

## Public read proof

Real Gmail/Privy-authenticated requests through `api.layrs.xyz` returned:

- `layrs-mm-01@predifi.com`: 160.453499 USDC;
- `layrs-mm-02@predifi.com`: 9.404611 USDC.

Both identity bindings and amounts exactly match the independently frozen
customer-attribution census. No OTP, access token, session secret, wallet
secret, or sensitive identity value is retained in this evidence.

## Runtime proof

The final writer-disabled candidate is source commit `40ca230`, AMI
`ami-0a0c4d0e2608aa701`, and EIF SHA-256
`28c4f8ad242ebb5b0525961cc5994b6b6426c98dd48a39ae133e7cac476912c2`.
Fresh post-restart Nitro evidence verified the AWS certificate chain, ES384
signature, nonce, binding, opening-state hash, evidence-manifest hash, and the
exact PCR tuple. The attestation document SHA-256 is
`305675978e5d15f12fbe01e054f67c6423eb568876da6977068a438a259aa70d`.

PostgreSQL remains a projection and was not used to reconstruct authoritative
private state. Writer authority and identity admission remain disabled. No
funded canary, custody call, balance mutation, new customer, Green operation,
or interaction with sequence 75594 occurred.

Machine-readable evidence SHA-256:
`0734c53b34f2d39187cdfa37af365c03057bbf1a9591c11a88c5ea1ade480c99`.
