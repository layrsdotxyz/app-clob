# Step 7 final pre-canary evidence — 2026-09-12

`STEP_7_STATUS = COMPLETE`

`PRODUCTION_ACTIVATION_STATUS = READY_FOR_FUNDED_CANARY`

The final candidate is source commit `40ca230`, AMI
`ami-0a0c4d0e2608aa701`, and EIF SHA-256
`28c4f8ad242ebb5b0525961cc5994b6b6426c98dd48a39ae133e7cac476912c2`.
The AMI is available, the dormant runtime and read-only BFF stacks are
`UPDATE_COMPLETE`, both target groups are healthy, and the exact post-restart
Nitro attestation has been independently verified.

The governed WriterGrant is signed and cryptographically verified against this
exact candidate, opening epoch, runtime identity, and retained legacy-writer
fence. It has not been installed to enable writer authority.

## Read-only production proof

The `/adoption` page now uses the real direct projection API and contains no
mock/static fallback, retired Green dependency, or Durable Command dependency.
Its live aggregate response reports 438 identities, 413 auth subjects, 322
funded identities, 414 valid embedded EVM mappings, and 238,747,549 atomic
USDC projected liability.

Real public Gmail/Privy-authenticated balance requests returned and reconciled:

- MM-01: 160.453499 USDC;
- MM-02: 9.404611 USDC.

Both authenticated identity/wallet bindings and amounts exactly match the
frozen customer-attribution census and the isolated projection. PostgreSQL is
projection/audit only, never private-state recovery authority.

## Controls

- All six legacy financial services remain at desired/running `0/0`.
- The new runtime remains writer-disabled and admission-disabled.
- The unauthenticated balance route returns `401`; command, admission, deposit,
  and withdrawal routes remain unpublished (`404`).
- The production immutable archive has Object Lock enabled and contains no
  post-genesis successor artifact for this writer-disabled epoch.
- The source and both final release binaries contain no Durable Command,
  preparation lifecycle, financial queue, lease, or coordinator execution path.
- The existing read-only custody/finality configuration remains at 20 Base
  confirmations and produced no sign/submit attempt.
- SNS has the confirmed production recipient and controlled delivery evidence.
  Nineteen non-critical alarms retain Devendra Tanwar's bounded acceptance;
  the activation-critical runtime health alarm is bound to the final instance
  and is `OK` from real EC2 health datapoints.

Final tests: runtime 35 passed; BFF 421 passed plus typecheck; marketing 12
passed plus the repository's validation and production build.

No funded canary was executed. No funds moved, balance changed, custody
transaction was submitted, new customer was created, or new wallet/key was
created. Green and sequence 75594 were untouched.

Machine-readable evidence SHA-256:
`09fc9528f67a599861849725b7d23c921d6eb836e801e3d9753445b725b4abfd`.
