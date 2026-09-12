# Activation-gate compatibility verification — 2026-09-12

This record is a read-only verification of the final dormant candidate.  It
does not authorize a writer, route traffic, create an intent, submit custody,
or change a production balance.

## Exact candidate remains dormant

- AMI: `ami-0781a67a374dc8a70` (available, x86_64)
- EIF SHA-256:
  `6f1cc6cd61492e7b2d3c34d75256412542de640fefbf3b6f4aad7021cc742542`
- Parent instance: `i-0fba59d5740ca0847`, healthy and private.
- Auto Scaling Group tag and instance tag: `WriterEnabled=false`.
- Transaction model: `layrs.direct-execution.v1`.

## WriterGrant compatibility result

The current attested runtime accepts a `WriterGrant` only if its `signature`
is an HMAC-SHA-256 value verified using the separately injected
`LAYRS_DIRECT_GOVERNANCE_KEY_HEX`.  This is shown by
`enclave/direct-execution-v1/src/lib.rs` and `src/bin/enclave.rs`.

The only production KMS signing primitive discovered by metadata is the
recovery-evidence key with `KeyUsage=SIGN_VERIFY`, `KeySpec=ECC_NIST_P256`,
and `ECDSA_SHA_256`.  It cannot create the HMAC expected by the attested
runtime.  No configured reference for `LAYRS_DIRECT_GOVERNANCE_KEY_HEX`, no
concrete activation ID, and no concrete bounded expiry was found in the
activation artifacts.  Substituting the P-256 key, deriving a new symmetric
key, or changing the verifier would invalidate the approved candidate and is
prohibited.

## Existing BFF and projection references

The legacy public-API task definition has existing, metadata-verified
references for the Privy provider (`appId`, `appSecret`, and JWKS endpoint)
and the existing fresh-epoch API database principal (`username` and
`password`).  These establish the possible BFF/reader inputs without reading
a secret value.

They do **not** establish the required direct-session reference.  The direct
parent requires `LAYRS_DIRECT_SESSION_HMAC_KEY_HEX`; no production secret or
parameter reference for that exact purpose exists.  Existing realtime and
Cloudflare-origin HMAC controls have distinct protocols and must not be
repurposed.  The parent also runs projection DDL and opening-state import when
`LAYRS_DIRECT_PROJECTION_DATABASE_URL` is present, so a read-only credential
preflight cannot safely be presented as a projection deployment.

The clean deterministic Privy/JWKS bridge tests passed (5 tests), but no
production BFF route was created because it cannot issue an assertion the
attested parent can safely verify.

## Alert and DLQ verification

- The existing topic
  `arn:aws:sns:us-east-1:082223548516:layrs-production-operational-alerts`
  has zero subscriptions.  There is no endpoint to which a controlled test
  can be delivered without inventing a recipient.
- All 20 production alarms are currently `ALARM`; the individual dispositions
  are in `PRODUCTION_ACTIVATION_CHECKLIST_20260912.md`.
- The shared legacy worker DLQ currently has 917 visible messages.  It is not
  a stale zero-message condition.  Deleting or redriving it would either lose
  evidence or target a fenced legacy writer, so neither action was taken.
- The direct-runtime health alarm is configured against an undimensioned
  `AWS/EC2 StatusCheckFailed` metric with missing data treated as breaching.
  It has no datapoints despite the private runtime instance being healthy;
  a real instance/ASG-aware health metric is required rather than silencing
  the alarm.

## Result

The custody read-only preflight, archive, immutable-intent implementation,
attestation, and old-writer fence remain intact.  The final candidate cannot
be made writer-capable or BFF-routable with the discovered production material
without an incompatible signature substitution, an unapproved new/repurposed
session key, a projection write, or a funded payout.

No funds moved.  No production balance, custody state, secret value, signer,
wallet, key, writer, or legacy route was changed.
