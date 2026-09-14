# MM02 returned-canary-principal recovery renewal

Status: `AWAITING_GOVERNANCE_SIGNATURE`; not applied.

The sole prior signature expired at `2026-09-14T03:37:29Z`. The proposed
bounded renewal expires at `2026-09-14T05:48:12Z` (`1789364892`). It preserves
the same recovery ID, account, identity, amount, expected pre-balance, reason,
epoch, runtime, and evidence hash.

Governance signer:

- alias: `alias/layrs/production/recovery-evidence-signing`
- ARN: `arn:aws:kms:us-east-1:082223548516:key/4a6aab45-cb27-48b6-903e-2499bf251224`
- key spec/use: `ECC_NIST_P256` / `SIGN_VERIFY`
- algorithm: `ECDSA_SHA_256`

The exact signing message is compact JSON serialization of this tuple:

```text
("layrs.direct-balance-recovery.v1\0", unsigned-recovery-object)
```

Use `prepare_and_verify.py` to emit the exact payload, verify a returned KMS
signature, and print a bounded SSM apply command. The tool never signs and
never reads a private key.

Authorized signer ceremony commands (the signature output is public evidence,
not key material):

```bash
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["signature"]=""; sys.stdout.buffer.write(json.dumps(["layrs.direct-balance-recovery.v1\0",d],separators=(",",":")).encode())' \
  /tmp/layrs-mm02-recovery-renewal-20260914/MM02_RETURNED_CANARY_PRINCIPAL_RECOVERY_UNSIGNED_RENEWAL_20260914.json \
  > /tmp/mm02-governed-recovery-signing-payload.bin

aws --profile predifi-root kms sign --region us-east-1 \
  --key-id alias/layrs/production/recovery-evidence-signing \
  --message fileb:///tmp/mm02-governed-recovery-signing-payload.bin \
  --message-type RAW --signing-algorithm ECDSA_SHA_256 \
  --query Signature --output text
```

The authorized operator inserts that returned Base64 signature into a copy of
the unsigned JSON, then runs:

```bash
/tmp/layrs-mm02-recovery-renewal-20260914/prepare_and_verify.py \
  /absolute/path/to/signed-renewal.json
```

Only after the tool prints `status=SIGNATURE_VERIFIED_NOT_APPLIED`, pass its
printed `ssm_remote_apply_command` as the sole command in an
`AWS-RunShellScript` invocation targeting `i-041785209e534c1c2`. Do not route
the operator endpoint through Cloudflare or the public BFF.

Pre-apply invariants:

- authoritative runtime is `layrs.direct-execution.v1` for the named epoch;
- runtime reports `writerEnabled=true` under the current governed grant;
- latest immutable artifact/head remains sequence 10 with root
  `f3718751936087f155fddcac3ad2b01d5ceb8b0ae675fac22ff0400f2c643057`;
- MM02 authoritative/projection balance is `4404611` atomic USDC;
- no receipt exists for recovery ID
  `recover-mm02-returned-canary-principal-20260913`;
- the signed JSON matches the unsigned request byte-for-byte except for its
  signature and verifies under the KMS key above.

Expected successful result:

- effect `GOVERNED_BALANCE_RECOVERY_APPLIED`;
- amount `5000000`;
- MM02 `USER_AVAILABLE=9404611`;
- exactly one successor artifact/head and one receipt/accounting projection;
- no custody event or external transfer.

Replay proof accepts either the identical terminal response or a bounded
request-reuse rejection, but always requires no additional artifact/head,
accounting event, or balance effect.
