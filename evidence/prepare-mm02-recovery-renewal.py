#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import shlex
import time

import boto3

DOMAIN = "layrs.direct-balance-recovery.v1\x00"
KMS_ALIAS = "alias/layrs/production/recovery-evidence-signing"
KMS_ARN = "arn:aws:kms:us-east-1:082223548516:key/4a6aab45-cb27-48b6-903e-2499bf251224"
EXPECTED_EXPIRY = 1789364892
EXPECTED = {
    "recoveryId": "recover-mm02-returned-canary-principal-20260913",
    "epochId": "layrs-opening-epoch-20260911-941107537728c98b",
    "runtime": "layrs.direct-execution.v1",
    "accountId": "7619baaa0831003f3ca58bfcf5b2c773c8bc302a015124b1c432d220ddaa704b",
    "identityCommitment": "88dff4a4d5ab480024423e999bd92463a6474bb00e56f46c264b944aaba39871",
    "asset": "USDC",
    "bucket": "USER_AVAILABLE",
    "amountAtomic": "5000000",
    "expectedBalanceBeforeAtomic": "4404611",
    "evidenceSha256": "79eeb296d8d26ecb4464c649d80bae7a8057b386c766b75bc51486f3d9471143",
    "reasonCode": "RESTORE_RETURNED_CANARY_PRINCIPAL",
    "expiresAtUnix": EXPECTED_EXPIRY,
    "governanceKeyId": KMS_ALIAS,
    "signingAlgorithm": "ECDSA_SHA_256",
    "signature": "",
}


def compact_payload(document):
    unsigned = dict(document)
    unsigned["signature"] = ""
    return json.dumps([DOMAIN, unsigned], separators=(",", ":")).encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("document")
    parser.add_argument("--signature-b64")
    args = parser.parse_args()
    with open(args.document, "rb") as handle:
        document = json.load(handle)
    supplied = document.get("signature", "")
    document["signature"] = ""
    if document != EXPECTED:
        raise SystemExit("FAIL_CLOSED: request differs from exact approved fields")
    payload = compact_payload(document)
    print("unsigned_json_sha256=" + hashlib.sha256(
        json.dumps(document, indent=2).encode() + b"\n"
    ).hexdigest())
    print("signing_payload_sha256=" + hashlib.sha256(payload).hexdigest())
    print("signing_payload_base64=" + base64.b64encode(payload).decode())
    signature_b64 = args.signature_b64 or supplied
    if not signature_b64:
        print("status=AWAITING_GOVERNANCE_SIGNATURE")
        return
    signature = base64.b64decode(signature_b64, validate=True)
    kms = boto3.Session(
        profile_name="predifi-root", region_name="us-east-1"
    ).client("kms")
    result = kms.verify(
        KeyId=KMS_ARN,
        Message=payload,
        MessageType="RAW",
        Signature=signature,
        SigningAlgorithm="ECDSA_SHA_256",
    )
    if not result.get("SignatureValid"):
        raise SystemExit("FAIL_CLOSED: governance signature invalid")
    if int(time.time()) >= EXPECTED_EXPIRY:
        raise SystemExit("FAIL_CLOSED: governed request expired")
    signed = dict(document)
    signed["signature"] = signature_b64
    encoded = base64.b64encode(
        json.dumps(signed, separators=(",", ":")).encode()
    ).decode()
    remote = (
        "printf %s "
        + shlex.quote(encoded)
        + " | base64 -d | curl -sS --fail-with-body --max-time 30 "
        + "-H 'content-type: application/json' --data-binary @- "
        + "http://127.0.0.1:8443/v1/operator/balance-recoveries"
    )
    print("status=SIGNATURE_VERIFIED_NOT_APPLIED")
    print("ssm_remote_apply_command=" + remote)


if __name__ == "__main__":
    main()
