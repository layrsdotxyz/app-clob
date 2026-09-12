#!/usr/bin/env python3
"""Exercise one non-financial direct state commit without emitting credentials."""

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.request

ENV_PATH = "/etc/layrs-opening/direct-runtime.env"
TOKEN_PATH = "/root/layrs-isolated-admission-token"
EPOCH_ID = "layrs-opening-epoch-20260911-941107537728c98b"
EPOCH_SHA = "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590"
SUBJECT = "e" * 64
PRIVY_USER = "f" * 64
WALLET = "0x2021202120212021202120212021202120212021"
REQUEST_ID = "keyrelease-packaged-admission-20260913"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def environment() -> dict:
    result = {}
    with open(ENV_PATH, encoding="utf-8") as source:
        for line in source:
            if not line.strip() or line.startswith("#"):
                continue
            key, value = line.rstrip("\n").split("=", 1)
            result[key] = json.loads(value)
    return result


def make_token() -> str:
    app_secret = environment()["LAYRSV2_PRIVY_APP_SECRET"].encode()
    session_key = hmac.new(
        app_secret,
        b"layrs.direct-session.v1\0" + EPOCH_ID.encode() + b"\0" + EPOCH_SHA.encode(),
        hashlib.sha256,
    ).digest()
    identity = hashlib.sha256(
        b"layrs.direct-identity-admission.v1\0"
        + EPOCH_ID.encode()
        + b"\0"
        + SUBJECT.encode()
        + b"\0"
        + WALLET.lower().encode()
    ).hexdigest()
    claims = {
        "sessionId": "keyrelease-packaged-session-20260913",
        "subjectHash": SUBJECT,
        "privyUserIdHash": PRIVY_USER,
        "audience": "layrs.direct-execution.v1",
        "epochId": EPOCH_ID,
        "epochStateSha256": EPOCH_SHA,
        "walletAddress": WALLET,
        "identityCommitment": identity,
        "expiresAtUnix": int(time.time()) + 900,
        "responseKey": b64url(bytes([23]) * 32),
        "signature": "",
    }
    unsigned = json.dumps(claims, separators=(",", ":")).encode()
    claims["signature"] = hmac.new(session_key, unsigned, hashlib.sha256).hexdigest()
    token = b64url(json.dumps(claims, separators=(",", ":")).encode())
    with open(TOKEN_PATH, "w", encoding="utf-8") as target:
        target.write(token)
    os.chmod(TOKEN_PATH, 0o600)
    return token


if len(sys.argv) > 1 and sys.argv[1] == "replay":
    with open(TOKEN_PATH, encoding="utf-8") as source:
        token = source.read().strip()
    phase = "replay"
else:
    token = make_token()
    phase = "initial"

request = urllib.request.Request(
    "http://127.0.0.1:8443/v1/direct/admissions",
    data=b"{}",
    method="POST",
    headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Idempotency-Key": REQUEST_ID,
    },
)
with urllib.request.urlopen(request, timeout=30) as response:
    body = response.read()
    status = response.status

counts = subprocess.run(
    [
        "sudo", "-u", "postgres", "psql", "-d", "layrs_direct", "-At", "-F", ",", "-c",
        "SELECT (SELECT count(*) FROM layrs_direct_v1.direct_execution_receipts),"
        "(SELECT count(*) FROM layrs_direct_v1.direct_execution_accounting_events),"
        "(SELECT count(*) FROM layrs_direct_v1.direct_execution_identity_admissions),"
        "(SELECT count(*) FROM layrs_direct_v1.direct_execution_sessions);",
    ],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout.strip()

print(json.dumps({
    "phase": phase,
    "httpStatus": status,
    "encryptedResponseSha256": hashlib.sha256(body).hexdigest(),
    "projectionCountsReceiptAccountingAdmissionSession": counts,
    "financialAmount": "0",
    "custodyCalled": False,
}, sort_keys=True))
