#!/usr/bin/env python3
"""Configure the isolated verifier without emitting secret material."""

import hashlib
import json
import os
import subprocess

RUNTIME_SECRET = "arn:aws:secretsmanager:us-east-1:082223548516:secret:layrs/production/runtime/fresh-epoch-20260826-qVSXMW"
RPC_SECRET = "arn:aws:secretsmanager:us-east-1:082223548516:secret:layrs/production/providers/rpc-bXcAga"


def secret(reference: str) -> dict:
    raw = subprocess.run(
        [
            "aws", "--region", "us-east-1", "secretsmanager", "get-secret-value",
            "--secret-id", reference, "--query", "SecretString", "--output", "text",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout
    return json.loads(raw)


runtime = secret(RUNTIME_SECRET)
rpc = secret(RPC_SECRET)
with open("/tmp/layrs-writer-grant.json", encoding="utf-8") as source:
    grant = json.load(source)
binding = grant["runtimeMeasurement"]

required_runtime = [
    "privyAppId",
    "privyAppSecret",
    "basePoolLedgerPrivyAddress",
    "basePoolLedgerPrivyWalletId",
    "basePoolLedgerPrivyAuthPrivateKeyPem",
    "receiptShareHmacSecret",
]
missing = [key for key in required_runtime if not runtime.get(key)]
if missing or not rpc.get("baseRpcUrl"):
    raise SystemExit("required existing configuration reference is incomplete")

ack_key = hashlib.sha256(
    b"layrs.direct-execution.durability-ack.v1\0"
    + runtime["receiptShareHmacSecret"].encode("utf-8")
).hexdigest()

values = {
    "LAYRS_DIRECT_ISOLATED_TEST": "false",
    "LAYRS_DIRECT_EXECUTION_MODE": "production-enabled",
    "LAYRS_DIRECT_WRITER_GRANT_JSON": json.dumps(grant, separators=(",", ":")),
    "LAYRS_DIRECT_APPROVED_RUNTIME_BINDING_JSON": json.dumps(binding, separators=(",", ":")),
    "LAYRS_DIRECT_KEY_RELEASE_KMS_KEY_ID": grant["keyReleaseKmsKeyId"],
    "LAYRS_DIRECT_PROJECTION_DATABASE_URL": "postgresql://direct_runtime:layrs_isolated_df846b8_only@127.0.0.1:5432/layrs_direct?sslmode=require",
    "LAYRS_DIRECT_PROJECTION_DATABASE_CA_PEM": open(
        "/var/lib/pgsql/data/server.crt", encoding="utf-8"
    ).read(),
    "LAYRS_DIRECT_ARCHIVE_BACKEND": "s3-object-lock",
    "LAYRS_DIRECT_ARCHIVE_BUCKET": "layrs-production-082223548516-us-east-1-immutable",
    "LAYRS_DIRECT_ARCHIVE_PREFIX": "verification/keyrelease/df846b8",
    "LAYRS_DIRECT_ARCHIVE_KMS_KEY_ID": "arn:aws:kms:us-east-1:082223548516:key/f1e83e95-698d-4778-8df9-14d98998e651",
    "LAYRS_DIRECT_ARCHIVE_RETENTION_SECONDS": "86400",
    "LAYRS_DIRECT_COMMIT_ACK_KEY_HEX": ack_key,
    "LAYRS_DIRECT_CUSTODY_PROVIDER": "privy-base-existing-pool-ledger",
    "LAYRSV2_PRIVY_APP_ID": runtime["privyAppId"],
    "LAYRSV2_PRIVY_APP_SECRET": runtime["privyAppSecret"],
    "LAYRSV2_BASE_POOL_LEDGER_PRIVY_ADDRESS": runtime["basePoolLedgerPrivyAddress"],
    "LAYRSV2_BASE_POOL_LEDGER_PRIVY_WALLET_ID": runtime["basePoolLedgerPrivyWalletId"],
    "LAYRSV2_BASE_POOL_LEDGER_PRIVY_AUTH_PRIVATE_KEY_PEM": runtime["basePoolLedgerPrivyAuthPrivateKeyPem"],
    "LAYRSV2_BASE_POOL_ADDRESS": "0xb07627b0D646F5c82C8E30975a37650Dc272a35f",
    "LAYRSV2_BASE_RPC_URL": rpc["baseRpcUrl"],
    "LAYRSV2_BASE_CONFIRMATIONS": "20",
}

target = "/etc/layrs-opening/direct-runtime.env"
temporary = target + ".tmp"
with open(temporary, "w", encoding="utf-8") as out:
    for key in sorted(values):
        out.write(f"{key}={json.dumps(str(values[key]))}\n")
os.chmod(temporary, 0o640)
subprocess.run(["chown", "root:layrsopening", temporary], check=True)
os.replace(temporary, target)

# Only configuration references and non-secret controls are emitted.
print(json.dumps({
    "runtimeSecretReference": RUNTIME_SECRET,
    "rpcSecretReference": RPC_SECRET,
    "kmsKeyReference": grant["keyReleaseKmsKeyId"],
    "archivePrefix": values["LAYRS_DIRECT_ARCHIVE_PREFIX"],
    "executionMode": values["LAYRS_DIRECT_EXECUTION_MODE"],
    "projection": "isolated-local-postgresql",
    "custodyCallsMade": False,
}, sort_keys=True))
