#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import shlex
import time
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

EPOCH_ID = "layrs-opening-epoch-20260911-941107537728c98b"
EPOCH_SHA = "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590"
AUDIENCE = "layrs.direct-execution.v1"

ACCOUNTS = [
    {
        "label": "MM02",
        "subjectHash": "7619baaa0831003f3ca58bfcf5b2c773c8bc302a015124b1c432d220ddaa704b",
        "privyUserId": "did:privy:cmtjb4t83000n0cl7n1vxbp3t",
        "wallet": "0xB69ac21b8a96234A09Ba6c7644F1c2b106FD4A01",
        "identities": ["88dff4a4d5ab480024423e999bd92463a6474bb00e56f46c264b944aaba39871"],
    },
    {
        "label": "0x511fa04b4765672d2606cB4Fce6C10629a729A09",
        "subjectHash": "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3",
        "privyUserId": "did:privy:cmtouh7fl015y0cjwrg3v4ptw",
        "wallet": "0x1CbE2Ddb7c7Ac4c67Bc692cB463f759d0d7b4deD",
        "identities": [
            "7f4c67c76eed0cdf7e496358af186db61c79c08ffe424f2b3b3e47b7dfb01bea",
            "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481",
        ],
    },
    {
        "label": "0x7EF8c8639F5e4CBa821ae76e1631AFCb8cc5Fa0B",
        "subjectHash": "cffdcb64ba7d34e7ee6d523c8d0e3281827ad94d160975df770192dc08a1fcd8",
        "privyUserId": "did:privy:cmtogtfgo011x0cl8iprn29v3",
        "wallet": "0xCc7E28E126Fe8dF7CD7c01f96770C67b3Cd23440",
        "identities": [
            "1af4f2296c17ce57d8553582095d2e4e70f1bd6eea8c2d29bbb3b1b75a940f74",
            "ecefd0c2c92887812ee1f53c38ddf61483900c5d734ee2f4ddfbcc3becea8c6a",
        ],
    },
]


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_environment():
    values = {}
    with open("/etc/layrs-opening/direct-runtime.env", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw = line.split("=", 1)
            parsed = shlex.split(raw)
            values[key] = parsed[0] if parsed else ""
    return values


def session_key(environment):
    explicit = environment.get("LAYRS_DIRECT_SESSION_HMAC_KEY_HEX")
    if explicit:
        return bytes.fromhex(explicit)
    secret = environment["LAYRSV2_PRIVY_APP_SECRET"].encode()
    material = b"layrs.direct-session.v1\x00" + EPOCH_ID.encode() + b"\x00" + EPOCH_SHA.encode()
    return hmac.new(secret, material, hashlib.sha256).digest()


def query(key, account, identity, endpoint, query_string=""):
    response_key = os.urandom(32)
    claims = {
        "sessionId": "readonly-proof-" + hashlib.sha256(
            (account["label"] + identity + endpoint + str(time.time_ns())).encode()
        ).hexdigest()[:32],
        "subjectHash": account["subjectHash"],
        "privyUserIdHash": hashlib.sha256(account["privyUserId"].encode()).hexdigest(),
        "audience": AUDIENCE,
        "epochId": EPOCH_ID,
        "epochStateSha256": EPOCH_SHA,
        "walletAddress": account["wallet"],
        "financialWalletAddress": None,
        "identityCommitment": identity,
        "expiresAtUnix": int(time.time()) + 60,
        "responseKey": b64url(response_key),
        "signature": "",
    }
    unsigned = json.dumps(claims, separators=(",", ":")).encode()
    claims["signature"] = hmac.new(key, unsigned, hashlib.sha256).hexdigest()
    token = b64url(json.dumps(claims, separators=(",", ":")).encode())
    request = urllib.request.Request(
        "http://127.0.0.1:8443/v1/direct/" + endpoint + "/" + identity + query_string,
        headers={"authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        envelope = json.load(response)
    plaintext = ChaCha20Poly1305(response_key).decrypt(
        b64url_decode(envelope["nonce"]), b64url_decode(envelope["ciphertext"]), None
    )
    return json.loads(plaintext)


def main():
    key = session_key(load_environment())
    output = []
    for account in ACCOUNTS:
        identities = []
        for identity in account["identities"]:
            balance = query(key, account, identity, "balances")
            withdrawal_hold = query(
                key, account, identity, "balances", "?bucket=USER_WITHDRAWAL_HOLD"
            )
            order_hold = query(
                key, account, identity, "balances", "?bucket=USER_ORDER_HOLD"
            )
            portfolio = query(key, account, identity, "portfolio")
            identities.append(
                {
                    "identityCommitment": identity,
                    "balance": balance,
                    "withdrawalHold": withdrawal_hold,
                    "orderHold": order_hold,
                    "portfolio": portfolio,
                }
            )
        output.append({"account": account["label"], "identities": identities})
    print(json.dumps(output, separators=(",", ":")))


if __name__ == "__main__":
    main()
