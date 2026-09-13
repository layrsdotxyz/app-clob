#!/usr/bin/env python3
"""Verify a direct-runtime Nitro attestation response read from stdin."""

import argparse
import base64
import hashlib
import json
import re
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def required_pcr(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{96}", value):
        raise argparse.ArgumentTypeError("PCR must be 96 lowercase hex characters")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-nonce", required=True)
    parser.add_argument("--expected-pcr0", required=True, type=required_pcr)
    parser.add_argument("--expected-pcr1", required=True, type=required_pcr)
    parser.add_argument("--expected-pcr2", required=True, type=required_pcr)
    args = parser.parse_args()

    response = json.load(sys.stdin)
    document = decode_base64url(response["attestationDocument"])
    protected, _unprotected, payload, signature = cbor2.loads(document)
    if cbor2.loads(protected).get(1) != -35 or len(signature) != 96:
        raise SystemExit("attestation does not contain a valid COSE ES384 envelope")

    attestation = cbor2.loads(payload)
    leaf = x509.load_der_x509_certificate(attestation["certificate"])
    signature_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    leaf.public_key().verify(
        encode_dss_signature(
            int.from_bytes(signature[:48], "big"),
            int.from_bytes(signature[48:], "big"),
        ),
        signature_structure,
        ec.ECDSA(hashes.SHA384()),
    )

    certificates = [
        x509.load_der_x509_certificate(encoded) for encoded in attestation["cabundle"]
    ]
    by_subject = {certificate.subject.rfc4514_string(): certificate for certificate in certificates}
    current = leaf
    verified = 0
    visited = set()
    while current.issuer != current.subject:
        issuer = by_subject.get(current.issuer.rfc4514_string())
        if issuer is None:
            raise SystemExit("attestation certificate issuer is absent")
        issuer.public_key().verify(
            current.signature,
            current.tbs_certificate_bytes,
            ec.ECDSA(current.signature_hash_algorithm),
        )
        verified += 1
        current = issuer
        fingerprint = current.fingerprint(hashes.SHA256()).hex()
        if fingerprint in visited:
            raise SystemExit("attestation certificate chain contains a cycle")
        visited.add(fingerprint)
    current.public_key().verify(
        current.signature,
        current.tbs_certificate_bytes,
        ec.ECDSA(current.signature_hash_algorithm),
    )
    verified += 1

    if attestation["nonce"] != args.expected_nonce.encode():
        raise SystemExit("attestation nonce mismatch")
    actual_pcrs = [attestation["pcrs"][index].hex() for index in range(3)]
    expected_pcrs = [args.expected_pcr0, args.expected_pcr1, args.expected_pcr2]
    if actual_pcrs != expected_pcrs:
        raise SystemExit("attestation PCR tuple mismatch")
    user_data = json.loads(attestation["user_data"])
    if user_data != response["binding"]:
        raise SystemExit("attested runtime binding does not match response binding")

    print(json.dumps({
        "coseAlgorithm": "ES384",
        "coseSignatureVerified": True,
        "certificateChainSignaturesVerified": verified,
        "rootSubject": current.subject.rfc4514_string(),
        "rootSha256": current.fingerprint(hashes.SHA256()).hex(),
        "moduleId": attestation["module_id"],
        "pcr0": actual_pcrs[0],
        "pcr1": actual_pcrs[1],
        "pcr2": actual_pcrs[2],
        "nonceMatches": True,
        "bindingMatches": True,
        "binding": response["binding"],
        "attestationBytes": len(document),
        "attestationSha256": hashlib.sha256(document).hexdigest(),
    }, indent=2))


if __name__ == "__main__":
    main()
