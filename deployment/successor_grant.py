#!/usr/bin/env python3
"""Build, preflight, sign, and atomically install a successor WriterGrant.

All predecessor fields are read from the target database row and the exact
current S3 authorization object version.  No hash, commitment, activation ID,
VersionId, or grant-bound ARN is accepted on the command line.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import secrets
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import boto3
import psycopg2


PROFILE = "predifi-root"
REGION = "us-east-1"
ACCOUNT = "082223548516"
EPOCH = "layrs-opening-epoch-20260911-941107537728c98b"
MIGRATION_SECRET = "layrsv2/fresh-epoch-20260826/database/migration"
CA_SECRET = "layrs/production/runtime/green-core-5658a29-20260909"
PRODUCTION_ASG = "layrs-production-direct-execution-dormant-DormantAutoScalingGroup-7IpwwCXpbuJL"
HELPER = Path(os.environ.get(
    "LAYRS_WRITER_GRANT_HELPER",
    Path(__file__).parents[1] / "enclave/direct-execution-v1/target/release/writer-grant-helper",
))

TARGETS = {
    "clone": {
        "cluster": "layrs-v71-ancestor-rehearsal-20261001",
        "endpoint": "layrs-v71-ancestor-rehearsal-20261001.cluster-ckx8y68gahaa.us-east-1.rds.amazonaws.com",
        "bucket": "layrs-v71-ancestor-rehearsal-082223548516-us-east-1-20261001",
        "prefix": "direct-execution/rehearsal-v71-cutover-ancestor-20261001",
        "activation_prefix": "layrs-v71-ancestor-rehearsal",
        "required_tag": ("RehearsalId", "v71-ancestor-20261001"),
    },
    "production": {
        "cluster": "layrsv2-fresh-epoch-20260826-aurora",
        "endpoint": "layrsv2-fresh-epoch-20260826-aurora.cluster-ckx8y68gahaa.us-east-1.rds.amazonaws.com",
        "bucket": "layrs-production-082223548516-us-east-1-immutable",
        "prefix": "direct-execution/layrs-opening-epoch-20260911-941107537728c98b",
        "activation_prefix": "layrs-v71",
        "required_tag": None,
    },
}


def fail(code: str) -> "NoReturn":
    raise SystemExit(code)


def write_new(path: Path, body: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(body)
        target.flush()
        os.fsync(target.fileno())


def run_helper(*arguments: str) -> dict[str, str]:
    result = subprocess.run(
        [str(HELPER), *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        message = " ".join(result.stderr.strip().splitlines())
        if len(message) > 512:
            message = message[:512]
        fail(f"GRANT_HELPER_FAILED: {message}")
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def resolve4(host: str) -> set[str]:
    return {row[4][0] for row in socket.getaddrinfo(host, 5432, socket.AF_INET, socket.SOCK_STREAM)}


def production_writer_is_single_and_live(group: dict) -> bool:
    """MinSize is intentionally zero; desired and observed live writers are the fence."""
    instances = group.get("Instances", [])
    return (
        group.get("MinSize") == 0
        and group.get("MaxSize") == 1
        and group.get("DesiredCapacity") == 1
        and len(instances) == 1
        and instances[0].get("LifecycleState") == "InService"
    )


def runtime_measurement_changed(current_grant: dict, approved_binding: dict) -> bool:
    """Bind prepared-artifact evidence to whether this is a runtime upgrade."""
    return current_grant.get("runtimeMeasurement") != approved_binding


class Rotator:
    def __init__(self, target: str, connect_host: str, connect_port: int):
        self.target_name = target
        self.target = TARGETS[target]
        self.connect_host = connect_host
        self.connect_port = connect_port
        self.session = boto3.Session(profile_name=PROFILE, region_name=REGION)
        self.sts = self.session.client("sts")
        self.rds = self.session.client("rds")
        self.s3 = self.session.client("s3")
        self.kms = self.session.client("kms")
        self.ec2 = self.session.client("ec2")
        self.secrets = self.session.client("secretsmanager")

    def secret(self, reference: str) -> dict:
        return json.loads(self.secrets.get_secret_value(SecretId=reference)["SecretString"])

    def connect(self):
        database = self.secret(MIGRATION_SECRET)
        ca = self.secret(CA_SECRET)
        ca_fd, ca_name = tempfile.mkstemp(prefix="layrs-rds-ca-", suffix=".pem", dir="/dev/shm")
        os.close(ca_fd)
        ca_path = Path(ca_name)
        os.chmod(ca_path, 0o600)
        ca_path.write_text(ca["databaseCaPem"], encoding="utf-8")
        try:
            connection = psycopg2.connect(
                host=self.target["endpoint"],
                hostaddr=self.connect_host,
                port=self.connect_port,
                dbname=database.get("dbname", "layrsv2"),
                user=database["username"],
                password=database["password"],
                sslmode="verify-full",
                sslrootcert=str(ca_path),
                connect_timeout=15,
            )
        finally:
            ca_path.unlink(missing_ok=True)
        return connection

    def assert_target_in_session(self, cursor) -> dict:
        if self.sts.get_caller_identity().get("Account") != ACCOUNT:
            fail("AWS_ACCOUNT_MISMATCH")
        groups = self.session.client("autoscaling").describe_auto_scaling_groups(
            AutoScalingGroupNames=[PRODUCTION_ASG]
        )["AutoScalingGroups"]
        if len(groups) != 1:
            fail("PRODUCTION_ASG_COUNT")
        if self.target_name == "production":
            if not production_writer_is_single_and_live(groups[0]):
                fail("PRODUCTION_WRITER_NOT_SINGLE_AND_LIVE")
        cluster = self.rds.describe_db_clusters(DBClusterIdentifier=self.target["cluster"])["DBClusters"]
        if len(cluster) != 1 or cluster[0]["Endpoint"] != self.target["endpoint"]:
            fail("TARGET_CLUSTER_CONTROL_PLANE_MISMATCH")
        required_tag = self.target["required_tag"]
        if required_tag:
            tags = {
                row["Key"]: row["Value"]
                for row in self.rds.list_tags_for_resource(ResourceName=cluster[0]["DBClusterArn"])["TagList"]
            }
            if tags.get(required_tag[0]) != required_tag[1]:
                fail("CLONE_REHEARSAL_TAG_MISMATCH")
        cursor.execute("SELECT inet_server_addr()::text, inet_server_port(), current_database(), current_user")
        server_address_raw, server_port, database, user = cursor.fetchone()
        server_address = str(ipaddress.ip_interface(server_address_raw).ip)
        target_addresses = resolve4(self.target["endpoint"])
        production_addresses = resolve4(TARGETS["production"]["endpoint"])
        if server_address not in target_addresses or int(server_port) != 5432:
            fail("SQL_SESSION_TARGET_MISMATCH")
        if self.target_name == "clone" and server_address in production_addresses:
            fail("SQL_SESSION_RESOLVES_TO_PRODUCTION")
        return {
            "clusterIdentifier": cluster[0]["DBClusterIdentifier"],
            "endpoint": cluster[0]["Endpoint"],
            "sqlServerAddress": server_address,
            "database": database,
            "databaseUser": user,
            "productionAddressExcluded": server_address not in production_addresses,
        }

    def current_authorization(self, cursor, for_update: bool = False) -> dict:
        lock = " FOR UPDATE" if for_update else ""
        cursor.execute(
            """SELECT g.activation_id, g.expires_at_unix, g.grant_json,
                      f.old_writer_authorized, f.target_writer_enabled,
                      f.activation_id AS fence_activation
                 FROM layrs_direct_v1.direct_execution_writer_grants g
                 JOIN layrs_direct_v1.direct_execution_writer_fence f USING (epoch_id)
                WHERE g.epoch_id=%s""" + lock,
            (EPOCH,),
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            fail("AUTHORIZATION_ROW_COUNT")
        activation, expiry, grant, old_authorized, target_enabled, fence_activation = rows[0]
        if activation != fence_activation or old_authorized or not target_enabled:
            fail("SINGLE_WRITER_FENCE_INVALID")
        if grant.get("activationId") != activation or int(grant.get("expiresAtUnix", 0)) != int(expiry):
            fail("DATABASE_GRANT_ROW_BINDING_MISMATCH")
        return {"activation": activation, "expiry": int(expiry), "grant": grant}

    def current_artifact(self, activation: str, path: Path) -> dict:
        key = f"{self.target['prefix']}/authorization/{activation}.cbor"
        versions = []
        paginator = self.s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=self.target["bucket"], Prefix=key):
            versions.extend(
                row for row in page.get("Versions", [])
                if row.get("Key") == key and row.get("IsLatest")
            )
            if any(row.get("Key") == key and row.get("IsLatest") for row in page.get("DeleteMarkers", [])):
                fail("CURRENT_ARTIFACT_IS_DELETE_MARKER")
        if len(versions) != 1:
            fail("CURRENT_ARTIFACT_VERSION_COUNT")
        version = versions[0]
        body = self.s3.get_object(
            Bucket=self.target["bucket"], Key=key, VersionId=version["VersionId"]
        )["Body"].read()
        write_new(path, body)
        return {"key": key, "versionId": version["VersionId"], "size": len(body)}

    def runtime_binding(self, path: Path) -> dict:
        if not str(path).startswith("/dev/shm/"):
            fail("RUNTIME_BINDING_MUST_BE_TMPFS")
        info = path.stat()
        if stat.S_IMODE(info.st_mode) & 0o077:
            fail("RUNTIME_BINDING_MUST_BE_PRIVATE")
        binding = json.loads(path.read_text(encoding="utf-8"))
        required = {
            "amiId", "eifSha256", "pcr0", "pcr1", "pcr2",
            "sourceCommit", "enclaveSha256", "parentSha256",
        }
        if not isinstance(binding, dict) or set(binding) != required:
            fail("RUNTIME_BINDING_FIELDS_INVALID")
        if not isinstance(binding["amiId"], str) or not binding["amiId"].startswith("ami-"):
            fail("RUNTIME_BINDING_AMI_INVALID")
        for key in ("eifSha256", "enclaveSha256", "parentSha256"):
            value = binding[key]
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                fail("RUNTIME_BINDING_SHA256_INVALID")
        for key in ("pcr0", "pcr1", "pcr2"):
            value = binding[key]
            if not isinstance(value, str) or len(value) != 96 or any(c not in "0123456789abcdef" for c in value):
                fail("RUNTIME_BINDING_PCR_INVALID")
        source_commit = binding["sourceCommit"]
        if not isinstance(source_commit, str) or len(source_commit) != 40 or any(c not in "0123456789abcdef" for c in source_commit):
            fail("RUNTIME_BINDING_SOURCE_COMMIT_INVALID")
        images = self.ec2.describe_images(ImageIds=[binding["amiId"]], Owners=[ACCOUNT])["Images"]
        if len(images) != 1 or images[0].get("State") != "available" or images[0].get("OwnerId") != ACCOUNT:
            fail("RUNTIME_BINDING_AMI_NOT_AVAILABLE")
        tags = {row["Key"]: row["Value"] for row in images[0].get("Tags", [])}
        expected_tags = {
            "EifSha256": binding["eifSha256"],
            "ParentSha256": binding["parentSha256"],
            "SourceCommit": binding["sourceCommit"],
        }
        if any(tags.get(key) != value for key, value in expected_tags.items()):
            fail("RUNTIME_BINDING_AMI_TAG_MISMATCH")
        return binding

    def rotate(
        self,
        output: Path,
        valid_seconds: int,
        binding_path: Path,
        renew_expired_predecessor: bool = False,
        apply_database: bool = True,
    ) -> dict:
        if not str(output).startswith("/dev/shm/"):
            fail("OUTPUT_MUST_BE_TMPFS")
        if output.exists():
            fail("OUTPUT_EXISTS")
        now = int(time.time())
        runtime_binding = self.runtime_binding(binding_path)
        work = Path(tempfile.mkdtemp(prefix="layrs-successor-", dir="/dev/shm"))
        os.chmod(work, 0o700)
        current_path = work / "current.json"
        artifact_path = work / "predecessor.cbor"
        unsigned_path = work / "successor-unsigned.json"
        message_path = work / "kms-message.bin"
        signature_path = work / "kms-signature.txt"
        finalized_path = work / "successor-signed.json"
        connection = self.connect()
        try:
            connection.set_session(isolation_level="SERIALIZABLE", readonly=False, autocommit=False)
            cursor = connection.cursor()
            cursor.execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'")
            target_evidence = self.assert_target_in_session(cursor)
            current = self.current_authorization(cursor, for_update=True)
            if current["expiry"] <= now:
                if not renew_expired_predecessor or current["expiry"] < 2:
                    fail("PREDECESSOR_GRANT_EXPIRED")
                predecessor_verify_time = current["expiry"] - 1
                expired_predecessor_renewed = True
            else:
                if renew_expired_predecessor:
                    fail("PREDECESSOR_NOT_EXPIRED")
                predecessor_verify_time = now
                expired_predecessor_renewed = False
            write_new(current_path, json.dumps(current["grant"], separators=(",", ":")).encode())
            source = self.current_artifact(current["activation"], artifact_path)
            predecessor = run_helper(
                "verify-predecessor",
                str(current_path),
                str(artifact_path),
                str(predecessor_verify_time),
            )
            if predecessor.get("activationId") != current["activation"]:
                fail("PREDECESSOR_ACTIVATION_MISMATCH")
            activation = (
                f"{self.target['activation_prefix']}-"
                f"{current['grant']['runtimeMeasurement']['sourceCommit'][:7]}-"
                f"{time.strftime('%Y%m%d', time.gmtime(now))}-{secrets.token_hex(4)}"
            )
            successor = dict(current["grant"])
            successor["activationId"] = activation
            successor["runtimeMeasurement"] = runtime_binding
            successor["keyReleasePredecessor"] = {
                "activationId": predecessor["activationId"],
                "artifactSha256": predecessor["artifactHash"],
                "writerGrantCommitment": predecessor["currentGrantCommitment"],
            }
            successor["expiresAtUnix"] = now + valid_seconds
            successor["signature"] = ""
            write_new(unsigned_path, json.dumps(successor, separators=(",", ":")).encode())
            run_helper("unsigned", str(unsigned_path), str(message_path))
            signature = self.kms.sign(
                KeyId=current["grant"]["governanceKeyId"],
                Message=message_path.read_bytes(),
                MessageType="RAW",
                SigningAlgorithm=current["grant"]["signingAlgorithm"],
            )["Signature"]
            write_new(signature_path, base64.b64encode(signature))
            run_helper(
                "finalize", str(unsigned_path), str(signature_path), str(finalized_path), str(now)
            )
            # Automated pre-submit check: refetch the exact live object version,
            # re-read the locked DB row, and recompute all predecessor bindings.
            live_again = self.current_authorization(cursor, for_update=False)
            if live_again["activation"] != current["activation"] or live_again["grant"] != current["grant"]:
                fail("LIVE_GRANT_CHANGED_DURING_BUILD")
            artifact_check = work / "predecessor-check.cbor"
            source_again = self.current_artifact(current["activation"], artifact_check)
            if source_again["versionId"] != source["versionId"] or artifact_check.read_bytes() != artifact_path.read_bytes():
                fail("LIVE_PREDECESSOR_CHANGED_DURING_BUILD")
            verified = run_helper(
                "verify-successor",
                str(current_path),
                str(artifact_check),
                str(finalized_path),
                str(binding_path),
                str(predecessor_verify_time),
                str(now),
            )
            if not apply_database:
                connection.rollback()
                write_new(output, finalized_path.read_bytes())
                return {
                    "status": "SUCCESSOR_GRANT_PREPARED",
                    "target": self.target_name,
                    "clusterIdentifier": target_evidence["clusterIdentifier"],
                    "sqlServerAddress": target_evidence["sqlServerAddress"],
                    "databaseUser": target_evidence["databaseUser"],
                    "productionAddressExcluded": target_evidence["productionAddressExcluded"],
                    "predecessorActivationId": predecessor["activationId"],
                    "predecessorArtifactHash": predecessor["artifactHash"],
                    "predecessorGrantCommitment": predecessor["currentGrantCommitment"],
                    "sourceObjectVersionId": source["versionId"],
                    "successorActivationId": activation,
                    "successorGrantCommitment": verified["successorGrantCommitment"],
                    "runtimeAmiId": runtime_binding["amiId"],
                    "runtimeSourceCommit": runtime_binding["sourceCommit"],
                    "runtimeBindingReadFrom": str(binding_path),
                    "expiresAtUnix": successor["expiresAtUnix"],
                    "expiredPredecessorRenewed": expired_predecessor_renewed,
                    "predecessorVerifiedAtUnix": predecessor_verify_time,
                    "output": str(output),
                }
            cursor.execute(
                """UPDATE layrs_direct_v1.direct_execution_writer_grants
                      SET activation_id=%s, expires_at_unix=%s, grant_json=%s::jsonb,
                          applied_at=transaction_timestamp()
                    WHERE epoch_id=%s AND activation_id=%s
                      AND expires_at_unix=%s AND grant_json=%s::jsonb""",
                (
                    activation,
                    successor["expiresAtUnix"],
                    finalized_path.read_text(),
                    EPOCH,
                    current["activation"],
                    current["expiry"],
                    current_path.read_text(),
                ),
            )
            if cursor.rowcount != 1:
                fail("GRANT_UPDATE_COUNT")
            cursor.execute(
                """UPDATE layrs_direct_v1.direct_execution_writer_fence
                      SET activation_id=%s, changed_at=transaction_timestamp()
                    WHERE epoch_id=%s AND activation_id=%s
                      AND old_writer_authorized=FALSE AND target_writer_enabled=TRUE""",
                (activation, EPOCH, current["activation"]),
            )
            if cursor.rowcount != 1:
                fail("FENCE_UPDATE_COUNT")
            after = self.current_authorization(cursor, for_update=False)
            if after["activation"] != activation:
                fail("SUCCESSOR_READBACK_MISMATCH")
            # Same SQL session target assertion immediately before commit.
            target_evidence_after = self.assert_target_in_session(cursor)
            if target_evidence_after != target_evidence:
                fail("SQL_SESSION_TARGET_CHANGED")
            connection.commit()
            write_new(output, finalized_path.read_bytes())
            return {
                "status": "SUCCESSOR_GRANT_APPLIED",
                "target": self.target_name,
                "clusterIdentifier": target_evidence["clusterIdentifier"],
                "sqlServerAddress": target_evidence["sqlServerAddress"],
                "databaseUser": target_evidence["databaseUser"],
                "productionAddressExcluded": target_evidence["productionAddressExcluded"],
                "predecessorActivationId": predecessor["activationId"],
                "predecessorArtifactHash": predecessor["artifactHash"],
                "predecessorGrantCommitment": predecessor["currentGrantCommitment"],
                "sourceObjectVersionId": source["versionId"],
                "successorActivationId": activation,
                "successorGrantCommitment": verified["successorGrantCommitment"],
                "runtimeAmiId": runtime_binding["amiId"],
                "runtimeSourceCommit": runtime_binding["sourceCommit"],
                "runtimeBindingReadFrom": str(binding_path),
                "expiresAtUnix": successor["expiresAtUnix"],
                "expiredPredecessorRenewed": expired_predecessor_renewed,
                "predecessorVerifiedAtUnix": predecessor_verify_time,
                "output": str(output),
            }
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def install_prepared(
        self,
        successor_path: Path,
        prepared_evidence_path: Path,
        binding_path: Path,
    ) -> dict:
        """CAS the database only after the parent has prepared the exact artifact.

        The evidence is the JSON response from /writer-grant/prepare. Every
        commitment/hash is independently recomputed from the signed grant and
        the exact versioned S3 objects before the transaction commits.
        """
        for path, code in ((successor_path, "SUCCESSOR"), (prepared_evidence_path, "PREPARED_EVIDENCE")):
            if not str(path).startswith("/dev/shm/") or stat.S_IMODE(path.stat().st_mode) & 0o077:
                fail(f"{code}_MUST_BE_PRIVATE_TMPFS")
        now = int(time.time())
        successor = json.loads(successor_path.read_text(encoding="utf-8"))
        evidence = json.loads(prepared_evidence_path.read_text(encoding="utf-8"))
        binding = self.runtime_binding(binding_path)
        work = Path(tempfile.mkdtemp(prefix="layrs-successor-install-", dir="/dev/shm"))
        os.chmod(work, 0o700)
        current_path = work / "current.json"
        predecessor_artifact_path = work / "predecessor.cbor"
        successor_artifact_path = work / "successor.cbor"
        connection = self.connect()
        try:
            connection.set_session(isolation_level="SERIALIZABLE", readonly=False, autocommit=False)
            cursor = connection.cursor()
            cursor.execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'")
            target_evidence = self.assert_target_in_session(cursor)
            current = self.current_authorization(cursor, for_update=True)
            write_new(current_path, json.dumps(current["grant"], separators=(",", ":")).encode())
            source = self.current_artifact(current["activation"], predecessor_artifact_path)
            predecessor = run_helper(
                "verify-predecessor", str(current_path), str(predecessor_artifact_path), str(now)
            )
            verified = run_helper(
                "verify-successor", str(current_path), str(predecessor_artifact_path),
                str(successor_path), str(binding_path), str(now), str(now),
            )
            activation = verified.get("successorActivationId")
            commitment = verified.get("successorGrantCommitment")
            expiry = int(verified.get("expiresAtUnix", "0"))
            successor_source = self.current_artifact(activation, successor_artifact_path)
            artifact = run_helper(
                "verify-artifact", str(successor_path), str(successor_artifact_path), str(now)
            )
            runtime_changed = runtime_measurement_changed(current["grant"], binding)
            expected_evidence = {
                "activationId": activation,
                "writerGrantCommitment": commitment,
                "writerGrantExpiresAtUnix": expiry,
                "keyReleaseArtifactHash": artifact.get("artifactHash"),
                "runtimeChanged": runtime_changed,
            }
            if evidence != expected_evidence:
                fail("PREPARED_ARTIFACT_EVIDENCE_MISMATCH")
            if successor.get("activationId") != activation or int(successor.get("expiresAtUnix", 0)) != expiry:
                fail("SUCCESSOR_GRANT_METADATA_MISMATCH")
            cursor.execute(
                """UPDATE layrs_direct_v1.direct_execution_writer_grants
                      SET activation_id=%s, expires_at_unix=%s, grant_json=%s::jsonb,
                          applied_at=transaction_timestamp()
                    WHERE epoch_id=%s AND activation_id=%s
                      AND expires_at_unix=%s AND grant_json=%s::jsonb""",
                (activation, expiry, successor_path.read_text(), EPOCH, current["activation"],
                 current["expiry"], current_path.read_text()),
            )
            if cursor.rowcount != 1:
                fail("GRANT_UPDATE_COUNT")
            cursor.execute(
                """UPDATE layrs_direct_v1.direct_execution_writer_fence
                      SET activation_id=%s, changed_at=transaction_timestamp()
                    WHERE epoch_id=%s AND activation_id=%s
                      AND old_writer_authorized=FALSE AND target_writer_enabled=TRUE""",
                (activation, EPOCH, current["activation"]),
            )
            if cursor.rowcount != 1:
                fail("FENCE_UPDATE_COUNT")
            after = self.current_authorization(cursor, for_update=False)
            if after["activation"] != activation or after["grant"] != successor:
                fail("SUCCESSOR_READBACK_MISMATCH")
            if self.assert_target_in_session(cursor) != target_evidence:
                fail("SQL_SESSION_TARGET_CHANGED")
            connection.commit()
            return {
                "status": "SUCCESSOR_GRANT_DATABASE_CAS_APPLIED",
                "target": self.target_name,
                "clusterIdentifier": target_evidence["clusterIdentifier"],
                "predecessorActivationId": predecessor["activationId"],
                "predecessorArtifactHash": predecessor["artifactHash"],
                "predecessorObjectVersionId": source["versionId"],
                "successorActivationId": activation,
                "successorGrantCommitment": commitment,
                "successorArtifactHash": artifact["artifactHash"],
                "successorObjectVersionId": successor_source["versionId"],
                "expiresAtUnix": expiry,
                "runtimeAmiId": binding["amiId"],
                "runtimeChanged": runtime_changed,
            }
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("prepare", "install"))
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--connect-host", default="127.0.0.1")
    parser.add_argument("--connect-port", type=int, default=55432)
    parser.add_argument("--valid-seconds", type=int, default=6 * 60 * 60)
    parser.add_argument("--runtime-binding", required=True)
    parser.add_argument("--output")
    parser.add_argument("--successor")
    parser.add_argument("--prepared-evidence")
    parser.add_argument("--confirm-production-mutation")
    parser.add_argument("--renew-expired-predecessor", action="store_true")
    args = parser.parse_args()
    if args.valid_seconds < 3600 or args.valid_seconds > 7 * 24 * 60 * 60:
        fail("VALIDITY_OUT_OF_RANGE")
    if args.target == "production" and args.operation == "install" \
            and args.confirm_production_mutation != "APPROVE_PRODUCTION_WRITER_GRANT_HOT_RENEWAL":
        fail("PRODUCTION_CONFIRMATION_REQUIRED")
    rotator = Rotator(args.target, args.connect_host, args.connect_port)
    if args.operation == "prepare":
        if not args.output or args.successor or args.prepared_evidence:
            fail("PREPARE_ARGUMENTS_INVALID")
        result = rotator.rotate(
            Path(args.output), args.valid_seconds, Path(args.runtime_binding),
            args.renew_expired_predecessor, apply_database=False,
        )
    else:
        if not args.successor or not args.prepared_evidence or args.output or args.renew_expired_predecessor:
            fail("INSTALL_ARGUMENTS_INVALID")
        result = rotator.install_prepared(
            Path(args.successor), Path(args.prepared_evidence), Path(args.runtime_binding)
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
