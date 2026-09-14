#!/usr/bin/env bash
set -euo pipefail

# Exact inverse of rebind-p0-attestation-projection.sh. This is held ready so
# a failed runtime rollout can restore the previously authorized, healthy
# writer projection without touching customer balances or private state.
readonly ENV_FILE=/etc/layrs-opening/direct-runtime.env
readonly GRANT_FILE=${1:?previous signed grant path required}
readonly GRANT_FILE_SHA256=05e22c4b256f9a1f40e8b058b2c0ccf454811f13d9fdc1e5bf628bd4b739d86c
readonly ADMIN_SECRET_ID=layrsv2/fresh-epoch-20260826/database/migration

[[ ${EUID} -eq 0 ]]
[[ -r ${ENV_FILE} && -r ${GRANT_FILE} ]]
command -v psql >/dev/null
command -v aws >/dev/null
command -v python3 >/dev/null
[[ $(sha256sum "${GRANT_FILE}" | awk '{print $1}') == "${GRANT_FILE_SHA256}" ]]

# shellcheck disable=SC1091
set -a
source "${ENV_FILE}"
set +a
: "${LAYRS_DIRECT_PROJECTION_DATABASE_URL:?projection database unavailable}"
export PGCONNECT_TIMEOUT=10

secret_outer=$(mktemp -p /run layrs-p0-migration-secret.XXXXXX)
pg_environment=$(mktemp -p /run layrs-p0-pg-env.XXXXXX)
readonly secret_outer pg_environment
trap 'rm -f "${secret_outer}" "${pg_environment}"' EXIT
chmod 600 "${secret_outer}" "${pg_environment}"
aws --region us-east-1 secretsmanager get-secret-value \
  --secret-id "${ADMIN_SECRET_ID}" >"${secret_outer}"
SECRET_OUTER="${secret_outer}" PG_ENVIRONMENT="${pg_environment}" python3 <<'PY'
import json
import os
import shlex
from urllib.parse import urlsplit

outer = json.load(open(os.environ["SECRET_OUTER"], encoding="utf-8"))
secret = json.loads(outer["SecretString"])
runtime = urlsplit(os.environ["LAYRS_DIRECT_PROJECTION_DATABASE_URL"])
required = {key: secret.get(key) for key in ("username", "password", "dbname", "port")}
if not runtime.hostname or any(value in (None, "") for value in required.values()):
    raise SystemExit("P0_ADMIN_DATABASE_CONFIGURATION_INVALID")
values = {
    "PGHOST": runtime.hostname,
    "PGPORT": str(required["port"]),
    "PGUSER": str(required["username"]),
    "PGPASSWORD": str(required["password"]),
    "PGDATABASE": str(required["dbname"]),
    "PGSSLMODE": "require",
}
with open(os.environ["PG_ENVIRONMENT"], "w", encoding="utf-8") as output:
    for key, value in values.items():
        output.write(f"export {key}={shlex.quote(value)}\n")
PY
# shellcheck disable=SC1090
source "${pg_environment}"
rm -f "${secret_outer}" "${pg_environment}"
unset LAYRS_DIRECT_PROJECTION_DATABASE_URL

grant_base64=$(base64 -w0 -- "${GRANT_FILE}")
readonly grant_base64

psql --no-psqlrc --no-align --tuples-only \
  --set=ON_ERROR_STOP=1 --set=grant_base64="${grant_base64}" <<'SQL'
\set QUIET 1
\set VERBOSITY terse
BEGIN ISOLATION LEVEL SERIALIZABLE;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path = layrs_direct_v1, pg_catalog;

CREATE TEMPORARY TABLE p0_previous_grant_input (
    grant_json JSONB NOT NULL
) ON COMMIT DROP;
INSERT INTO p0_previous_grant_input(grant_json)
VALUES (convert_from(decode(:'grant_base64', 'base64'), 'UTF8')::jsonb);

DO $guarded_rollback$
DECLARE
    supplied_grant JSONB;
    affected BIGINT;
BEGIN
    SELECT grant_json INTO STRICT supplied_grant FROM p0_previous_grant_input;

    IF supplied_grant->>'activationId' <> 'layrs-direct-0d0d560-p0-hashfix-20260914'
       OR supplied_grant->>'epochId' <> 'layrs-opening-epoch-20260911-941107537728c98b'
       OR supplied_grant->>'runtime' <> 'layrs.direct-execution.v1'
       OR supplied_grant->>'oldWriterFenceEvidenceSha256' <> 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       OR (supplied_grant->>'expiresAtUnix')::BIGINT <> 1789430400
       OR supplied_grant#>>'{runtimeMeasurement,amiId}' <> 'ami-07bc5e5703da58ace'
       OR supplied_grant#>>'{runtimeMeasurement,eifSha256}' <> 'c18bbd7c01e163d358e1913f02ffb8514f0026592589c5983d38bbd5c0ef0ec6'
       OR supplied_grant#>>'{runtimeMeasurement,pcr0}' <> '7b8f7d691ea7dff214414da22e6d5e4e68ffc4831d47c255601f3729c57ff56a7755f6833a607d74674585d37f9dd334'
       OR supplied_grant#>>'{runtimeMeasurement,sourceCommit}' <> '0d0d560e3a3e271c6f46a130369f01e497998946'
       OR supplied_grant#>>'{keyReleasePredecessor,activationId}' <> 'layrs-direct-4d14163-p0-withdrawal-20260914'
       OR supplied_grant#>>'{keyReleasePredecessor,artifactSha256}' <> 'c6772995ac1570866ac53b6ddf2c8162a0bc73fadd67ff2ac3efcdd561ed1cc4'
       OR supplied_grant#>>'{keyReleasePredecessor,writerGrantCommitment}' <> 'f577563b8d72afae62d168bb21bb91a79ceaf6480ac5f41a5533a0faf3a15aad'
       OR COALESCE(supplied_grant->>'signature', '') = '' THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PREVIOUS_SIGNED_GRANT_MISMATCH';
    END IF;

    PERFORM 1 FROM direct_execution_writer_fence
     WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND old_writer_authorized = FALSE
       AND target_writer_enabled = TRUE
       AND activation_id = 'layrs-direct-f70014d-p0-attestation-20260914'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_FENCE_TARGET_MISMATCH';
    END IF;

    PERFORM 1 FROM direct_execution_writer_grants
     WHERE activation_id = 'layrs-direct-f70014d-p0-attestation-20260914'
       AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND expires_at_unix = 1789435461
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_GRANT_TARGET_MISMATCH';
    END IF;

    IF EXISTS (SELECT 1 FROM direct_execution_writer_grants
               WHERE activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914') THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PREVIOUS_TARGET_ALREADY_EXISTS';
    END IF;

    UPDATE direct_execution_writer_grants
       SET activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914',
           expires_at_unix = 1789430400,
           grant_json = supplied_grant,
           applied_at = transaction_timestamp()
     WHERE activation_id = 'layrs-direct-f70014d-p0-attestation-20260914'
       AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND expires_at_unix = 1789435461;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PREVIOUS_GRANT_CARDINALITY_MISMATCH';
    END IF;

    UPDATE direct_execution_writer_fence
       SET activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914',
           changed_at = transaction_timestamp()
     WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND old_writer_authorized = FALSE
       AND target_writer_enabled = TRUE
       AND activation_id = 'layrs-direct-f70014d-p0-attestation-20260914';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PREVIOUS_FENCE_CARDINALITY_MISMATCH';
    END IF;
END
$guarded_rollback$;
COMMIT;
\set QUIET 0

SELECT json_build_object(
    'activationId', fence.activation_id,
    'oldWriterAuthorized', fence.old_writer_authorized,
    'targetWriterEnabled', fence.target_writer_enabled,
    'oldWriterFenceEvidenceSha256', fence.old_writer_fence_evidence_sha256,
    'expiresAtUnix', g.expires_at_unix
)::TEXT
FROM layrs_direct_v1.direct_execution_writer_fence AS fence
JOIN layrs_direct_v1.direct_execution_writer_grants AS g
  ON g.activation_id = fence.activation_id
 AND g.epoch_id = fence.epoch_id
 AND g.old_writer_fence_evidence_sha256 = fence.old_writer_fence_evidence_sha256
WHERE fence.epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b';
SQL
