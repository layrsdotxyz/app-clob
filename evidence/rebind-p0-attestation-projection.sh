#!/usr/bin/env bash
set -euo pipefail

# Exactly-once, serializable authorization-projection rebind. This changes no
# customer balance or private financial state. It may run only after the exact
# signed f700 grant has passed the measured-runtime verifier.
readonly ENV_FILE=/etc/layrs-opening/direct-runtime.env
readonly GRANT_FILE=${1:?signed grant path required}
readonly GRANT_FILE_SHA256=aa9a47ede138432f1d93105c7c19fe73f35e245cd87559aa4e701e72f4183c4b
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

# Resolve the already-existing governed migration principal without printing
# or retaining its value. The current runtime URL supplies only the verified
# production endpoint; the private username/password come from Secrets Manager.
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

CREATE TEMPORARY TABLE p0_attestation_grant_input (
    grant_json JSONB NOT NULL
) ON COMMIT DROP;
INSERT INTO p0_attestation_grant_input(grant_json)
VALUES (convert_from(decode(:'grant_base64', 'base64'), 'UTF8')::jsonb);

DO $guarded_rebind$
DECLARE
    supplied_grant JSONB;
    affected BIGINT;
BEGIN
    SELECT grant_json INTO STRICT supplied_grant
      FROM p0_attestation_grant_input;

    IF supplied_grant->>'activationId' <> 'layrs-direct-f70014d-p0-attestation-20260914'
       OR supplied_grant->>'epochId' <> 'layrs-opening-epoch-20260911-941107537728c98b'
       OR supplied_grant->>'runtime' <> 'layrs.direct-execution.v1'
       OR supplied_grant->>'oldWriterFenceEvidenceSha256' <> 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       OR (supplied_grant->>'expiresAtUnix')::BIGINT <> 1789435461
       OR supplied_grant#>>'{runtimeMeasurement,amiId}' <> 'ami-045b26e26393c3356'
       OR supplied_grant#>>'{runtimeMeasurement,eifSha256}' <> '4d5fa5c9e83c7dca7cad20730cb8201d7eeae459708417533cf9c6f4afc9c396'
       OR supplied_grant#>>'{runtimeMeasurement,pcr0}' <> '285ca2c612492c0a547b6b23e9e60ea8c27f8020ad13dd16c8d423dd8b884553dc768d586c0774c121330f3248ad8f52'
       OR supplied_grant#>>'{runtimeMeasurement,sourceCommit}' <> 'f70014dddaed01214d20a18faed871d0f8a5a3b1'
       OR supplied_grant#>>'{keyReleasePredecessor,activationId}' <> 'layrs-direct-0d0d560-p0-hashfix-20260914'
       OR supplied_grant#>>'{keyReleasePredecessor,artifactSha256}' <> '49f57873cc3d3742e2898bdcbf0d044a36657f1e82e638cb91dd8c5822b99aa1'
       OR supplied_grant#>>'{keyReleasePredecessor,writerGrantCommitment}' <> '26d7f36a2fdae599105e896766b21424ac98a55ab00024f02208b1c339a5fd76'
       OR COALESCE(supplied_grant->>'signature', '') = '' THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_SIGNED_GRANT_MISMATCH';
    END IF;

    PERFORM 1 FROM direct_execution_writer_fence
     WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND old_writer_authorized = FALSE
       AND target_writer_enabled = TRUE
       AND activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_FENCE_PREDECESSOR_MISMATCH';
    END IF;

    PERFORM 1 FROM direct_execution_writer_grants
     WHERE activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914'
       AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND expires_at_unix = 1789430400
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_GRANT_PREDECESSOR_MISMATCH';
    END IF;

    IF EXISTS (SELECT 1 FROM direct_execution_writer_grants
               WHERE activation_id = 'layrs-direct-f70014d-p0-attestation-20260914') THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_TARGET_ALREADY_EXISTS';
    END IF;

    UPDATE direct_execution_writer_grants
       SET activation_id = 'layrs-direct-f70014d-p0-attestation-20260914',
           expires_at_unix = 1789435461,
           grant_json = supplied_grant,
           applied_at = transaction_timestamp()
     WHERE activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914'
       AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND expires_at_unix = 1789430400;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_GRANT_CARDINALITY_MISMATCH';
    END IF;

    UPDATE direct_execution_writer_fence
       SET activation_id = 'layrs-direct-f70014d-p0-attestation-20260914',
           changed_at = transaction_timestamp()
     WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND old_writer_authorized = FALSE
       AND target_writer_enabled = TRUE
       AND activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_FENCE_CARDINALITY_MISMATCH';
    END IF;

    IF (SELECT COUNT(*) FROM direct_execution_writer_grants
        WHERE activation_id = 'layrs-direct-f70014d-p0-attestation-20260914'
          AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
          AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
          AND expires_at_unix = 1789435461
          AND grant_json = supplied_grant) <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_ATTESTATION_GRANT_POSTCONDITION_FAILED';
    END IF;
END
$guarded_rebind$;
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
