#!/usr/bin/env bash
set -euo pipefail

readonly ENV_FILE=/etc/layrs-opening/direct-runtime.env
[[ ${EUID} -eq 0 ]]
[[ -r ${ENV_FILE} ]]
command -v psql >/dev/null

# shellcheck disable=SC1091
set -a
source "${ENV_FILE}"
set +a
: "${LAYRS_DIRECT_PROJECTION_DATABASE_URL:?projection database unavailable}"
export PGDATABASE="${LAYRS_DIRECT_PROJECTION_DATABASE_URL}"
export PGCONNECT_TIMEOUT=10
unset LAYRS_DIRECT_PROJECTION_DATABASE_URL

psql --dbname="${PGDATABASE}" --no-psqlrc --no-align --tuples-only --set=ON_ERROR_STOP=1 <<'SQL'
BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE;
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path = layrs_direct_v1, pg_catalog;

SELECT json_build_object(
    'fenceRows', (SELECT count(*) FROM direct_execution_writer_fence),
    'grantRows', (SELECT count(*) FROM direct_execution_writer_grants),
    'activationId', fence.activation_id,
    'oldWriterAuthorized', fence.old_writer_authorized,
    'targetWriterEnabled', fence.target_writer_enabled,
    'oldWriterFenceEvidenceSha256', fence.old_writer_fence_evidence_sha256,
    'grantActivationId', g.activation_id,
    'grantEpochId', g.epoch_id,
    'grantExpiresAtUnix', g.expires_at_unix,
    'grantSourceCommit', g.grant_json#>>'{runtimeMeasurement,sourceCommit}',
    'grantAmiId', g.grant_json#>>'{runtimeMeasurement,amiId}'
)::TEXT
FROM direct_execution_writer_fence AS fence
JOIN direct_execution_writer_grants AS g
  ON g.activation_id = fence.activation_id
 AND g.epoch_id = fence.epoch_id
 AND g.old_writer_fence_evidence_sha256 = fence.old_writer_fence_evidence_sha256
WHERE fence.epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b';

COMMIT;
SQL
