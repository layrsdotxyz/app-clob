#!/usr/bin/env bash
set -euo pipefail

# One governed, serializable projection rebind. This script does not change
# private financial state and must run only after the exact signed grant and
# measured candidate have passed their independent gates.

readonly ENV_FILE=/etc/layrs-opening/direct-runtime.env
readonly GRANT_FILE_SHA256=05e22c4b256f9a1f40e8b058b2c0ccf454811f13d9fdc1e5bf628bd4b739d86c

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly GRANT_FILE="${SCRIPT_DIR}/WRITER_GRANT_P0_HASHFIX_SIGNED_20260914.json"

[[ ${EUID} -eq 0 ]] || {
  printf '%s\n' 'P0_PROJECTION_REBIND_REQUIRES_ROOT' >&2
  exit 1
}
[[ -r ${ENV_FILE} ]] || {
  printf '%s\n' 'P0_PROJECTION_REBIND_ENV_UNAVAILABLE' >&2
  exit 1
}
[[ -r ${GRANT_FILE} ]] || {
  printf '%s\n' 'P0_PROJECTION_REBIND_GRANT_UNAVAILABLE' >&2
  exit 1
}
command -v psql >/dev/null 2>&1 || {
  printf '%s\n' 'P0_PROJECTION_REBIND_PSQL_UNAVAILABLE' >&2
  exit 1
}
[[ $(sha256sum "${GRANT_FILE}" | awk '{print $1}') == "${GRANT_FILE_SHA256}" ]] || {
  printf '%s\n' 'P0_PROJECTION_REBIND_GRANT_HASH_MISMATCH' >&2
  exit 1
}

# shellcheck disable=SC1091
set -a
source "${ENV_FILE}"
set +a
: "${LAYRS_DIRECT_PROJECTION_DATABASE_URL:?P0_PROJECTION_DATABASE_URL_UNAVAILABLE}"

# Keep connection material out of argv and never emit it. The signed grant is
# public authorization evidence, but its JSON/signature is also intentionally
# omitted from command output.
export PGDATABASE="${LAYRS_DIRECT_PROJECTION_DATABASE_URL}"
export PGCONNECT_TIMEOUT=10
unset LAYRS_DIRECT_PROJECTION_DATABASE_URL

grant_base64="$(base64 -w0 -- "${GRANT_FILE}")"
readonly grant_base64

psql --no-psqlrc --no-align --tuples-only \
  --set=ON_ERROR_STOP=1 --set=grant_base64="${grant_base64}" <<'SQL'
\set QUIET 1
\set VERBOSITY terse
BEGIN ISOLATION LEVEL SERIALIZABLE;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL search_path = layrs_direct_v1, pg_catalog;

CREATE TEMPORARY TABLE p0_hashfix_grant_input (
    grant_json JSONB NOT NULL
) ON COMMIT DROP;

INSERT INTO p0_hashfix_grant_input(grant_json)
VALUES (convert_from(decode(:'grant_base64', 'base64'), 'UTF8')::jsonb);

DO $guarded_rebind$
DECLARE
    fence_count BIGINT;
    grant_count BIGINT;
    conflicting_target_count BIGINT;
    affected BIGINT;
    current_old_authorized BOOLEAN;
    current_target_enabled BOOLEAN;
    current_activation_id TEXT;
    current_fence_sha256 TEXT;
    supplied_grant JSONB;
BEGIN
    SELECT grant_json INTO STRICT supplied_grant
    FROM p0_hashfix_grant_input;

    IF supplied_grant->>'activationId' <> 'layrs-direct-0d0d560-p0-hashfix-20260914'
       OR supplied_grant->>'epochId' <> 'layrs-opening-epoch-20260911-941107537728c98b'
       OR supplied_grant->>'oldWriterFenceEvidenceSha256' <> 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       OR (supplied_grant->>'expiresAtUnix')::BIGINT <> 1789430400
       OR supplied_grant#>>'{keyReleasePredecessor,activationId}' <> 'layrs-direct-4d14163-p0-withdrawal-20260914'
       OR supplied_grant#>>'{keyReleasePredecessor,writerGrantCommitment}' <> 'f577563b8d72afae62d168bb21bb91a79ceaf6480ac5f41a5533a0faf3a15aad'
       OR supplied_grant#>>'{keyReleasePredecessor,artifactSha256}' <> 'c6772995ac1570866ac53b6ddf2c8162a0bc73fadd67ff2ac3efcdd561ed1cc4'
       OR COALESCE(supplied_grant->>'signature', '') = '' THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_SIGNED_GRANT_MISMATCH';
    END IF;

    SELECT COUNT(*) INTO fence_count
    FROM direct_execution_writer_fence
    WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b';
    IF fence_count <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_FENCE_CARDINALITY_MISMATCH';
    END IF;

    SELECT old_writer_authorized,
           target_writer_enabled,
           activation_id,
           old_writer_fence_evidence_sha256
      INTO current_old_authorized,
           current_target_enabled,
           current_activation_id,
           current_fence_sha256
    FROM direct_execution_writer_fence
    WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
    FOR UPDATE;

    IF current_old_authorized IS DISTINCT FROM FALSE
       OR current_target_enabled IS DISTINCT FROM TRUE
       OR current_activation_id IS DISTINCT FROM 'layrs-direct-4d14163-p0-withdrawal-20260914'
       OR current_fence_sha256 IS DISTINCT FROM 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364' THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_FENCE_PREDECESSOR_MISMATCH';
    END IF;

    SELECT COUNT(*) INTO grant_count
    FROM direct_execution_writer_grants
    WHERE activation_id = 'layrs-direct-4d14163-p0-withdrawal-20260914'
      AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
      AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
      AND expires_at_unix = 1789419793;
    IF grant_count <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_GRANT_PREDECESSOR_MISMATCH';
    END IF;

    PERFORM 1
    FROM direct_execution_writer_grants
    WHERE activation_id = 'layrs-direct-4d14163-p0-withdrawal-20260914'
      AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
      AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
      AND expires_at_unix = 1789419793
    FOR UPDATE;

    SELECT COUNT(*) INTO conflicting_target_count
    FROM direct_execution_writer_grants
    WHERE activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914';
    IF conflicting_target_count <> 0 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_TARGET_ALREADY_EXISTS';
    END IF;

    UPDATE direct_execution_writer_grants
       SET activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914',
           expires_at_unix = 1789430400,
           grant_json = supplied_grant,
           applied_at = transaction_timestamp()
     WHERE activation_id = 'layrs-direct-4d14163-p0-withdrawal-20260914'
       AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND expires_at_unix = 1789419793;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_GRANT_UPDATE_CARDINALITY_MISMATCH';
    END IF;

    UPDATE direct_execution_writer_fence
       SET activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914',
           changed_at = transaction_timestamp()
     WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
       AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
       AND old_writer_authorized = FALSE
       AND target_writer_enabled = TRUE
       AND activation_id = 'layrs-direct-4d14163-p0-withdrawal-20260914';
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_FENCE_UPDATE_CARDINALITY_MISMATCH';
    END IF;

    IF (SELECT COUNT(*)
        FROM direct_execution_writer_grants
        WHERE activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914'
          AND epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
          AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
          AND expires_at_unix = 1789430400
          AND grant_json = supplied_grant) <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_GRANT_POSTCONDITION_FAILED';
    END IF;

    IF (SELECT COUNT(*)
        FROM direct_execution_writer_fence
        WHERE epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b'
          AND old_writer_fence_evidence_sha256 = 'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364'
          AND old_writer_authorized = FALSE
          AND target_writer_enabled = TRUE
          AND activation_id = 'layrs-direct-0d0d560-p0-hashfix-20260914') <> 1 THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_FENCE_POSTCONDITION_FAILED';
    END IF;

    IF EXISTS (
        SELECT 1 FROM direct_execution_writer_grants
        WHERE activation_id = 'layrs-direct-4d14163-p0-withdrawal-20260914'
    ) THEN
        RAISE EXCEPTION USING MESSAGE = 'P0_PROJECTION_REBIND_PREDECESSOR_REMAINS';
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
           'expiresAtUnix', grant.expires_at_unix
       )::TEXT
FROM layrs_direct_v1.direct_execution_writer_fence AS fence
JOIN layrs_direct_v1.direct_execution_writer_grants AS grant
  ON grant.activation_id = fence.activation_id
 AND grant.epoch_id = fence.epoch_id
 AND grant.old_writer_fence_evidence_sha256 = fence.old_writer_fence_evidence_sha256
WHERE fence.epoch_id = 'layrs-opening-epoch-20260911-941107537728c98b';
SQL
