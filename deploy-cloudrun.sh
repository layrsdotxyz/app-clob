#!/usr/bin/env bash
set -euo pipefail

# Ensure we run from the clob-service directory (co-located Dockerfile)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Unified deployment script: single --set-env-vars invocation to avoid Cloud Run CLI conflicts.
# Usage: ./deploy-cloudrun.sh [region] [service_name]

REGION="${1:-us-east1}"
SERVICE_NAME="${2:-predifi-clob-app}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-zoopx-0xperps}"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "Deploying CLOB service"
echo " Region: ${REGION}"
echo " Service: ${SERVICE_NAME}"
echo " Project: ${PROJECT_ID}"; echo

echo "Building container image ${IMAGE_NAME}:${IMAGE_TAG}"
gcloud builds submit \
  --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
  --project "${PROJECT_ID}" \
  --timeout=20m

echo "Resolving secrets (converted to plain env vars)..."
get_secret() {
    local value
    value=$(gcloud secrets versions access latest --secret "$1" --project "${PROJECT_ID}" 2>/dev/null)
    if [[ -z "$value" ]]; then
        echo "ERROR: Secret '$1' not found or is empty in project '${PROJECT_ID}'." >&2
        echo "Please ensure the secret exists, is not empty, and that you have the 'Secret Manager Secret Accessor' role." >&2
        exit 1
    fi
    echo "$value"
}

REDIS_URL_VALUE="$(get_secret REDIS_URL)"
RPC_URL_VALUE="$(get_secret RPC_URL)"
SETTLEMENT_PK_VALUE="$(get_secret SETTLEMENT_PRIVATE_KEY)"

[[ -z "$REDIS_URL_VALUE" ]] && echo " WARNING: REDIS_URL missing" || echo " REDIS_URL loaded"
[[ -z "$RPC_URL_VALUE" ]] && echo " WARNING: RPC_URL missing" || echo " RPC_URL loaded"
[[ -z "$SETTLEMENT_PK_VALUE" ]] && echo " WARNING: SETTLEMENT_PRIVATE_KEY missing" || echo " SETTLEMENT_PRIVATE_KEY loaded"

BASE_ENV=(
  "RUST_LOG=info,tower_http=info"
  "RUST_BACKTRACE=1"
  "HOST=0.0.0.0"
  "ENABLE_SETTLEMENT=true"
  "CHAIN_ID=11155420"
  "SETTLEMENT_CONTRACT=0xB42EE1571E2a4C151aA09ea8C001059D867aD96C"
  "SETTLEMENT_BATCH_SIZE=10"
  "SETTLEMENT_RETRY_ATTEMPTS=3"
  "MAKER_FEE_BPS=0"
  "TAKER_FEE_BPS=0"
  "MAX_ORDERS_PER_USER=100"
  "MAX_ORDER_SIZE=1000000"
  "MIN_ORDER_SIZE=1"
)

[[ -n "$REDIS_URL_VALUE" ]] && BASE_ENV+=("REDIS_URL=$REDIS_URL_VALUE")
[[ -n "$RPC_URL_VALUE" ]] && BASE_ENV+=("RPC_URL=$RPC_URL_VALUE")
[[ -n "$SETTLEMENT_PK_VALUE" ]] && BASE_ENV+=("SETTLEMENT_PRIVATE_KEY=$SETTLEMENT_PK_VALUE")

ENV_JOINED=$(IFS=','; echo "${BASE_ENV[*]}")

echo "Deploying revision..."
echo "Cleaning previous secret-based env bindings (if any)..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE_NAME}:${IMAGE_TAG}" \
  --platform managed \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --allow-unauthenticated \
  --port 8080 \
  --remove-env-vars REDIS_URL,RPC_URL,SETTLEMENT_PRIVATE_KEY || true

gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE_NAME}:${IMAGE_TAG}" \
  --platform managed \
  --region "${REGION}" \
  --project "${PROJECT_ID}" \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300 \
  --concurrency 1000 \
  --min-instances 1 \
  --max-instances 10 \
  --port 8080 \
  --cpu-boost \
  --vpc-connector predifi-connector \
  --vpc-egress all-traffic \
  --set-env-vars "${ENV_JOINED}"

echo "Revision deployed. Fetching URL..."
CLOB_URL=$(gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --project "${PROJECT_ID}" --format 'value(status.url)')
echo "Service URL: ${CLOB_URL}"; echo
echo "Next steps:"; echo "  curl ${CLOB_URL}/health"; echo "  Set CLOB_SERVICE_URL=${CLOB_URL} in backend and redeploy"
