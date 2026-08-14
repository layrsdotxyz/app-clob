#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=''
export AWS_CLI_AUTO_PROMPT=off

aws_region=${LAYRSV2_PRIMARY_REGION:-us-east-1}
environment=${LAYRSV2_ENVIRONMENT:-production}
repository_uri=${LAYRSV2_ZK_PROOF_ECR_REPOSITORY_URI:-255638996474.dkr.ecr.us-east-1.amazonaws.com/layrsv2-production-zk-proof-worker}
release_sha=${CI_COMMIT_SHA:-$(git rev-parse HEAD)}

[[ "$environment" == production ]] || { echo 'only production is wired' >&2; exit 65; }
[[ "$release_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'release SHA must be a git commit' >&2; exit 65; }
command -v aws >/dev/null || { echo 'aws CLI is required' >&2; exit 69; }
command -v docker >/dev/null || { echo 'docker CLI is required' >&2; exit 69; }

if [[ -n "${LAYRSV2_AWS_ROLE_ARN:-}" ]]; then
  credentials=$(aws sts assume-role \
    --region "$aws_region" \
    --role-arn "$LAYRSV2_AWS_ROLE_ARN" \
    --role-session-name "layrsv2-zk-gitlab-${CI_PIPELINE_ID:-manual}-${CI_JOB_ID:-0}" \
    --duration-seconds 14400 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text)
  read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<<"$credentials"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
fi

caller_arn=$(aws sts get-caller-identity --query Arn --output text)
echo "CALLER $caller_arn"
[[ "$caller_arn" != *':root' && "$caller_arn" == *':assumed-role/layrsv2-'* ]] || {
  echo "least-privilege layrsv2 assumed role required; got $caller_arn" >&2
  exit 77
}

registry=${repository_uri%%/*}
repository_name=${repository_uri#*/}
image_tag="git-${release_sha}"
tagged_image="${repository_uri}:${image_tag}"

aws ecr describe-repositories --region "$aws_region" --repository-names "$repository_name" >/dev/null
aws ecr get-login-password --region "$aws_region" |
  docker login --username AWS --password-stdin "$registry" >/dev/null

image_digest=$(aws ecr describe-images \
  --region "$aws_region" \
  --repository-name "$repository_name" \
  --image-ids "imageTag=$image_tag" \
  --query 'imageDetails[0].imageDigest' \
  --output text 2>/dev/null || true)

if [[ "$image_digest" == sha256:* ]]; then
  echo "DOCKER_IMAGE_REUSE $tagged_image $image_digest"
else
  echo "DOCKER_BUILD $tagged_image"
  docker build --pull --file Dockerfile.zk-proof-worker --tag "$tagged_image" .
  echo "DOCKER_PUSH $tagged_image"
  timeout 1800 docker push "$tagged_image" >/dev/null
fi

for _ in $(seq 1 60); do
  image_digest=$(aws ecr describe-images \
    --region "$aws_region" \
    --repository-name "$repository_name" \
    --image-ids "imageTag=$image_tag" \
    --query 'imageDetails[0].imageDigest' \
    --output text 2>/dev/null || true)
  [[ "$image_digest" == sha256:* ]] && break
  sleep 2
done
[[ "$image_digest" == sha256:* ]] || { echo 'immutable ECR digest unavailable' >&2; exit 75; }
image_uri="${repository_uri}@${image_digest}"

scan_json=''
scan_status=''
for _ in $(seq 1 120); do
  scan_json=$(aws ecr describe-image-scan-findings \
    --region "$aws_region" \
    --repository-name "$repository_name" \
    --image-id "imageDigest=$image_digest" \
    --output json 2>/dev/null || true)
  scan_status=$(node -e "const raw=require('fs').readFileSync(0,'utf8').trim(); const x=raw ? JSON.parse(raw) : {}; console.log(x.imageScanStatus?.status ?? '')" <<<"$scan_json")
  [[ "$scan_status" == COMPLETE ]] && break
  if [[ "$scan_status" =~ ^(FAILED|UNSUPPORTED_IMAGE|SCAN_ELIGIBILITY_EXPIRED|FINDINGS_UNAVAILABLE)$ ]]; then
    echo "ECR_SCAN_FAILED status=$scan_status" >&2
    exit 78
  fi
  sleep 5
done
[[ "$scan_status" == COMPLETE ]] || {
  echo "ECR_SCAN_INCOMPLETE status=${scan_status:-unknown}" >&2
  exit 78
}
critical=$(node -e "const raw=require('fs').readFileSync(0,'utf8').trim(); const x=raw ? JSON.parse(raw) : {}; console.log(x.imageScanFindings?.findingSeverityCounts?.CRITICAL ?? 0)" <<<"$scan_json")
high=$(node -e "const raw=require('fs').readFileSync(0,'utf8').trim(); const x=raw ? JSON.parse(raw) : {}; console.log(x.imageScanFindings?.findingSeverityCounts?.HIGH ?? 0)" <<<"$scan_json")
[[ "$critical" == 0 && "$high" == 0 ]] || {
  echo "ECR_SCAN_REJECTED critical=$critical high=$high" >&2
  exit 78
}

release_tag="released-${release_sha}"
released_image="${repository_uri}:${release_tag}"
release_digest=$(aws ecr describe-images \
  --region "$aws_region" \
  --repository-name "$repository_name" \
  --image-ids "imageTag=$release_tag" \
  --query 'imageDetails[0].imageDigest' \
  --output text 2>/dev/null || true)
if [[ "$release_digest" == sha256:* ]]; then
  [[ "$release_digest" == "$image_digest" ]] || {
    echo "ECR_RELEASE_TAG_DIGEST_MISMATCH expected=$image_digest got=$release_digest" >&2
    exit 78
  }
else
  docker pull "$tagged_image" >/dev/null
  docker tag "$tagged_image" "$released_image"
  timeout 1800 docker push "$released_image" >/dev/null
fi
released_digest=$(aws ecr describe-images \
  --region "$aws_region" \
  --repository-name "$repository_name" \
  --image-ids "imageTag=$release_tag" \
  --query 'imageDetails[0].imageDigest' \
  --output text)
[[ "$released_digest" == "$image_digest" ]] || {
  echo "ECR_RELEASE_TAG_DIGEST_MISMATCH expected=$image_digest got=$released_digest" >&2
  exit 78
}

mkdir -p deployment/releases
node - "deployment/releases/zk-proof-worker-${release_sha}.json" "$release_sha" "$image_uri" "$critical" "$high" <<'NODE'
const fs = require('node:fs');
const [file, gitSha, image, critical, high] = process.argv.slice(2);
fs.writeFileSync(file, `${JSON.stringify({
  generatedAt: new Date().toISOString(),
  gitSha,
  image,
  provenance: {
    provider: process.env.CI_PIPELINE_ID ? 'gitlab' : 'manual',
    pipelineId: process.env.CI_PIPELINE_ID ?? null,
    jobId: process.env.CI_JOB_ID ?? null,
    pipelineUrl: process.env.CI_PIPELINE_URL ?? null,
  },
  verification: {
    ecrFindingSeverityCounts: { CRITICAL: Number(critical), HIGH: Number(high) },
  },
}, null, 2)}\n`);
NODE

echo "PUBLISHED $image_uri"
