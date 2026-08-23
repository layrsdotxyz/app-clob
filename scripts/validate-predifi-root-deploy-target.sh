#!/usr/bin/env bash
set -euo pipefail

ci_file=.gitlab-ci.yml
deploy_file=deployment/deploy-zk-proof-worker.sh

for forbidden in \
  255638996474 \
  255638996474.dkr.ecr.us-east-1.amazonaws.com/layrsv2-production-zk-proof-worker \
  arn:aws:iam::255638996474:role/layrsv2-production-deployer
do
  if grep -Fq "$forbidden" "$ci_file" "$deploy_file"; then
    echo "OLD_LAYRS_DEPLOY_TARGET_PRESENT:$forbidden" >&2
    exit 1
  fi
done

for required in \
  arn:aws:iam::082223548516:role/layrs-production-deployer \
  082223548516.dkr.ecr.us-east-1.amazonaws.com/layrs-production-zk-proof-worker \
  arn:aws:sts::082223548516:assumed-role/layrs-production-deployer/ \
  layrs-production-zk-image-builder \
  layrs-production-082223548516-us-east-1-build-source \
  'aws codebuild start-build'
do
  grep -Fq "$required" "$ci_file" "$deploy_file" || {
    echo "PREDIFI_ROOT_DEPLOY_TARGET_MISSING:$required" >&2
    exit 1
  }
done

echo PREDIFI_ROOT_ZK_DEPLOY_TARGET_VALID
