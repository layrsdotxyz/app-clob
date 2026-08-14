#!/usr/bin/env bash
set -euo pipefail

echo 'CircleCI compatibility wrapper: authoritative deployment runs through protected GitLab main.' >&2
exec "$(dirname "$0")/deploy-zk-proof-worker.sh" "$@"
