#!/usr/bin/env bash
set -euo pipefail
image="${1:?image digest}"; identity="${2:?signing identity}"
# Always verify immediately before execution; never accept a mutable tag here.
bash scripts/verify-image.sh "$image" "$identity" > evidence/pre-deploy-verification.json
name="trusted-pipeline-${GITHUB_RUN_ID:-local}"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run --detach --name "$name" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --cpus 0.5 -p 127.0.0.1:8080:8080 "$image"
for attempt in {1..20}; do
  if curl --fail --silent http://127.0.0.1:8080/health > evidence/health.json; then
    python3 -c 'import json; assert json.load(open("evidence/health.json")) == {"status": "ok"}'
    echo 'PASS: verified image deployed and health check succeeded' | tee -a evidence/scenarios.txt
    exit 0
  fi
  sleep 1
done
docker logs "$name"
echo 'FAIL: API health check timed out' >&2
exit 1
