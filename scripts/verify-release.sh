#!/usr/bin/env bash
set -euo pipefail
: "${REF:?}" "${IDENTITY:?}" "${SOURCE_SHA:?}" "${UPSTREAM_RUN_ID:?}" "${BUILD_ATTEMPT:?}"
bash scripts/verify-image.sh "$REF" "$IDENTITY" > evidence/verified-signature.json
for spec in 'provenance|https://slsa.dev/provenance/v1' 'scan|https://trusted-container-pipeline.dev/attestations/scan/v1' 'sbom|cyclonedx'; do
  name=${spec%%|*}; type=${spec#*|}
  cosign verify-attestation --new-bundle-format=false --type "$type" --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$REF" \
    > "evidence/verified-$name.jsonl"
done
python3 scripts/evidence.py verify --image "$REF" --commit "$SOURCE_SHA" \
  --run-id "$UPSTREAM_RUN_ID" --attempt "$BUILD_ATTEMPT"
trivy image --scanners vuln --format json --output evidence/pre-deploy-scan.json "$REF"
python3 scripts/gate.py evidence/pre-deploy-scan.json --image "$REF" --output evidence/deploy-decision.json
