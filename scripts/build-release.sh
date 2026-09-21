#!/usr/bin/env bash
set -euo pipefail
: "${IMAGE:?}" "${TAG:?}" "${IDENTITY:?}"
docker build --pull --platform linux/amd64 \
  --label "org.opencontainers.image.source=https://github.com/$GITHUB_REPOSITORY" \
  --label "org.opencontainers.image.revision=$GITHUB_SHA" \
  --label "demo.run=$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" -t "$IMAGE:$TAG" .
docker push "$IMAGE:$TAG"
docker pull "$IMAGE:$TAG"
REF=$(docker image inspect "$IMAGE:$TAG" --format '{{index .RepoDigests 0}}')
export REF
printf '%s\n' "$REF" > evidence/image.txt
bash scripts/expect-rejection.sh unsigned-before-signing 'no signatures|no matching signatures|no valid signatures|no signature found' \
  bash scripts/verify-image.sh "$REF" "$IDENTITY"
trivy image --scanners vuln --format json --output evidence/scan.json "$REF"
trivy image --format cyclonedx --output evidence/sbom.cdx.json "$REF"
python3 scripts/gate.py evidence/scan.json --image "$REF" --output evidence/build-decision.json
python3 scripts/evidence.py generate --image "$REF"
cosign sign --yes "$REF"
cosign attest --yes --type cyclonedx --predicate evidence/sbom.cdx.json "$REF"
cosign attest --yes --type slsaprovenance1 --predicate evidence/provenance.json "$REF"
cosign attest --yes --type https://trusted-container-pipeline.dev/attestations/scan/v1 \
  --predicate evidence/scan-predicate.json "$REF"

# Separate benign fixture images are never promoted as approved releases.
for variant in unsigned missing-provenance blocked-scan; do
  context="$RUNNER_TEMP/$variant"
  mkdir -p "$context"
  printf 'FROM %s\nCOPY marker.txt /demo-variant.txt\n' "$REF" > "$context/Dockerfile"
  printf 'BENIGN ADMISSION TEST FIXTURE: %s\n' "$variant" > "$context/marker.txt"
  docker build -t "$IMAGE:$variant-$TAG" "$context"
  docker push "$IMAGE:$variant-$TAG"
  docker pull "$IMAGE:$variant-$TAG"
  variant_ref=$(docker image inspect "$IMAGE:$variant-$TAG" --format '{{index .RepoDigests 0}}')
  printf '%s\n' "$variant_ref" > "evidence/$variant-image.txt"
  if [[ "$variant" == unsigned ]]; then continue; fi
  cosign sign --yes "$variant_ref"
  trivy image --format cyclonedx --output "evidence/$variant-sbom.json" "$variant_ref"
  cosign attest --yes --type cyclonedx --predicate "evidence/$variant-sbom.json" "$variant_ref"
  if [[ "$variant" == missing-provenance ]]; then
    trivy image --scanners vuln --format json --output evidence/missing-scan-report.json "$variant_ref"
    python3 scripts/gate.py evidence/missing-scan-report.json --image "$variant_ref" --output evidence/missing-decision.json
    python3 - <<'PY'
import json, os
from pathlib import Path
from scripts.evidence import scan_predicate
d = json.loads(Path('evidence/missing-decision.json').read_text())
Path('evidence/missing-scan.json').write_text(json.dumps(scan_predicate(d, os.environ['GITHUB_SHA'])))
PY
    cosign attest --yes --type https://trusted-container-pipeline.dev/attestations/scan/v1 \
      --predicate evidence/missing-scan.json "$variant_ref"
  fi
  if [[ "$variant" == blocked-scan ]]; then
    # Truthfully label the provenance as a fixture transform, never an approved build.
    python3 - <<'PY'
import json, os
from pathlib import Path
from scripts.evidence import provenance, scan_predicate
p = provenance(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'],
               os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'], 'blocked-scan')
Path('evidence/blocked-provenance.json').write_text(json.dumps(p))
decision = {'image': Path('evidence/blocked-scan-image.txt').read_text().strip(),
            'decision': 'BLOCK', 'counts': {'CRITICAL': 1},
            'block_severities': json.loads(Path('policy/release.json').read_text())['block_severities'],
            'violations': [{'VulnerabilityID': 'DEMO-SYNTHETIC-CRITICAL', 'Severity': 'CRITICAL'}]}
Path('evidence/blocked-scan.json').write_text(json.dumps(scan_predicate(decision, os.environ['GITHUB_SHA'], fixture=True)))
PY
    cosign attest --yes --type slsaprovenance1 --predicate evidence/blocked-provenance.json "$variant_ref"
    cosign attest --yes --type https://trusted-container-pipeline.dev/attestations/scan/v1 \
      --predicate evidence/blocked-scan.json "$variant_ref"
  fi
done
python3 - <<'PY'
import json, os
from pathlib import Path
data = {'image': os.environ['REF'], 'sourceCommit': os.environ['GITHUB_SHA'],
        'runId': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT']}
for key, variant in [('unsigned','unsigned'),('missingProvenance','missing-provenance'),('blockedScan','blocked-scan')]:
    data[key] = Path(f'evidence/{variant}-image.txt').read_text().strip()
Path('evidence/release.json').write_text(json.dumps(data, indent=2))
PY
echo 'PASS: approved image and three isolated admission-test fixtures published' | tee -a evidence/scenarios.txt
