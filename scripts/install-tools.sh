#!/usr/bin/env bash
set -euo pipefail
# Release asset hashes reviewed from the upstream GitHub release metadata.
# These pins are an explicit trust bootstrap, not independent proof of provenance.
mkdir -p .tools
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz \
  -o .tools/trivy.tar.gz
echo '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a  .tools/trivy.tar.gz' | sha256sum --check
tar -xzf .tools/trivy.tar.gz -C .tools trivy
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 \
  -o .tools/cosign
echo '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71  .tools/cosign' | sha256sum --check
chmod +x .tools/cosign .tools/trivy
if [[ -n "${GITHUB_PATH:-}" ]]; then
  realpath .tools >> "$GITHUB_PATH"
fi
.tools/trivy --version
.tools/cosign version
