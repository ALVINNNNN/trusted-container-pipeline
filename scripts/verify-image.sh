#!/usr/bin/env bash
set -euo pipefail
image="${1:?Usage: verify-image.sh IMAGE@sha256:DIGEST IDENTITY}"
identity="${2:?Expected signing workflow identity is required}"
if [[ ! "$image" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]]; then
  echo 'BLOCK: an immutable SHA-256 image reference is required' >&2
  exit 2
fi
cosign verify --new-bundle-format=true "$image" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
