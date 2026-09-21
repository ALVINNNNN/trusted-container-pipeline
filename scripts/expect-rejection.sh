#!/usr/bin/env bash
set -euo pipefail
name="${1:?scenario name}"; pattern="${2:?expected error regex}"; shift 2
mkdir -p evidence
if "$@" > "evidence/$name.log" 2>&1; then
  echo "FAIL: $name unexpectedly succeeded" >&2
  exit 1
fi
if ! grep -Eiq -- "$pattern" "evidence/$name.log"; then
  cat "evidence/$name.log"
  echo "INCONCLUSIVE: $name failed for an unexpected reason (possibly infrastructure)" >&2
  exit 1
fi
echo "PASS: $name rejected for the expected reason" | tee -a evidence/scenarios.txt
