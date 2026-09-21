"""Treat downloaded release metadata as untrusted data, never executable input."""
import json
import os
import re
from pathlib import Path

run = json.loads(Path("evidence/upstream-run.json").read_text())
repo = os.environ["GITHUB_REPOSITORY"]
run_id = os.environ["UPSTREAM_RUN_ID"]
if not (str(run["id"]) == run_id and run["conclusion"] == "success"
        and run["event"] in ("push", "workflow_dispatch") and run["head_branch"] == "main"
        and run["repository"]["full_name"] == repo and run["head_repository"]["full_name"] == repo
        and run["path"] == ".github/workflows/pipeline.yml"):
    raise SystemExit("Untrusted upstream workflow run")
manifest = json.loads(Path("handoff/release.json").read_text())
if manifest["sourceCommit"] != run["head_sha"] or manifest["runId"] != run_id or manifest["attempt"] != str(run["run_attempt"]):
    raise SystemExit("Release handoff does not match authenticated GitHub run metadata")
image_pattern = re.escape("ghcr.io/" + repo.lower()) + r"@sha256:[0-9a-f]{64}"
for key in ("image", "unsigned", "missingProvenance", "blockedScan"):
    if not re.fullmatch(image_pattern, manifest[key]):
        raise SystemExit("Unexpected registry, repository or mutable image reference")
if len({manifest[k] for k in ("image", "unsigned", "missingProvenance", "blockedScan")}) != 4:
    raise SystemExit("Demo image digests must be distinct")
if not re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]):
    raise SystemExit("Invalid commit")
with open(os.environ["GITHUB_ENV"], "a") as env:
    for key, value in {"REF": manifest["image"], "SOURCE_SHA": run["head_sha"],
                       "BUILD_ATTEMPT": str(run["run_attempt"])}.items():
        env.write(f"{key}={value}\n")
print("PASS: handoff matches a successful same-repository main build")
