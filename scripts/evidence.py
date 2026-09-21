"""Generate and validate signed build metadata. Verification happens via Cosign first."""
import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

SCAN_TYPE = "https://trusted-container-pipeline.dev/attestations/scan/v1"
PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"


def policy_hash(path="policy/release.json"):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def base_image(path="Dockerfile"):
    value = Path(path).read_text().splitlines()[0].split()[1]
    if not re.fullmatch(r"python:[^@\s]+@sha256:[0-9a-f]{64}", value):
        raise ValueError("The Python base image must be pinned by digest")
    return value


def provenance(repo, commit, run_id, attempt, variant="approved"):
    workflow = f"https://github.com/{repo}/.github/workflows/pipeline.yml@refs/heads/main"
    base = base_image()
    return {
        "buildDefinition": {
            "buildType": f"https://github.com/{repo}/blob/main/docs/BUILD-TYPE.md",
            "externalParameters": {"repository": f"https://github.com/{repo}",
                "ref": "refs/heads/main", "sourceCommit": commit, "variant": variant,
                "dockerfile": "Dockerfile", "platform": "linux/amd64"},
            "internalParameters": {},
            "resolvedDependencies": [
                {"uri": f"git+https://github.com/{repo}@refs/heads/main", "digest": {"gitCommit": commit}},
                {"uri": "pkg:docker/library/" + base.split("@")[0],
                 "digest": {"sha256": base.split("sha256:")[1]}}]},
        "runDetails": {"builder": {"id": workflow}, "metadata": {
            "invocationId": f"https://github.com/{repo}/actions/runs/{run_id}/attempts/{attempt}"}}}


def scan_predicate(decision, commit, *, fixture=False):
    return {**decision, "counts": {s: decision["counts"].get(s, 0)
            for s in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")},
            "policySha256": policy_hash(), "sourceCommit": commit,
            "scannedAt": datetime.now(timezone.utc).isoformat(), "demoFixture": fixture}


def statements(text):
    # Cosign emits newline-delimited JSON objects, occasionally an array.
    decoder, offset, result = json.JSONDecoder(), 0, []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        item, offset = decoder.raw_decode(text, offset)
        for envelope in item if isinstance(item, list) else [item]:
            result.append(json.loads(base64.b64decode(envelope["payload"], validate=True)))
    if not result:
        raise ValueError("No verified statements")
    return result


def check_statement(statement, predicate_type, image):
    digest = image.split("@sha256:")[1]
    if statement.get("predicateType") != predicate_type:
        raise ValueError("Unexpected predicate type")
    if not any(s.get("digest", {}).get("sha256") == digest for s in statement.get("subject", [])):
        raise ValueError("Attestation subject is not the requested image")
    return statement["predicate"]


def check_provenance(p, repo, commit, run_id, attempt):
    expected = provenance(repo, commit, run_id, attempt)
    if p != expected:
        raise ValueError("Provenance differs from expected source, base digest, builder or workflow run")


def check_scan(p, image, commit):
    policy = json.loads(Path("policy/release.json").read_text())
    if (p.get("image") != image or p.get("decision") != "ALLOW"
        or p.get("demoFixture") is not False or p.get("sourceCommit") != commit
        or p.get("policySha256") != policy_hash()
        or p.get("block_severities") != policy["block_severities"]):
        raise ValueError("Scan attestation does not match release policy")
    for severity in policy["block_severities"]:
        if type(p.get("counts", {}).get(severity)) is not int or p["counts"][severity] != 0:
            raise ValueError("Signed scan exceeds vulnerability policy")
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(p["scannedAt"])).total_seconds()
    if not 0 <= age <= 86400:
        raise ValueError("Signed scan is stale or future-dated")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["generate", "verify"])
    parser.add_argument("--image", required=True)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    args = parser.parse_args()
    if args.mode == "generate":
        decision = json.loads(Path("evidence/build-decision.json").read_text())
        Path("evidence/provenance.json").write_text(json.dumps(provenance(args.repo, args.commit, args.run_id, args.attempt), indent=2))
        Path("evidence/scan-predicate.json").write_text(json.dumps(scan_predicate(decision, args.commit), indent=2))
    else:
        for kind, predicate_type in (("provenance", PROVENANCE_TYPE), ("scan", SCAN_TYPE)):
            candidates = statements(Path(f"evidence/verified-{kind}.jsonl").read_text())
            accepted = False
            for statement in candidates:
                try:
                    p = check_statement(statement, predicate_type, args.image)
                    if kind == "provenance":
                        check_provenance(p, args.repo, args.commit, args.run_id, args.attempt)
                    else:
                        check_scan(p, args.image, args.commit)
                    accepted = True
                    break
                except (ValueError, KeyError, TypeError):
                    continue
            if not accepted:
                raise ValueError(f"No acceptable signed {kind} statement")
        print("PASS: signed provenance and scan match source, base, run, digest and policy")


if __name__ == "__main__":
    main()
