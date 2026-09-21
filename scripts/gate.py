"""Fail-closed policy evaluation of a Trivy image report. No dependencies."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def evaluate(report, policy, image):
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Expected an immutable image reference with a SHA-256 digest")
    blocked = policy.get("block_severities")
    if not isinstance(blocked, list) or not blocked or not set(blocked) <= SEVERITIES:
        raise ValueError("Policy must contain valid, non-empty block_severities")
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        raise ValueError("Missing or unsupported Trivy image report schema")
    if report.get("ArtifactName") != image:
        raise ValueError("Scan report does not match the image being released")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Missing scan results; an empty report is not a clean scan")
    counts, violations = Counter(), []
    for result in results:
        if not isinstance(result, dict) or not result.get("Target"):
            raise ValueError("Malformed scan target")
        findings = result.get("Vulnerabilities")
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise ValueError("Malformed vulnerability list")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Malformed vulnerability record")
            severity = finding.get("Severity")
            if severity not in SEVERITIES or not finding.get("VulnerabilityID"):
                raise ValueError("Incomplete vulnerability record")
            counts[severity] += 1
            if severity in blocked:
                violations.append({k: finding.get(k, "") for k in
                                   ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity")})
    return {"image": image, "decision": "BLOCK" if violations else "ALLOW",
            "counts": dict(counts), "block_severities": blocked, "violations": violations}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--image", required=True)
    parser.add_argument("--policy", default="policy/release.json")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = evaluate(json.loads(Path(args.report).read_text()),
                          json.loads(Path(args.policy).read_text()), args.image)
    except (ValueError, TypeError, AttributeError, OSError) as exc:
        result = {"decision": "ERROR", "error": str(exc)}
    output = json.dumps(result, indent=2)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n")
    return {"ALLOW": 0, "BLOCK": 1, "ERROR": 2}[result["decision"]]


if __name__ == "__main__":
    raise SystemExit(main())
