"""Render Kyverno policies from the SAME reviewed severity policy used by CI."""
import copy
import json
import os
from pathlib import Path
from scripts.evidence import policy_hash, base_image, SCAN_TYPE


def policies(repo, commit, run_id, attempt):
    identity = f"https://github.com/{repo}/.github/workflows/pipeline.yml@refs/heads/main"
    attestors = [{"entries": [{"keyless": {"subject": identity,
        "issuer": "https://token.actions.githubusercontent.com", "rekor": {"url": "https://rekor.sigstore.dev"}}}]}]
    match = {"any": [{"resources": {"kinds": ["Pod"], "namespaces": ["trusted-demo"]}}]}

    def condition(key, value):
        return {"key": "{{ " + key + " }}", "operator": "Equals", "value": value}

    def verification():
        return {"imageReferences": ["*"], "failureAction": "Enforce", "required": True,
                "mutateDigest": False, "verifyDigest": True,
                "imageRegistryCredentials": {"secrets": ["registry-read"]}}

    signature = verification()
    signature["attestors"] = attestors
    provenance = verification()
    provenance["attestations"] = [{"predicateType": "https://slsa.dev/provenance/v1", "attestors": attestors,
        "conditions": [{"all": [
            condition("buildDefinition.externalParameters.repository", f"https://github.com/{repo}"),
            condition("buildDefinition.externalParameters.ref", "refs/heads/main"),
            condition("buildDefinition.externalParameters.sourceCommit", commit),
            condition("runDetails.builder.id", identity),
            condition("runDetails.metadata.invocationId", f"https://github.com/{repo}/actions/runs/{run_id}/attempts/{attempt}"),
            condition("buildDefinition.resolvedDependencies[1].digest.sha256", base_image().split('sha256:')[1])]}]}]
    scan = verification()
    conditions = [condition("decision", "ALLOW"), condition("demoFixture", False),
                  condition("policySha256", policy_hash()), condition("sourceCommit", commit)]
    for severity in json.loads(Path("policy/release.json").read_text())["block_severities"]:
        conditions.append(condition(f"counts.{severity}", 0))
    scan["attestations"] = [{"predicateType": SCAN_TYPE, "attestors": attestors,
                             "conditions": [{"all": conditions}]}]
    sbom = verification()
    sbom["attestations"] = [{"predicateType": "https://cyclonedx.org/bom", "attestors": attestors}]
    registry_regex = "^ghcr\\.io/" + repo.lower() + "@sha256:[a-f0-9]{64}$"
    restrict = {"name": "require-repository-and-digest", "match": match,
        "validate": {"failureAction": "Enforce", "message": "Use only this repository's immutable SHA-256 images.",
            "foreach": [{"list": "request.object.spec.[containers, initContainers, ephemeralContainers][]",
                "deny": {"conditions": {"any": [{"key": "{{ regex_match('" + registry_regex + "', element.image) }}",
                                                 "operator": "Equals", "value": False}]}}}]}}
    rules = [restrict]
    for name, verification_rule in (("trusted-signature", signature), ("trusted-provenance", provenance),
                                    ("trusted-scan", scan), ("trusted-sbom", sbom)):
        rules.append({"name": name, "match": copy.deepcopy(match), "verifyImages": [verification_rule]})
    return {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
        "metadata": {"name": "trusted-release", "annotations": {"pod-policies.kyverno.io/autogen-controllers": "none"}},
        "spec": {"background": False, "webhookConfiguration": {"failurePolicy": "Fail", "timeoutSeconds": 30}, "rules": rules}}


if __name__ == "__main__":
    print(json.dumps(policies(os.environ["GITHUB_REPOSITORY"], os.environ["SOURCE_SHA"],
                             os.environ["UPSTREAM_RUN_ID"], os.environ["BUILD_ATTEMPT"]), indent=2))
