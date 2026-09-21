# Learning guide

## 1. Pinning and image identity

Read the first line of `Dockerfile`. The human-readable Python tag is followed
by an immutable digest. Docker Hub supplies the pinned base; the workflow adds
this repository's API and publishes a different image digest to GHCR.

Compare the approved and unsigned fixture image digests in build evidence. A
benign marker file changes the output digest, so the approved image's signature
cannot authorize the changed image.

Exercise: propose a base-digest update through a PR. Explain why a tag-only update
cannot change a digest-pinned build and why the new pin needs another scan.

## 2. Signing identity

The trusted signer is this repository's `pipeline.yml` workflow on `main`, with
GitHub Actions as the OIDC issuer. Cosign creates short-lived signing credentials;
there is no long-lived signing key in repository secrets.

The deployment workflow can read packages and verify evidence but cannot request
an OIDC signing token or publish signatures. Find these permission differences
in the two workflow files.

## 3. SBOM versus provenance versus scan

- SBOM: what software is inside the image?
- Provenance: which source, base and workflow invocation produced the image?
- Scan decision: what did the vulnerability policy conclude about that digest?

All three are signed statements bound to the image digest. Inspect their JSON
predicates in build evidence and the verified envelopes in deployment evidence.
They answer different questions and none proves that the application is safe.

## 4. Follow the deployment trust checks

Read `validate-handoff.py`, `verify-release.sh` and `evidence.py` in that order.
The artifact handoff is only a pointer, not an authorization decision. The deployer
checks the upstream run through GitHub's authenticated API, accepts only digest
references in its own image repository, then verifies signed claims before running
any image. A valid signature from the wrong workflow identity is rejected.

Exercise: use the unit tests to see why a different commit, base, run attempt,
image digest, policy hash or stale scan is rejected.

## 5. Change the severity policy

The baseline blocks Critical findings. Change `policy/release.json` to also block
High through a reviewed PR, then build again. Read the actual scan and remediate
any blocked packages. `render_admission.py` uses that same policy file to generate
Kubernetes conditions, so there is no second severity list to forget to update.

The signed Critical fixture is marked synthetic and must not be presented as a
real discovered CVE. It tests whether the cluster rejects an authenticated but
noncompliant statement.

## 6. Watch Kubernetes enforce the policy

Open the deployment run's admission results and rejection logs. Observe:

1. A complete compliant release creates a Ready Pod.
2. An unsigned image is denied.
3. A signed image missing only provenance is denied.
4. A signed synthetic failing scan is denied under `trusted-scan`.
5. A mutable image tag is denied.
6. An unsigned init container prevents admission even when the main container is approved.

Server-side dry runs reach the real admission webhook without starting rejected
containers. The successful Pod and `/health` check show the cluster was functional.

## 7. Explain the remaining limits

Can repository writers change the build and deployment policies? Yes. Can the
demo job edit cluster policy? Yes. Can a trusted compromised builder lie? Yes.
This is why independent platform-owned admission policy, branch protection,
required review and restricted production RBAC matter.

The cluster is temporary and bound to one expected build run. Production needs
ongoing scanning, freshness/cache handling and policies across all relevant
namespaces. This project does not certify a SLSA level.

## Troubleshooting

| Symptom | What to inspect |
|---|---|
| Build blocks on a real vulnerability | Scan JSON, package and fixed-version fields; update and rebuild |
| Handoff rejected | Upstream event, branch, repo, commit and run attempt |
| Provenance rejected | Expected base pin, source commit, builder and run ID |
| Old build rejected | Scan age or changed policy/base pin; make a fresh build |
| GHCR access denied | Package access for this repository; no broad PAT is required |
| Admission setup fails | Cluster setup log and Kyverno controller/pod diagnostics |
| Negative test does not show a policy denial | Treat as inconclusive/failure, not a security success |
| Checksum mismatch | Stop and investigate the upstream asset; never bypass the check |

## Portfolio demo

Show both workflow runs. Open signed provenance, point to its source commit and
base digest, then show the Kubernetes rejection logs and the approved Pod's health
response. Explain that signing establishes identity and integrity while admission
adds enforcement. Discuss one remaining trust boundary instead of claiming that
the pipeline makes every signed image safe.
