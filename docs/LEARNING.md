# Learning guide

## 1. Understand the image identity

Open `evidence/image.txt` from a successful workflow artifact. The part after
`@sha256:` identifies the image content. A tag is a name that can be moved;
the digest changes when the content changes.

Compare `modified-image.txt` with `image.txt`. The modified demo adds only a
harmless marker file, yet the original signature cannot approve the new digest.

## 2. Understand the signer

The expected signer is:

```
https://github.com/ALVINNNNN/trusted-container-pipeline/.github/workflows/pipeline.yml@refs/heads/main
```

GitHub gives the job a short-lived OIDC identity. Cosign obtains a signing
certificate through Sigstore and signs the image. The verifier checks the
signature, image digest, exact certificate identity, issuer and transparency
evidence. No long-lived signing key is stored in this repo.

Open `wrong-identity.log`: why should a cryptographically valid signature still
be rejected? Because the signer must also match the release's trust policy.

## 3. Understand the SBOM

Open `sbom.cdx.json`. Find the Python version and several operating-system
packages. The SBOM answers what is inside the image. The scan adds vulnerability
intelligence. The signed attestation binds the inventory statement to an image
digest and signer. None of these alone proves the application is secure.

## 4. Change a policy deliberately

Create a branch, add HIGH to `block_severities`, and open a PR. Read the unit-test
results, then review and merge the policy if appropriate. Main runs the live
scan. Compare the decision counts with the individual Trivy records.

The deterministic fixture uses `DEMO-CRITICAL-001`, not a real CVE. It proves that
the gate handles a Critical record. Real vulnerability findings are exclusively
in the actual scan reports. Never present the synthetic fixture as an exploited
vulnerability or as evidence of a vulnerable production service.

## 5. Practice fail-closed behavior

Run the unit tests locally. They verify that missing results, malformed fields,
an unexpected image and mutable tags do not pass. Delete `Results` from a copy
of a real scan and run `scripts/gate.py`: it should return ERROR (exit code 2),
not ALLOW. Policy violations use exit code 1; successful evaluation uses 0.

## 6. Read the trust boundary

Could a repository writer remove the verification command? Yes. Could a
compromised trusted workflow sign a malicious image? Yes. This demonstrates
why protected branches and independently enforced deployment policies matter.
The next iteration should put the trust policy outside the application's
writable repository and require review for policy changes.

## Troubleshooting

| Symptom | Next step |
|---|---|
| Package push denied | Check GHCR package/repository access and organization Actions policies |
| Real Critical finding | Read package and fixed-version information, remediate and rebuild |
| No fixed version | Assess risk and seek a safe alternate image/version; this baseline still blocks it |
| Negative demo is INCONCLUSIVE | Inspect its log; registry/network/service failure is not a successful security test |
| Signing or verification service unavailable | Keep the release blocked; retry after service recovery |
| Tool checksum mismatch | Stop and investigate upstream release integrity; never bypass the checksum |
| Identity mismatch on a fork | Workflow builds the expected identity from `github.repository`; verify the branch and workflow path |

## A 90-second portfolio demonstration

1. Explain the problem: scanning does not establish who built or signed an image.
2. Show the workflow graph and exact image digest.
3. Show the unsigned, wrong-identity and modified-image rejection logs.
4. Show the signed SBOM verification and vulnerability decision.
5. End with the verified deployment's health response and explain one limitation.

Describe results only after the corresponding workflow steps succeed. Use the
actual run URL and artifact logs when discussing the project on LinkedIn.
