# Build type: trusted-container-pipeline

This project emits a SLSA provenance v1 predicate and signs it with Cosign.
It is workflow-generated provenance, not an independent SLSA certification or
a claim of SLSA Build Level 3 isolation.

## Definition

- Builder: this repository's `.github/workflows/pipeline.yml` on `main`.
- Inputs: checked-out source commit, `Dockerfile`, pinned Python base-image index,
  Linux/amd64 platform and named variant.
- Output subject: the exact GHCR image digest passed to `cosign attest`.
- Dependencies: source commit and pinned base index digest.
- Invocation: authenticated GitHub workflow run ID and attempt.
- Approved variant: a Docker build of the repository's Dockerfile.
- Test variants: benign marker files added to the approved image. A fixture's
  provenance names its variant and is never treated as an approved build.

The original source commit identifies both the source and build script. Build
tool binaries and the hosted runner remain trusted dependencies; this is not a
complete hermetic dependency inventory. Pinning the base prevents a tag from
silently changing the base, but it does not make the whole build bit-reproducible.

## Verification

The deployment workflow verifies the certificate identity and issuer, attestation
signature and subject digest, then checks the predicate against the authenticated
upstream run: source repository/commit, main branch, builder, run ID/attempt,
platform and reviewed base pin. It requires a recent signed scan matching the
current policy and performs a fresh scan itself.

Kyverno separately verifies image signatures, signed SBOM, provenance source/run/base
and the signed scan policy in the Kubernetes API admission path. The scan's
blocked severity counts must all be zero and its policy hash must match the
same `policy/release.json` used by CI. Missing values do not default to success.

The signed failing fixture is explicitly synthetic and has `demoFixture: true`,
`decision: BLOCK` and a Critical count of one. Admission rejects it under
`trusted-scan`; it does not represent a real discovered CVE.
