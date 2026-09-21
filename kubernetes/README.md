# Kubernetes admission demo

`Deploy Verified Release` creates a disposable kind cluster, installs checksum-pinned
Kyverno v1.19.1 and renders `trusted-release` from `scripts/render_admission.py`.
The generated policy is uploaded as `admission-policy.json` in deployment evidence.

## Enforcement

The policy applies to Pods in the **trusted-demo** namespace, including their
regular, init and ephemeral container image fields. Controllers such as Deployments
are ultimately gated when they create Pods; controller-template autogeneration is
disabled for this focused demo. The policy is not cluster-wide.

- Require the exact project registry/repository and an immutable digest.
- Require the approved main build-workflow signing identity and GitHub OIDC issuer.
- Verify signed SBOM and SLSA-format provenance for the expected source, base and run.
- Verify the signed scan decision, reviewed policy hash and zero findings at each
  blocked severity. CI and admission both derive thresholds from `policy/release.json`.
- Reject synthetic scan attestations and fail closed on webhook errors.

## Tests

The workflow deploys one real approved Pod and checks its health. It then uses
server-side dry runs to prove that unsigned images, missing provenance, a signed
failing scan fixture, mutable tags and unsigned init containers are denied.
Tests require explicit policy denials; a generic connection error is not a pass.

Private GHCR packages work through the temporary deployment token, which has
`packages: read` only. Docker registry secrets exist only in the disposable cluster
and are never included in uploaded evidence. No signing permission is granted to
the deployment workflow. The cluster is removed on success or failure.

## Scope and limitations

Kyverno ClusterPolicy is a supported but deprecated API in this pinned version;
migration to ImageValidatingPolicy/CEL is a future compatibility exercise.
The Kubernetes node image and installer assets are pinned. The upstream controller
manifest uses versioned controller-image tags; full transitive image digest pinning
would be an additional hardening step.

This workflow is a demo cluster administrator and installs its own policy. It
demonstrates enforcement, not separation from the cluster owner. For production,
platform administrators should own policy installation and ordinary deployers
must not edit policies, webhook configuration, namespaces or privileged RBAC.
Protect `main` and the deployment environment and isolate the policy repository.

The temporary cluster's policy is bound to one expected build run. Deployment also
requires scan age <= 24 hours and rescans the image. A long-lived admission deployment
needs a freshness/refresh policy and consideration of Kyverno's verification cache;
this example does not continuously rescan running Pods.

Do not apply the installer to an existing cluster: it is designed for the workflow's
new kind cluster. There is no persistent Kubernetes cluster or cloud bill created.
