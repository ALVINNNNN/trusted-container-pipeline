#!/usr/bin/env bash
set -euo pipefail
mkdir -p .tools
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 -o .tools/kind
echo 'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d  .tools/kind' | sha256sum --check
chmod +x .tools/kind
.tools/kind create cluster --name trusted-demo --wait 180s \
  --image kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/kyverno/kyverno/releases/download/v1.19.1/install.yaml -o .tools/kyverno.yaml
echo 'd3322cb346d3d42dd0f41e230b0d1d7bc5619960e1c36fdac4d9151d724b88e6  .tools/kyverno.yaml' | sha256sum --check
kubectl apply --server-side -f .tools/kyverno.yaml
kubectl -n kyverno wait --for=condition=Available deployment --all --timeout=300s
kubectl create namespace trusted-demo
# Ephemeral read-only job credentials. Never write secrets into evidence or logs.
for ns in kyverno trusted-demo; do
  kubectl -n "$ns" create secret generic registry-read --type=kubernetes.io/dockerconfigjson \
    --from-file=.dockerconfigjson="$HOME/.docker/config.json"
done
python3 -m scripts.render_admission > evidence/admission-policy.json
kubectl apply -f evidence/admission-policy.json
kubectl wait --for=condition=Ready clusterpolicy/trusted-release --timeout=120s
