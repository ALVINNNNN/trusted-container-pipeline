"""Exercise real Kubernetes admission; negative cases use server-side dry runs."""
import json
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

out = Path("evidence")
manifest = json.loads(Path("handoff/release.json").read_text())


def pod(name, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "trusted-demo"},
        "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "imagePullSecrets": [{"name": "registry-read"}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "api", "image": image, "ports": [{"containerPort": 8080}],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "50m", "memory": "32Mi"},
                              "limits": {"cpu": "500m", "memory": "128Mi"}},
                "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}}}]}}


def apply(resource, dry_run=True):
    cmd = ["kubectl", "create", "-f", "-"] + (["--dry-run=server"] if dry_run else [])
    return subprocess.run(cmd, input=json.dumps(resource), text=True, capture_output=True, timeout=120)


def denied(name, resource, rule):
    result = apply(resource)
    logs = result.stdout + result.stderr
    (out / f"admission-{name}.log").write_text(logs)
    if result.returncode == 0 or "denied the request" not in logs or "trusted-release" not in logs or rule not in logs:
        raise RuntimeError(f"{name}: expected an explicit {rule} admission denial, got:\n{logs}")
    print(f"PASS: Kubernetes rejected {name} ({rule})", flush=True)


# Policy readiness can precede webhook reconciliation. Probe without executing a Pod.
for attempt in range(30):
    result = apply(pod("readiness-canary", manifest["unsigned"]))
    if result.returncode != 0 and "trusted-release" in result.stderr and "trusted-signature" in result.stderr:
        break
    time.sleep(2)
else:
    raise RuntimeError("Admission webhook never enforced the unsigned-image policy")

# A successful real deployment first distinguishes policy enforcement from a broken registry/webhook.
approved = pod("approved", manifest["image"])
result = apply(approved, dry_run=False)
(out / "admission-approved.log").write_text(result.stdout + result.stderr)
if result.returncode:
    raise RuntimeError(result.stderr)
subprocess.run(["kubectl", "-n", "trusted-demo", "wait", "--for=condition=Ready", "pod/approved", "--timeout=180s"], check=True)
print("PASS: Kubernetes admitted the signed, compliant image and the Pod became Ready", flush=True)

denied("unsigned-image", pod("unsigned", manifest["unsigned"]), "trusted-signature")
denied("missing-provenance", pod("missing-provenance", manifest["missingProvenance"]), "trusted-provenance")
denied("signed-critical-fixture", pod("blocked-scan", manifest["blockedScan"]), "trusted-scan")
denied("mutable-tag", pod("mutable", manifest["image"].split("@")[0] +
       f":run-{manifest['runId']}-{manifest['attempt']}"), "digest")
init_pod = pod("unsigned-init", manifest["image"])
init_pod["spec"]["initContainers"] = [{"name": "init", "image": manifest["unsigned"]}]
denied("unsigned-init-container", init_pod, "trusted-signature")

with open(out / "port-forward.log", "w") as logs:
    forward = subprocess.Popen(["kubectl", "-n", "trusted-demo", "port-forward", "pod/approved", "18080:8080"],
                               stdout=logs, stderr=logs)
    try:
        for attempt in range(30):
            try:
                with urlopen("http://127.0.0.1:18080/health", timeout=2) as response:
                    data = json.load(response)
                if data != {"status": "ok"}:
                    raise RuntimeError("Unexpected health response")
                (out / "kubernetes-health.json").write_text(json.dumps(data))
                break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError("Kubernetes health check timed out")
    finally:
        forward.terminate()
        forward.wait(timeout=10)
print("PASS: admitted Kubernetes Pod returned a healthy API response", flush=True)
