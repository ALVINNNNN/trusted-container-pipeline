"""Deterministic demonstration, explicitly synthetic rather than a real CVE scan."""
import json
import subprocess
import sys
from pathlib import Path

image = "ghcr.io/demo/synthetic@sha256:" + "a" * 64
out = Path("evidence")
out.mkdir(exist_ok=True)
report = {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": image,
          "Results": [{"Target": "SYNTHETIC POLICY TEST - NOT A REAL SCAN", "Vulnerabilities": [
              {"VulnerabilityID": "DEMO-CRITICAL-001", "PkgName": "synthetic-package",
               "InstalledVersion": "1.0", "FixedVersion": "", "Severity": "CRITICAL"}]}]}
(out / "synthetic-critical.json").write_text(json.dumps(report, indent=2))
result = subprocess.run([sys.executable, "scripts/gate.py", str(out / "synthetic-critical.json"),
                         "--image", image, "--output", str(out / "synthetic-decision.json")],
                        capture_output=True, text=True)
(out / "synthetic-policy.log").write_text(result.stdout + result.stderr)
if result.returncode != 1 or json.loads(result.stdout)["decision"] != "BLOCK":
    raise SystemExit("FAIL: synthetic critical finding was not blocked")
print("PASS: synthetic critical finding blocked (not a real CVE finding)")
