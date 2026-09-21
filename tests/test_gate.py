import unittest
from scripts.gate import evaluate

IMAGE = "ghcr.io/example/app@sha256:" + "a" * 64


def report():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": IMAGE,
            "Results": [{"Target": "alpine", "Vulnerabilities": []}]}


class GateTests(unittest.TestCase):
    policy = {"block_severities": ["CRITICAL"]}

    def test_clean_report_allowed(self):
        self.assertEqual(evaluate(report(), self.policy, IMAGE)["decision"], "ALLOW")

    def test_critical_blocked_with_or_without_fix(self):
        for fix in ("", "2.0"):
            with self.subTest(fix=fix):
                data = report()
                data["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "DEMO-CRITICAL",
                    "Severity": "CRITICAL", "PkgName": "synthetic-fixture", "FixedVersion": fix}]
                self.assertEqual(evaluate(data, self.policy, IMAGE)["decision"], "BLOCK")

    def test_high_visible_but_allowed_by_baseline(self):
        data = report()
        data["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "DEMO-HIGH", "Severity": "HIGH"}]
        result = evaluate(data, self.policy, IMAGE)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertEqual(result["counts"], {"HIGH": 1})

    def test_stricter_policy_blocks_high(self):
        data = report()
        data["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "DEMO-HIGH", "Severity": "HIGH"}]
        self.assertEqual(evaluate(data, {"block_severities": ["HIGH", "CRITICAL"]}, IMAGE)["decision"], "BLOCK")

    def test_wrong_image_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(report(), self.policy, IMAGE[:-1] + "b")

    def test_mutable_tag_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(report(), self.policy, "ghcr.io/example/app:latest")

    def test_missing_or_empty_results_rejected(self):
        for results in (None, [], {}, "broken"):
            data = report()
            data["Results"] = results
            with self.subTest(results=results), self.assertRaises(ValueError):
                evaluate(data, self.policy, IMAGE)

    def test_malformed_report_rejected(self):
        for key in ("SchemaVersion", "ArtifactType", "ArtifactName"):
            data = report()
            del data[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                evaluate(data, self.policy, IMAGE)

    def test_malformed_vulnerability_rejected(self):
        for finding in ({}, {"VulnerabilityID": "DEMO", "Severity": "Typo"}, "broken"):
            data = report()
            data["Results"][0]["Vulnerabilities"] = [finding]
            with self.subTest(finding=finding), self.assertRaises(ValueError):
                evaluate(data, self.policy, IMAGE)

    def test_non_list_vulnerabilities_rejected(self):
        for findings in ({}, "", 0):
            data = report()
            data["Results"][0]["Vulnerabilities"] = findings
            with self.subTest(findings=findings), self.assertRaises(ValueError):
                evaluate(data, self.policy, IMAGE)

    def test_empty_or_invalid_policy_rejected(self):
        for policy in ({}, {"block_severities": []}, {"block_severities": ["Typo"]}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                evaluate(report(), policy, IMAGE)


if __name__ == "__main__":
    unittest.main()
