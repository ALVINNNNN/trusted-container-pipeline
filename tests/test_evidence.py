import base64
import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from scripts.evidence import (provenance, scan_predicate, check_provenance, check_scan,
                              check_statement, statements, PROVENANCE_TYPE)
from scripts.render_admission import policies

REPO = "ALVINNNNN/trusted-container-pipeline"
SHA = "a" * 40
IMAGE = "ghcr.io/alvinnnnn/trusted-container-pipeline@sha256:" + "b" * 64


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.provenance = provenance(REPO, SHA, "123", "1")
        self.scan = scan_predicate({"image": IMAGE, "decision": "ALLOW", "counts": {},
                                  "block_severities": ["CRITICAL"], "violations": []}, SHA)

    def test_expected_provenance_accepted(self):
        check_provenance(self.provenance, REPO, SHA, "123", "1")

    def test_other_commit_run_and_attempt_rejected(self):
        for commit, run, attempt in (("c" * 40, "123", "1"), (SHA, "124", "1"), (SHA, "123", "2")):
            with self.subTest(commit=commit, run=run, attempt=attempt), self.assertRaises(ValueError):
                check_provenance(self.provenance, REPO, commit, run, attempt)

    def test_other_base_rejected(self):
        self.provenance["buildDefinition"]["resolvedDependencies"][1]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            check_provenance(self.provenance, REPO, SHA, "123", "1")

    def test_expected_scan_accepted(self):
        check_scan(self.scan, IMAGE, SHA)

    def test_critical_count_rejected_even_if_decision_says_allow(self):
        self.scan["counts"]["CRITICAL"] = 1
        with self.assertRaises(ValueError):
            check_scan(self.scan, IMAGE, SHA)

    def test_missing_count_rejected(self):
        del self.scan["counts"]["CRITICAL"]
        with self.assertRaises(ValueError):
            check_scan(self.scan, IMAGE, SHA)

    def test_tampered_policy_image_commit_and_fixture_rejected(self):
        for field, value in (("policySha256", "wrong"), ("image", "wrong"), ("sourceCommit", "wrong"),
                             ("demoFixture", True), ("decision", "BLOCK"), ("block_severities", [])):
            data = copy.deepcopy(self.scan)
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_scan(data, IMAGE, SHA)

    def test_stale_or_future_scan_rejected(self):
        for delta in (timedelta(days=-2), timedelta(hours=1)):
            self.scan["scannedAt"] = (datetime.now(timezone.utc) + delta).isoformat()
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                check_scan(self.scan, IMAGE, SHA)

    def test_wrong_subject_and_type_rejected(self):
        stmt = {"predicateType": PROVENANCE_TYPE, "subject": [{"digest": {"sha256": "b" * 64}}], "predicate": {}}
        self.assertEqual(check_statement(stmt, PROVENANCE_TYPE, IMAGE), {})
        for key, value in (("predicateType", "other"), ("subject", [])):
            bad = {**stmt, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_statement(bad, PROVENANCE_TYPE, IMAGE)

    def test_decode_multiple_verified_envelopes(self):
        envelope = {"payload": base64.b64encode(json.dumps({"predicate": {}}).encode()).decode()}
        self.assertEqual(len(statements(json.dumps(envelope) + "\n" + json.dumps(envelope))), 2)
        with self.assertRaises(ValueError):
            statements("")

    def test_kubernetes_uses_same_policy_and_covers_all_images(self):
        policy = policies(REPO, SHA, "123", "1")
        self.assertEqual(policy["spec"]["webhookConfiguration"]["failurePolicy"], "Fail")
        rules = policy["spec"]["rules"]
        for rule in rules[1:]:
            self.assertEqual(rule["verifyImages"][0]["imageReferences"], ["*"])
            self.assertTrue(rule["verifyImages"][0]["required"])
            self.assertEqual(rule["verifyImages"][0]["failureAction"], "Enforce")
        scan = next(r for r in rules if r["name"] == "trusted-scan")
        conditions = scan["verifyImages"][0]["attestations"][0]["conditions"][0]["all"]
        self.assertIn({"key": "{{ counts.CRITICAL }}", "operator": "Equals", "value": 0}, conditions)

    def test_stricter_ci_policy_also_tightens_admission(self):
        real_read = __import__('pathlib').Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == "policy/release.json":
                return '{"block_severities": ["HIGH", "CRITICAL"]}'
            return real_read(path, *args, **kwargs)
        with patch('pathlib.Path.read_text', read):
            policy = policies(REPO, SHA, "123", "1")
        text = json.dumps(policy)
        self.assertIn('counts.HIGH', text)
        self.assertIn('counts.CRITICAL', text)
