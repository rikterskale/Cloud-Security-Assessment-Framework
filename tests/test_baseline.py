"""Baseline threshold loading, overrides, and severity handling."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.baseline import DEFAULT_THRESHOLDS, Baseline

REPO = Path(__file__).resolve().parent.parent


class TestBaseline(unittest.TestCase):
    def test_empty_baseline_uses_defaults(self):
        baseline = Baseline()
        self.assertEqual(baseline.baseline_id, "default")
        self.assertEqual(baseline.get("passwordMinLength"), 14)
        self.assertEqual(baseline.get("sensitiveIngressPorts"), [22, 3389])

    def test_load_none_returns_defaults(self):
        baseline = Baseline.load(None)
        self.assertEqual(baseline.thresholds, DEFAULT_THRESHOLDS)

    def test_threshold_overrides_merge_over_defaults(self):
        baseline = Baseline({"thresholds": {"passwordMinLength": 20}})
        self.assertEqual(baseline.get("passwordMinLength"), 20)
        # Untouched defaults survive the merge.
        self.assertEqual(baseline.get("accessKeyMaxAgeDays"), 90)

    def test_unknown_key_returns_default_argument(self):
        self.assertIsNone(Baseline().get("noSuchKey"))
        self.assertEqual(Baseline().get("noSuchKey", 7), 7)

    def test_severity_override_and_fallthrough(self):
        baseline = Baseline({"severityOverrides": {"CSAF-AWS-IAM-001": "LOW"}})
        self.assertEqual(baseline.severity_for("CSAF-AWS-IAM-001", "CRITICAL"), "LOW")
        self.assertEqual(baseline.severity_for("CSAF-AWS-IAM-002", "CRITICAL"), "CRITICAL")

    def test_not_applicable_controls_parsed_as_set(self):
        baseline = Baseline({"notApplicableControls": ["CSAF-AWS-RDS-001", "CSAF-AWS-RDS-001"]})
        self.assertEqual(baseline.not_applicable_controls, {"CSAF-AWS-RDS-001"})

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"baselineId": "customer-x", "thresholds": {"accessKeyMaxAgeDays": 30}}),
                encoding="utf-8",
            )
            baseline = Baseline.load(path)
            self.assertEqual(baseline.baseline_id, "customer-x")
            self.assertEqual(baseline.get("accessKeyMaxAgeDays"), 30)

    def test_shipped_cis_baseline_loads_and_covers_defaults(self):
        baseline = Baseline.load(REPO / "baselines" / "aws-cis-1.5.json")
        for key in DEFAULT_THRESHOLDS:
            self.assertIsNotNone(baseline.get(key), f"shipped baseline missing threshold {key}")


if __name__ == "__main__":
    unittest.main()
