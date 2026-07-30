"""Runner authorization, fatal-error, and exit-code paths (all offline)."""

import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csaf.engagement_signing import sign
from csaf.runner import EXIT_FATAL, EXIT_INCOMPLETE, EXIT_OK, RunConfig, run_assessment, source_revision

REPO = Path(__file__).resolve().parent.parent
CATALOG = str(REPO / "controls" / "control-catalog.json")
BASELINE = str(REPO / "baselines" / "aws-cis-1.5.json")


def run(tmp, **overrides):
    config = RunConfig(
        profile=overrides.pop("profile", "Assessment"),
        catalog_path=overrides.pop("catalog_path", CATALOG),
        baseline_path=overrides.pop("baseline_path", BASELINE),
        output_dir=str(tmp),
        self_check=True,
        log_level=overrides.pop("log_level", "ERROR"),
        **overrides,
    )
    return run_assessment(config)


def write_json(directory, name, payload):
    path = Path(directory) / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def write_signed_engagement(directory, **overrides):
    now = datetime.datetime.now(datetime.timezone.utc)
    data = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-TEST",
        "cloud": "AWS",
        "authorizedAccounts": ["000000000000"],
        "authorizedRegions": ["us-east-1"],
        "activeValidationApproved": True,
        "windowStartUtc": (now - datetime.timedelta(hours=1)).isoformat(),
        "windowEndUtc": (now + datetime.timedelta(hours=1)).isoformat(),
    }
    data.update(overrides)
    key = b"test-shared-secret"
    data["signature"] = sign(data, key)
    engagement_path = write_json(directory, "engagement.json", data)
    key_path = Path(directory) / "engagement.key"
    key_path.write_bytes(key)
    return engagement_path, str(key_path)


class TestAuthorizationPaths(unittest.TestCase):
    def test_validation_without_engagement_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp, profile="Validation")
            self.assertEqual(result.exit_code, EXIT_FATAL)
            self.assertIn("Unauthorized profile", result.message)

    def test_validation_with_approved_in_window_engagement_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            engagement, key = write_signed_engagement(tmp)
            out = Path(tmp) / "out"
            result = run(out, profile="Validation", engagement_path=engagement, engagement_key_path=key)
            self.assertNotEqual(result.exit_code, EXIT_FATAL)
            run_dir = Path(result.output_dir)
            rows = [
                json.loads(line)
                for line in (run_dir / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            # The validation-only privesc control is included under Validation.
            self.assertIn("CSAF-AWS-IAM-010", {r["ControlId"] for r in rows})

    def test_validation_outside_window_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            engagement, key = write_signed_engagement(
                tmp,
                windowStartUtc="2000-01-01T00:00:00Z",
                windowEndUtc="2000-01-02T00:00:00Z",
            )
            result = run(
                Path(tmp) / "out",
                profile="Validation",
                engagement_path=engagement,
                engagement_key_path=key,
            )
            self.assertEqual(result.exit_code, EXIT_FATAL)


class TestFatalPaths(unittest.TestCase):
    def test_missing_catalog_is_fatal_result_not_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp, catalog_path=str(Path(tmp) / "no-such-catalog.json"))
            self.assertEqual(result.exit_code, EXIT_FATAL)
            self.assertIn("Fatal", result.message)

    def test_malformed_baseline_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "baseline.json"
            bad.write_text("{not json", encoding="utf-8")
            result = run(Path(tmp) / "out", baseline_path=str(bad))
            self.assertEqual(result.exit_code, EXIT_FATAL)

    def test_profile_selecting_no_controls_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp, profile="Inventory")
            self.assertEqual(result.exit_code, EXIT_FATAL)
            self.assertIn("selected no controls", result.message)
            self.assertFalse((Path(tmp) / "technical-report.json").exists())

    def test_empty_engagement_key_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "empty.key"
            key_path.write_text(" \n", encoding="utf-8")
            result = run(Path(tmp) / "out", engagement_key_path=str(key_path))
            self.assertEqual(result.exit_code, EXIT_FATAL)
            self.assertIn("key file is empty", result.message)


class TestBaselineExclusions(unittest.TestCase):
    def test_not_applicable_controls_removed_from_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            reference = run(Path(tmp) / "ref")
            baseline = write_json(tmp, "baseline.json", {"notApplicableControls": ["CSAF-AWS-IAM-001"]})
            trimmed = run(Path(tmp) / "trimmed", baseline_path=baseline)
            self.assertEqual(
                trimmed.coverage["SelectedControls"],
                reference.coverage["SelectedControls"] - 1,
            )
            rows = (Path(trimmed.output_dir) / "control-results.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("CSAF-AWS-IAM-001", rows)

    def test_excluding_the_not_tested_control_yields_exit_ok(self):
        # The demo posture leaves only CSAF-AWS-OPS-001 untested; a baseline that
        # marks it not-applicable produces a fully-executed run and exit 0.
        with tempfile.TemporaryDirectory() as tmp:
            baseline = write_json(tmp, "baseline.json", {"notApplicableControls": ["CSAF-AWS-OPS-001"]})
            result = run(Path(tmp) / "out", baseline_path=baseline)
            self.assertEqual(result.exit_code, EXIT_OK)
            self.assertTrue(result.all_executed)

    def test_default_demo_posture_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp)
            self.assertEqual(result.exit_code, EXIT_INCOMPLETE)
            self.assertIn(
                "CSAF-AWS-OPS-001",
                json.loads((Path(result.output_dir) / "coverage-report.json").read_text(encoding="utf-8"))[
                    "NotTestedControls"
                ],
            )


class TestRunLogs(unittest.TestCase):
    def test_structured_jsonl_log_written_and_parseable(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(tmp, log_level="WARN")  # demo posture emits not-completed warnings
            jsonl_logs = list(Path(result.output_dir).glob("assessment-*.jsonl"))
            self.assertEqual(len(jsonl_logs), 1)
            records = [json.loads(line) for line in jsonl_logs[0].read_text(encoding="utf-8").splitlines()]
            self.assertTrue(records, "expected at least one structured log record")
            for record in records:
                self.assertIn("level", record)
                self.assertIn("message", record)
                self.assertIn("runId", record)
            self.assertTrue(any("NOT COMPLETED" in r["message"] for r in records))


class TestRunIsolation(unittest.TestCase):
    def test_repeated_runs_create_distinct_complete_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = run(tmp)
            second = run(tmp)
            first_dir = Path(first.output_dir)
            second_dir = Path(second.output_dir)
            self.assertNotEqual(first_dir, second_dir)
            self.assertEqual(first_dir.parent, Path(tmp))
            self.assertEqual(second_dir.parent, Path(tmp))
            self.assertTrue((first_dir / "manifest.json").exists())
            self.assertTrue((second_dir / "manifest.json").exists())


class TestSourceRevision(unittest.TestCase):
    def test_environment_revision_is_normalized_and_preferred(self):
        configured = "A" * 40
        with patch.dict(os.environ, {"CSAF_SOURCE_REVISION": configured}):
            self.assertEqual(source_revision(), configured.lower())


if __name__ == "__main__":
    unittest.main()
