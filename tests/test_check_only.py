"""Preflight --check-only (UX-ENH-004)."""

import tempfile
import unittest
from pathlib import Path

from csaf.runner import RunConfig, run_assessment


class TestCheckOnly(unittest.TestCase):
    def test_read_only_profile_preflight_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_assessment(
                RunConfig(profile="Assessment", cloud="aws", check_only=True, output_dir=tmp, log_level="ERROR")
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Preflight passed", result.message)
            # No report artifacts were written (only the log/run dir may exist).
            run_dir = Path(result.output_dir)
            self.assertFalse((run_dir / "technical-report.json").exists())
            self.assertFalse((run_dir / "findings.json").exists())
            self.assertFalse((run_dir / "manifest.json").exists())

    def test_active_profile_without_engagement_fails_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_assessment(
                RunConfig(profile="Validation", cloud="aws", check_only=True, output_dir=tmp, log_level="ERROR")
            )
            self.assertEqual(result.exit_code, 1)  # unauthorized profile, caught before any cloud contact

    def test_check_only_makes_no_cloud_call(self):
        # cloud="aws" without --self-check would normally build an AwsSession (needs creds);
        # check_only must return before that, so this succeeds with no credentials available.
        with tempfile.TemporaryDirectory() as tmp:
            result = run_assessment(
                RunConfig(profile="Assessment", cloud="aws", check_only=True, output_dir=tmp, log_level="ERROR")
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No cloud calls", result.message)


if __name__ == "__main__":
    unittest.main()
