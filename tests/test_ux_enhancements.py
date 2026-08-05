"""Focused regression tests for the seven UX improvements."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from csaf.preflight import plan_assessment, run_preflight
from invoke_assessment import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


class TestPreflightAndPlan(unittest.TestCase):
    def test_preflight_reports_required_checks_without_network(self):
        checks = run_preflight("aws", tempfile.mkdtemp())
        names = {check.name for check in checks}
        self.assertTrue({"Python version", "jsonschema", "catalog resource", "output directory"} <= names)

    def test_plan_is_deterministic_and_network_free(self):
        plan = plan_assessment("aws", "Assessment")
        self.assertEqual(plan["networkCalls"], 0)
        self.assertGreater(plan["selectedControls"], 0)
        self.assertEqual(plan, plan_assessment("aws", "Assessment"))

    def test_parser_exposes_ux_options(self):
        args = build_parser().parse_args(["--preflight", "--output-format", "json", "--no-color"])
        self.assertTrue(args.preflight)
        self.assertEqual(args.output_format, "json")
        self.assertTrue(args.no_color)

    def test_plan_json_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--plan", "--output-format", "json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["networkCalls"], 0)


class TestGeneratedDocumentation(unittest.TestCase):
    def test_cli_reference_exists_and_mentions_new_options(self):
        text = (ROOT / "docs" / "CLI_REFERENCE.md").read_text(encoding="utf-8")
        for option in ("--preflight", "--plan", "--tutorial", "--no-color", "--output-format"):
            self.assertIn(option, text)

    def test_coverage_schema_exists(self):
        schema = json.loads((ROOT / "schemas" / "coverage.schema.json").read_text(encoding="utf-8"))
        self.assertIn("CoverageSchemaVersion", schema["required"])


if __name__ == "__main__":
    unittest.main()
