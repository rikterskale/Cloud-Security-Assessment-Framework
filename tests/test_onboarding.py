"""First-run scope, cancellation, automation, and browser failure contracts."""

import contextlib
import io
import tempfile
import unittest
from unittest.mock import patch

from invoke_assessment import main


class TestOnboarding(unittest.TestCase):
    def run_cli(self, argv, answers=()):
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            patch("sys.stdin.isatty", return_value=True),
            patch("builtins.input", side_effect=answers),
        ):
            code = main(argv)
        return code, output.getvalue()

    def test_no_arguments_is_a_network_free_welcome(self):
        with patch("invoke_assessment.run_assessment") as runner:
            code, text = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("--start", text)
        runner.assert_not_called()

    def test_guided_demo_creates_a_real_report(self):
        with tempfile.TemporaryDirectory() as tmp, patch("webbrowser.open", return_value=True) as browser:
            code, text = self.run_cli(
                ["--start", "--output-dir", tmp, "--log-level", "ERROR"], ["", "gcp", "", "", ""]
            )
        self.assertEqual(code, 2)
        self.assertIn("GCP / demo", text)
        self.assertTrue(browser.call_args.args[0].startswith("file:"))

    def test_cancel_does_not_contact_cloud_or_write_reports(self):
        with patch("invoke_assessment.run_assessment") as runner:
            code, text = self.run_cli(["--start"], ["", "", "", "no"])
        self.assertEqual(code, 0)
        self.assertIn("Cancelled", text)
        runner.assert_not_called()

    def test_eof_and_interrupt_cancel_without_a_traceback(self):
        for exception in (EOFError, KeyboardInterrupt):
            with (
                patch("sys.stdin.isatty", return_value=True),
                patch("builtins.input", side_effect=exception),
                patch("invoke_assessment.run_assessment") as runner,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(["--start"]), 0)
            runner.assert_not_called()

    def test_redirected_input_fails_with_an_actionable_command(self):
        with patch("sys.stdin.isatty", return_value=False), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--start"]), 1)
        self.assertIn("--self-check", output.getvalue())

    def test_conflicting_execution_modes_are_rejected(self):
        for options in (["--self-check"], ["--plan"], ["--skip-live-preflight"], ["--profile", "Validation"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["--start", *options])

    def test_browser_failure_keeps_assessment_exit_code(self):
        for browser_error in (None, OSError("no browser")):
            with (
                tempfile.TemporaryDirectory() as tmp,
                patch("webbrowser.open", return_value=False, side_effect=browser_error),
            ):
                code, text = self.run_cli(
                    ["--self-check", "--open-report", "--output-dir", tmp, "--log-level", "ERROR"]
                )
            self.assertEqual(code, 2)
            self.assertIn("Open this file", text)

    def test_live_targets_reach_the_normal_runner_with_preflight_enabled(self):
        from csaf.runner import RunResult

        cases = (
            ("aws", ["audit", "us-east-1 eu-west-1"], "aws_profile", "audit"),
            ("azure", ["subscription-1"], "subscription_id", "subscription-1"),
            ("gcp", ["project-1"], "project_id", "project-1"),
            ("k8s", ["cluster-1", "config-path"], "kube_context", "cluster-1"),
        )
        for cloud, targets, field, expected in cases:
            with (
                self.subTest(cloud=cloud),
                patch(
                    "invoke_assessment.run_assessment",
                    return_value=RunResult(1, "missing-output", {}, {}, 0, False, "No credentials"),
                ) as runner,
            ):
                code, text = self.run_cli(["--start"], ["live", cloud, *targets, "", "yes", "no"])
            config = runner.call_args.args[0]
            self.assertEqual(getattr(config, field), expected)
            self.assertFalse(config.self_check)
            self.assertFalse(config.skip_live_preflight)
            self.assertEqual(config.profile, "Assessment")
            self.assertEqual(code, 1)
            self.assertNotIn("Output written", text)

    def test_fatal_run_does_not_open_an_existing_report(self):
        from pathlib import Path

        from csaf.runner import RunResult

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "executive-summary.html").write_text("old report", encoding="utf-8")
            with (
                patch("invoke_assessment.run_assessment", return_value=RunResult(1, tmp, {}, {}, 0, False, "fatal")),
                patch("webbrowser.open") as browser,
            ):
                code, _ = self.run_cli(["--open-report"])
        self.assertEqual(code, 1)
        browser.assert_not_called()
