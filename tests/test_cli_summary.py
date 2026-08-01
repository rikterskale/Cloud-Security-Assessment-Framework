"""End-of-run summary + exit-code help (UX-ENH-003, UX-ENH-008)."""

import io
import unittest
from contextlib import redirect_stdout

from csaf.runner import RunResult
from invoke_assessment import build_parser, exit_code_note, format_run_summary, main


def make_result(exit_code=2):
    return RunResult(
        exit_code=exit_code,
        output_dir="out/run-1",
        coverage={"SelectedControls": 30, "Executed": 29, "NotTested": 1, "Error": 0},
        risk={
            "severity_counts": {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0},
            "normalised_score": 70.0,
            "rating": "CRITICAL",
        },
        finding_count=4,
        all_executed=False,
        message="Completed.",
    )


class TestExitCodeHelp(unittest.TestCase):
    def test_epilog_lists_exit_codes(self):
        help_text = build_parser().format_help()
        self.assertIn("Exit codes:", help_text)
        for code in ("0", "1", "2"):
            self.assertIn(code, help_text)

    def test_exit_code_note(self):
        self.assertEqual(exit_code_note(0), "")
        self.assertIn("exit 2", exit_code_note(2))
        self.assertIn("fatal", exit_code_note(1).lower())


class TestRunSummary(unittest.TestCase):
    def test_summary_contents(self):
        text = format_run_summary(make_result())
        self.assertIn("Risk: 70.0/100 (CRITICAL)", text)
        self.assertIn("CRITICAL 2", text)
        self.assertIn("29/30 executed", text)

    def test_summary_empty_when_no_risk(self):
        empty = RunResult(1, "out", {}, {}, 0, False, "Fatal")
        self.assertEqual(format_run_summary(empty), "")

    def test_main_prints_summary_and_note(self):
        # Offline self-check run through the real CLI; exit 0 or 2.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as buf:
            code = main(["--self-check", "--output-dir", tmp])
        out = buf.getvalue()
        self.assertIn(code, (0, 2))
        self.assertIn("Findings by severity:", out)
        if code == 2:
            self.assertIn("exit 2", out)

    def test_main_suppresses_summary_at_error_level(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as buf:
            main(["--self-check", "--output-dir", tmp, "--log-level", "ERROR"])
        self.assertNotIn("Findings by severity:", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
