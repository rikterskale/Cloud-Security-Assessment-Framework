"""CLI argument handling and exit-code propagation for invoke_assessment.py."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from invoke_assessment import build_parser, main

REPO = Path(__file__).resolve().parent.parent


class TestParser(unittest.TestCase):
    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.profile, "Assessment")
        self.assertEqual(args.regions, ["us-east-1"])
        self.assertEqual(args.output_dir, "csaf-output")
        self.assertFalse(args.self_check)

    def test_multiple_regions(self):
        args = build_parser().parse_args(["--regions", "us-east-1", "eu-west-1"])
        self.assertEqual(args.regions, ["us-east-1", "eu-west-1"])

    def test_invalid_profile_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["--profile", "Exploit"])
        self.assertEqual(ctx.exception.code, 2)

    def test_version_flag(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                build_parser().parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class TestMain(unittest.TestCase):
    def test_self_check_run_propagates_incomplete_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "--self-check",
                        "--output-dir",
                        tmp,
                        "--log-level",
                        "ERROR",
                        "--catalog",
                        str(REPO / "controls" / "control-catalog.json"),
                        "--baseline",
                        str(REPO / "baselines" / "aws-cis-1.5.json"),
                    ]
                )
            # The demo posture leaves one control untested -> CompletedWithErrors.
            self.assertEqual(code, 2)
            self.assertIn("[INCOMPLETE]", stdout.getvalue())
            run_dirs = [path for path in Path(tmp).iterdir() if path.is_dir()]
            self.assertEqual(len(run_dirs), 1)
            self.assertTrue((run_dirs[0] / "manifest.json").exists())

    def test_fatal_run_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--self-check",
                        "--output-dir",
                        tmp,
                        "--log-level",
                        "ERROR",
                        "--catalog",
                        str(Path(tmp) / "missing.json"),
                    ]
                )
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
