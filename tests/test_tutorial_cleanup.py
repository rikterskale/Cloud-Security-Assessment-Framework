"""Tutorial cleanup must preserve client reports and reject unsafe ownership."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csaf.tutorial import MARKER, cleanup_tutorial, mark_tutorial
from invoke_assessment import main


class TestTutorialCleanup(unittest.TestCase):
    def test_tampered_artifact_is_not_marked_for_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "tutorial-output"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--tutorial", "--output-dir", str(base), "--log-level", "ERROR"]), 2)
            run = next(base.iterdir())
            (run / MARKER).unlink()
            (run / "findings.json").write_text("tampered", encoding="utf-8")
            with self.assertRaises(ValueError):
                mark_tutorial(str(base), str(run))
            self.assertFalse((run / MARKER).exists())

    def test_link_inside_owned_run_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "tutorial-output"
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--tutorial", "--output-dir", str(base), "--log-level", "ERROR"])
            run = next(base.iterdir())
            with patch("csaf.tutorial._is_link", side_effect=lambda path: path.name == "findings.json"):
                with self.assertRaises(ValueError):
                    cleanup_tutorial(str(base))
            self.assertTrue(run.exists())

    def test_only_owned_tutorial_runs_are_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "tutorial-output"
            real = base / "live-report"
            real.mkdir(parents=True)
            (real / "client-evidence.txt").write_text("preserve", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--tutorial", "--output-dir", str(base), "--log-level", "ERROR"]), 2)
            self.assertEqual(cleanup_tutorial(str(base)), 1)
            self.assertEqual((real / "client-evidence.txt").read_text(), "preserve")
            self.assertTrue(base.is_dir())
            self.assertEqual(cleanup_tutorial(str(base)), 0)

    def test_unmarked_demo_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "csaf-output"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--self-check", "--output-dir", str(base), "--log-level", "ERROR"]), 2)
            self.assertEqual(cleanup_tutorial(str(base)), 0)
            self.assertEqual(len(list(base.iterdir())), 1)

    def test_forged_marker_on_live_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "tutorial-output"
            run = base / "live"
            run.mkdir(parents=True)
            (run / MARKER).write_text(json.dumps({"runId": "live"}), encoding="utf-8")
            (run / "technical-report.json").write_text(
                json.dumps({"Context": {"runId": "live", "selfCheck": False}}), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                cleanup_tutorial(str(base))
            self.assertTrue(run.exists())

    def test_output_name_and_marker_containment_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                cleanup_tutorial(tmp)
            with self.assertRaises(ValueError):
                mark_tutorial(str(Path(tmp) / "tutorial-output"), str(Path(tmp) / "elsewhere"))

    def test_cleanup_during_tutorial_preserves_other_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "tutorial-output"
            other = base / "keep"
            other.mkdir(parents=True)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["--tutorial", "--cleanup-tutorial", "--output-dir", str(base), "--log-level", "ERROR"]), 2
                )
                self.assertEqual(main(["--cleanup-tutorial", "--output-dir", str(base)]), 0)
            self.assertEqual(list(base.iterdir()), [other])
