"""Installer bootstrap: structured errors, no extra pip, first-assessment gate."""

from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

INSTALL = Path(__file__).resolve().parent.parent / "scripts" / "install.py"


def load_install():
    spec = importlib.util.spec_from_file_location("csaf_install", INSTALL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {INSTALL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestInstallHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_install()

    def test_fail_shape(self):
        with redirect_stdout(io.StringIO()) as buf:
            code = self.mod._fail("CSAF-E001", "missing pip", "python", "python -m ensurepip --upgrade")
        text = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("[CSAF-E001] missing pip", text)
        self.assertIn("Resource: python", text)
        self.assertIn("Fix: python -m ensurepip --upgrade", text)

    def test_parse_args_defaults(self):
        args = self.mod.parse_args([])
        self.assertEqual(args.cloud, "aws")
        self.assertFalse(args.live)
        self.assertEqual(args.output_dir, "out")

    def test_ensure_checkout_ok(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.ensure_checkout(), 0)

    def test_ensure_python_too_old(self):
        proc = SimpleNamespace(returncode=0, stdout="3.9\n", stderr="")
        with patch.object(self.mod, "_run", return_value=proc), redirect_stdout(io.StringIO()) as buf:
            code = self.mod.ensure_python("python")
        self.assertEqual(code, 1)
        self.assertIn("CSAF-E001", buf.getvalue())
        self.assertIn("3.9", buf.getvalue())

    def test_ensure_python_missing_venv(self):
        calls = [
            SimpleNamespace(returncode=0, stdout="3.12\n", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr="No module named venv"),
        ]

        def run(cmd, **kwargs):
            return calls.pop(0)

        with patch.object(self.mod, "_run", side_effect=run), redirect_stdout(io.StringIO()) as buf:
            code = self.mod.ensure_python("python")
        self.assertEqual(code, 1)
        self.assertIn("venv module is missing", buf.getvalue())
        self.assertIn("python3-venv", buf.getvalue())

    def test_install_locked_missing_lock(self):
        with patch.object(self.mod, "ROOT", Path(tempfile.gettempdir()) / "csaf-missing-lock"):
            with redirect_stdout(io.StringIO()) as buf:
                code = self.mod.install_locked()
        self.assertEqual(code, 1)
        self.assertIn("CSAF-E003", buf.getvalue())
        self.assertIn("requirements-lock.txt", buf.getvalue())

    def test_local_preflight_failure_is_structured(self):
        proc = SimpleNamespace(returncode=1, stdout="", stderr="blocked")
        with (
            patch.object(self.mod, "_run", return_value=proc),
            patch.object(self.mod, "_assess_cmd", return_value=["csaf-assess"]),
            redirect_stdout(io.StringIO()) as buf,
        ):
            code = self.mod.local_preflight("aws", "out")
        self.assertEqual(code, 1)
        self.assertIn("CSAF-E001", buf.getvalue())
        self.assertIn("--preflight", buf.getvalue())

    def test_self_check_missing_reports(self):
        proc = SimpleNamespace(returncode=2, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(self.mod, "_run", return_value=proc),
                patch.object(self.mod, "_assess_cmd", return_value=["csaf-assess"]),
                patch.object(self.mod, "ROOT", Path(tmp)),
                redirect_stdout(io.StringIO()) as buf,
            ):
                code = self.mod.run_self_check("aws", "out")
        self.assertEqual(code, 1)
        self.assertIn("CSAF-E003", buf.getvalue())
        self.assertIn("executive-summary.html", buf.getvalue())

    def test_self_check_success_maps_incomplete(self):
        proc = SimpleNamespace(returncode=2, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "out" / "run-1"
            run_dir.mkdir(parents=True)
            for name in ("executive-summary.html", "findings.csv", "findings.json", "manifest.json"):
                (run_dir / name).write_text("ok", encoding="utf-8")
            with (
                patch.object(self.mod, "_run", return_value=proc),
                patch.object(self.mod, "_assess_cmd", return_value=["csaf-assess"]),
                patch.object(self.mod, "ROOT", Path(tmp)),
                redirect_stdout(io.StringIO()) as buf,
            ):
                code = self.mod.run_self_check("aws", "out")
            self.assertEqual(code, 0)
            self.assertIn("intentionally incomplete", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
