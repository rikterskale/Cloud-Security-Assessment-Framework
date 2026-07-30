"""Packaged runtime data must mirror repository source data."""

import os
import tempfile
import unittest
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from csaf.resource_paths import resolve_resource
from csaf.runner import RunConfig, run_assessment

REPO = Path(__file__).resolve().parent.parent


@contextmanager
def temporary_cwd(path: Path):
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


class TestPackagedResources(unittest.TestCase):
    def test_packaged_json_exactly_matches_source_directories(self):
        package_root = files("csaf.resources")
        for category, source_name in (
            ("controls", "controls"),
            ("baselines", "baselines"),
            ("schemas", "schemas"),
        ):
            with self.subTest(category=category):
                source_files = sorted((REPO / source_name).glob("*.json"))
                packaged_names = sorted(item.name for item in package_root.joinpath(category).iterdir())
                self.assertEqual(packaged_names, [item.name for item in source_files])
                for source in source_files:
                    packaged = package_root.joinpath(category, source.name)
                    self.assertEqual(packaged.read_bytes(), source.read_bytes(), source.name)

    def test_default_resource_resolution_is_independent_of_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp, temporary_cwd(Path(tmp)):
            with resolve_resource(None, "controls", "control-catalog.json") as path:
                self.assertTrue(path.is_file())
                self.assertIn('"catalogVersion"', path.read_text(encoding="utf-8"))

    def test_default_self_check_uses_packaged_catalog_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp, temporary_cwd(Path(tmp)):
            result = run_assessment(
                RunConfig(
                    output_dir=str(Path(tmp) / "output"),
                    self_check=True,
                    log_level="ERROR",
                )
            )
            self.assertIn(result.exit_code, (0, 2))
            self.assertTrue((Path(result.output_dir) / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
