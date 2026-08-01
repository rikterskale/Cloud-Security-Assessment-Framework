"""Malformed catalogs/baselines/engagements must fail closed (roadmap #12).

These guard the runtime schema-validation contract: bad operator-supplied
configuration is rejected with a ValueError (or a fatal run), never silently
accepted as a clean assessment.
"""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.baseline import Baseline
from csaf.catalog import Catalog
from csaf.engagement import Engagement
from csaf.resource_paths import read_resource_text
from csaf.runner import EXIT_FATAL, RunConfig, run_assessment


def _valid_catalog():
    data = json.loads(read_resource_text("controls", "control-catalog.json"))
    data["controls"] = data["controls"][:1]
    return data


def _write(tmp, name, data):
    path = Path(tmp) / name
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return path


class TestMalformedCatalog(unittest.TestCase):
    def test_missing_controls_key_rejected(self):
        data = _valid_catalog()
        del data["controls"]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Catalog.load(_write(tmp, "c.json", data))

    def test_invalid_severity_rejected(self):
        data = _valid_catalog()
        data["controls"][0]["defaultSeverity"] = "SEVERE"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Catalog.load(_write(tmp, "c.json", data))

    def test_duplicate_control_ids_rejected(self):
        data = _valid_catalog()
        data["controls"].append(json.loads(json.dumps(data["controls"][0])))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Catalog.load(_write(tmp, "c.json", data))

    def test_not_json_rejected(self):
        # json.JSONDecodeError is a subclass of ValueError.
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Catalog.load(_write(tmp, "c.json", "{ not json"))


class TestMalformedBaseline(unittest.TestCase):
    def test_wrong_top_level_type_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Baseline.load(_write(tmp, "b.json", ["not", "an", "object"]))


class TestMalformedEngagement(unittest.TestCase):
    def test_missing_engagement_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Engagement.load(_write(tmp, "e.json", {"customer": "acme"}))


class TestMalformedCatalogFatalRun(unittest.TestCase):
    def test_run_with_malformed_catalog_is_fatal_not_pass(self):
        data = _valid_catalog()
        del data["controls"]
        with tempfile.TemporaryDirectory() as tmp:
            bad = _write(tmp, "c.json", data)
            result = run_assessment(
                RunConfig(
                    self_check=True,
                    catalog_path=str(bad),
                    output_dir=str(Path(tmp) / "out"),
                    log_level="ERROR",
                )
            )
            self.assertEqual(result.exit_code, EXIT_FATAL)
            self.assertIn("Fatal", result.message)


if __name__ == "__main__":
    unittest.main()
