"""Operator-controlled JSON configuration is validated before use."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.baseline import Baseline
from csaf.catalog import Catalog
from csaf.engagement import Engagement

REPO = Path(__file__).resolve().parent.parent


def write_json(directory: str, name: str, data: dict) -> Path:
    path = Path(directory) / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestRuntimeSchemaValidation(unittest.TestCase):
    def test_catalog_rejects_unknown_root_property(self):
        data = json.loads((REPO / "controls" / "control-catalog.json").read_text(encoding="utf-8"))
        data["typoField"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(tmp, "catalog.json", data)
            with self.assertRaisesRegex(ValueError, r"<root>.*Additional properties.*typoField"):
                Catalog.load(path)

    def test_baseline_rejects_wrong_threshold_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(
                tmp,
                "baseline.json",
                {"schemaVersion": "1.0", "thresholds": {"passwordMinLength": "fourteen"}},
            )
            with self.assertRaisesRegex(ValueError, r"thresholds\.passwordMinLength.*not of type"):
                Baseline.load(path)

    def test_engagement_rejects_incompatible_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(
                tmp,
                "engagement.json",
                {"schemaVersion": "2.0", "engagementId": "ENG-1"},
            )
            with self.assertRaisesRegex(ValueError, r"schemaVersion.*1\.0"):
                Engagement.load(path)

    def test_engagement_rejects_unknown_authorization_property(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(
                tmp,
                "engagement.json",
                {"schemaVersion": "1.0", "engagementId": "ENG-1", "authorizedAccount": "123"},
            )
            with self.assertRaisesRegex(ValueError, r"<root>.*authorizedAccount"):
                Engagement.load(path)

    def test_active_engagement_requires_explicit_scope_and_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json(
                tmp,
                "engagement.json",
                {
                    "schemaVersion": "1.0",
                    "engagementId": "ENG-1",
                    "activeValidationApproved": True,
                },
            )
            with self.assertRaisesRegex(ValueError, r"authorizedAccounts"):
                Engagement.load(path)


if __name__ == "__main__":
    unittest.main()
