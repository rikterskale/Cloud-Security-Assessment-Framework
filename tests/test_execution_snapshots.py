"""Historical execution snapshots are labeled as not-current (roadmap #14 / REV-DOC-005)."""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SNAPSHOTS = ["aws.md", "azure.md", "gcp.md", "k8s.md"]


class TestExecutionSnapshots(unittest.TestCase):
    def test_each_cloud_report_has_historical_banner(self):
        for name in SNAPSHOTS:
            path = REPO / "docs" / "test-execution" / name
            self.assertTrue(path.is_file(), f"missing {name}")
            head = "".join(path.read_text(encoding="utf-8").splitlines(keepends=True)[:6])
            self.assertIn("Historical snapshot", head, f"{name} missing not-current banner")
            self.assertIn("Not current runtime evidence", head, f"{name} banner missing disclaimer")

    def test_readme_notes_historical_status(self):
        readme = (REPO / "docs" / "test-execution" / "README.md").read_text(encoding="utf-8")
        self.assertIn("historical snapshot", readme.lower())


if __name__ == "__main__":
    unittest.main()
