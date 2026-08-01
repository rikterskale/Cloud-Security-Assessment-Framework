"""Purple-team detection-coverage pack (OFF-FEAT-003)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.detection_pack import build_detection_pack, build_pack_from_run, main

ROWS = [
    {"Technique": "T1078", "Status": "Gap", "ControlIds": ["CIS-1.1"], "GapControlIds": ["CIS-1.1"]},
    {"Technique": "T1530", "Status": "Covered", "ControlIds": ["CIS-2.1"], "GapControlIds": []},
    {"Technique": "T1562", "Status": "Unknown", "ControlIds": ["CIS-3.1"], "GapControlIds": []},
]


class TestDetectionPack(unittest.TestCase):
    def test_summary_and_gap_list(self):
        pack = build_detection_pack(ROWS, "AWS")
        self.assertEqual(pack["summary"], {"Covered": 1, "Gap": 1, "Unknown": 1})
        self.assertEqual(pack["gapTechniques"], ["T1078"])
        self.assertEqual(pack["techniqueCount"], 3)

    def test_markers_are_safe_and_present(self):
        pack = build_detection_pack(ROWS, "AWS")
        markers = [t["purpleTeamMarker"] for t in pack["techniques"]]
        self.assertTrue(all("dataSource" in m for m in markers))
        # Gap technique marker is high priority and references CloudTrail.
        gap_marker = next(m for m in markers if m["technique"] == "T1078")
        self.assertEqual(gap_marker["priority"], "high")
        self.assertIn("CloudTrail", gap_marker["dataSource"])
        # Safety: no offensive/exploit language anywhere in the pack.
        blob = json.dumps(pack).lower()
        for banned in ("exploit", "payload", "reverse shell", "evasion", "curl ", "bypass "):
            self.assertNotIn(banned, blob)

    def test_no_markers_flag(self):
        pack = build_detection_pack(ROWS, "GCP", include_markers=False)
        self.assertFalse(any("purpleTeamMarker" in t for t in pack["techniques"]))

    def test_build_from_run_and_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "detection-coverage.json").write_text(json.dumps(ROWS), encoding="utf-8")
            (run / "manifest.json").write_text(json.dumps({"Cloud": "Azure"}), encoding="utf-8")
            pack = build_pack_from_run(run)
            self.assertEqual(pack["cloud"], "Azure")
            with redirect_stdout(io.StringIO()) as buf:
                rc = main([str(run)])
            self.assertEqual(rc, 0)
            self.assertIn("Detection pack", buf.getvalue())
            written = json.loads((run / "detection-pack.json").read_text())
            self.assertEqual(written["summary"]["Gap"], 1)

    def test_missing_coverage_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                build_pack_from_run(tmp)


if __name__ == "__main__":
    unittest.main()
