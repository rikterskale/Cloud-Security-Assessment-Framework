"""write_detection_coverage output and the executive-HTML gap card."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.coverage import Coverage
from csaf.reporting import write_detection_coverage, write_executive_html


def full_coverage(**overrides):
    values = dict(selected=1, executed=1, passed=0, failed=1, review=0, not_applicable=0, not_tested=0, error=0)
    values.update(overrides)
    return Coverage(**values)


class TestWriteDetectionCoverage(unittest.TestCase):
    def test_json_and_csv_written(self):
        rows = [{"Technique": "T1078", "Status": "Gap", "ControlIds": ["C1", "C2"], "GapControlIds": ["C2"]}]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_detection_coverage(rows, out)
            data = json.loads((out / "detection-coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(data, rows)
            csv_text = (out / "detection-coverage.csv").read_text(encoding="utf-8")
            self.assertIn("T1078,Gap,C1;C2,C2", csv_text)

    def test_empty_rows_still_write_valid_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_detection_coverage([], out)
            self.assertEqual(json.loads((out / "detection-coverage.json").read_text(encoding="utf-8")), [])


class TestExecutiveHtmlGapCard(unittest.TestCase):
    def test_gap_card_rendered_when_detection_coverage_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            rows = [{"Technique": "T1078", "Status": "Gap", "ControlIds": ["C1"], "GapControlIds": ["C1"]}]
            write_executive_html(
                [],
                full_coverage(),
                {
                    "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    "normalised_score": 0,
                    "rating": "MINIMAL",
                },
                {},
                {},
                out,
                detection_coverage=rows,
            )
            html = (out / "executive-summary.html").read_text(encoding="utf-8")
            self.assertIn("ATT&amp;CK Technique Gaps", html)
            self.assertIn(">1<", html)

    def test_no_gap_card_when_detection_coverage_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_executive_html(
                [],
                full_coverage(),
                {
                    "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                    "normalised_score": 0,
                    "rating": "MINIMAL",
                },
                {},
                {},
                out,
            )
            html = (out / "executive-summary.html").read_text(encoding="utf-8")
            self.assertNotIn("ATT&amp;CK Technique Gaps", html)


if __name__ == "__main__":
    unittest.main()
