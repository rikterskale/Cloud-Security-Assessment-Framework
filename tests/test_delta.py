"""Finding delta: New/Persisted classification and resolved-finding detection."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.delta import NEW, PERSISTED, compute_delta
from csaf.model import finding_from_result
from tests.test_reporting import make_result


def finding(cid, resource_id="r1"):
    return finding_from_result(make_result(cid, "Fail", "HIGH", "Title", resource_id), "fix")


class TestComputeDelta(unittest.TestCase):
    def test_no_previous_path_returns_none(self):
        self.assertIsNone(compute_delta([finding("CSAF-AWS-TST-001")], None))

    def test_all_new_when_previous_empty(self):
        f = finding("CSAF-AWS-TST-001")
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = Path(tmp) / "findings.json"
            prev_path.write_text("[]", encoding="utf-8")
            delta = compute_delta([f], prev_path)
        self.assertEqual(delta.status_for(f.finding_id), NEW)
        self.assertEqual(delta.resolved, [])

    def test_persisted_when_id_matches_previous(self):
        f = finding("CSAF-AWS-TST-001")
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = Path(tmp) / "findings.json"
            prev_path.write_text(json.dumps([f.to_dict()]), encoding="utf-8")
            delta = compute_delta([f], prev_path)
        self.assertEqual(delta.status_for(f.finding_id), PERSISTED)

    def test_resolved_when_previous_id_absent_from_current(self):
        old = finding("CSAF-AWS-TST-002", resource_id="gone")
        current = finding("CSAF-AWS-TST-001")
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = Path(tmp) / "findings.json"
            prev_path.write_text(json.dumps([old.to_dict()]), encoding="utf-8")
            delta = compute_delta([current], prev_path)
        self.assertEqual(delta.status_for(current.finding_id), NEW)
        self.assertEqual([r["FindingId"] for r in delta.resolved], [old.finding_id])

    def test_summary_counts(self):
        old = finding("CSAF-AWS-TST-002", resource_id="gone")
        persisted = finding("CSAF-AWS-TST-001")
        new = finding("CSAF-AWS-TST-003", resource_id="new-one")
        with tempfile.TemporaryDirectory() as tmp:
            prev_path = Path(tmp) / "findings.json"
            prev_path.write_text(json.dumps([old.to_dict(), persisted.to_dict()]), encoding="utf-8")
            delta = compute_delta([persisted, new], prev_path)
        self.assertEqual(delta.to_summary(), {"new": 1, "persisted": 1, "resolved": 1})


class TestDeltaEndToEnd(unittest.TestCase):
    def test_second_self_check_run_marks_findings_persisted(self):
        from csaf.runner import RunConfig, run_assessment

        repo = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            first_dir = Path(tmp) / "first"
            config = RunConfig(
                profile="Assessment",
                catalog_path=str(repo / "controls" / "control-catalog.json"),
                baseline_path=str(repo / "baselines" / "aws-cis-1.5.json"),
                output_dir=str(first_dir),
                self_check=True,
                log_level="ERROR",
            )
            first_result = run_assessment(config)

            second_dir = Path(tmp) / "second"
            config.output_dir = str(second_dir)
            config.previous_findings_path = str(Path(first_result.output_dir) / "findings.json")
            second_result = run_assessment(config)
            output = Path(second_result.output_dir)

            findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            self.assertTrue(findings, "self-check should produce findings")
            self.assertTrue(all(f["DeltaStatus"] == PERSISTED for f in findings))

            resolved = json.loads((output / "findings-resolved.json").read_text(encoding="utf-8"))
            self.assertEqual(resolved, [])

            html = (output / "executive-summary.html").read_text(encoding="utf-8")
            self.assertIn("Delta vs previous run", html)


if __name__ == "__main__":
    unittest.main()
