"""ATT&CK technique detection-coverage rollup."""

import unittest

from csaf.detection_coverage import COVERED, GAP, UNKNOWN, compute_detection_coverage
from csaf.model import ControlResult


def result(cid, status, mappings, resource_id=""):
    return ControlResult(
        control_id=cid,
        title="t",
        category="c",
        status=status,
        severity="HIGH" if status in ("Fail", "Review") else "INFO",
        cloud="AWS",
        account_id="1",
        region="global",
        resource_id=resource_id,
        mappings=mappings,
    )


class TestComputeDetectionCoverage(unittest.TestCase):
    def test_no_mitre_mappings_produces_no_rows(self):
        results = [result("C1", "Pass", ["CIS-AWS:1.1"])]
        self.assertEqual(compute_detection_coverage(results), [])

    def test_all_pass_is_covered(self):
        results = [result("C1", "Pass", ["MITRE:T1078"])]
        rows = compute_detection_coverage(results)
        self.assertEqual(rows, [{"Technique": "T1078", "Status": COVERED, "ControlIds": ["C1"], "GapControlIds": []}])

    def test_any_fail_is_gap(self):
        results = [
            result("C1", "Pass", ["MITRE:T1078"], resource_id="r1"),
            result("C2", "Fail", ["MITRE:T1078"], resource_id="r2"),
        ]
        rows = compute_detection_coverage(results)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Status"], GAP)
        self.assertEqual(rows[0]["ControlIds"], ["C1", "C2"])
        self.assertEqual(rows[0]["GapControlIds"], ["C2"])

    def test_review_status_is_gap(self):
        results = [result("C1", "Review", ["MITRE:T1078"])]
        self.assertEqual(compute_detection_coverage(results)[0]["Status"], GAP)

    def test_only_not_tested_or_error_is_unknown(self):
        results = [result("C1", "NotTested", ["MITRE:T1078"]), result("C2", "Error", ["MITRE:T1078"])]
        rows = compute_detection_coverage(results)
        self.assertEqual(rows[0]["Status"], UNKNOWN)

    def test_not_applicable_counts_as_executed_and_covered(self):
        results = [result("C1", "NotApplicable", ["MITRE:T1078"])]
        self.assertEqual(compute_detection_coverage(results)[0]["Status"], COVERED)

    def test_multiple_techniques_on_one_control_each_get_a_row(self):
        results = [result("C1", "Fail", ["MITRE:T1078", "MITRE:T1552.001"])]
        rows = compute_detection_coverage(results)
        techniques = {r["Technique"] for r in rows}
        self.assertEqual(techniques, {"T1078", "T1552.001"})

    def test_rows_sorted_by_technique_id(self):
        results = [result("C1", "Pass", ["MITRE:T1552"]), result("C2", "Pass", ["MITRE:T1078"])]
        rows = compute_detection_coverage(results)
        self.assertEqual([r["Technique"] for r in rows], ["T1078", "T1552"])


if __name__ == "__main__":
    unittest.main()
