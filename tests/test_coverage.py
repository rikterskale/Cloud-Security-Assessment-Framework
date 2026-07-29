import unittest

from csaf.coverage import compute_coverage, compute_risk_score
from csaf.model import ControlResult


def cr(cid, status, severity="HIGH"):
    return ControlResult(
        control_id=cid,
        title="t",
        category="c",
        status=status,
        severity=severity if status in ("Fail", "Review") else "INFO",
        cloud="AWS",
        account_id="1",
    )


class TestCoverage(unittest.TestCase):
    def test_missing_control_counts_as_not_tested(self):
        selected = {"CSAF-AWS-IAM-001", "CSAF-AWS-IAM-002", "CSAF-AWS-S3-001"}
        results = [cr("CSAF-AWS-IAM-001", "Pass"), cr("CSAF-AWS-IAM-002", "Fail")]
        cov = compute_coverage(selected, results)
        self.assertEqual(cov.selected, 3)
        self.assertEqual(cov.not_tested, 1)
        self.assertFalse(cov.all_selected_executed)

    def test_fail_dominates_pass_for_same_control(self):
        selected = {"CSAF-AWS-S3-002"}
        results = [cr("CSAF-AWS-S3-002", "Pass"), cr("CSAF-AWS-S3-002", "Fail")]
        cov = compute_coverage(selected, results)
        self.assertEqual(cov.failed, 1)
        self.assertEqual(cov.passed, 0)

    def test_error_breaks_completeness(self):
        selected = {"CSAF-AWS-IAM-001"}
        cov = compute_coverage(selected, [cr("CSAF-AWS-IAM-001", "Error")])
        self.assertEqual(cov.error, 1)
        self.assertFalse(cov.all_selected_executed)

    def test_error_dominates_pass_for_same_control(self):
        # A control that passed in one region but errored in another did not
        # fully execute; an Error anywhere must never be masked by a Pass.
        selected = {"CSAF-AWS-EC2-002"}
        results = [cr("CSAF-AWS-EC2-002", "Pass"), cr("CSAF-AWS-EC2-002", "Error")]
        cov = compute_coverage(selected, results)
        self.assertEqual(cov.error, 1)
        self.assertEqual(cov.passed, 0)
        self.assertFalse(cov.all_selected_executed)

    def test_error_dominates_fail_for_coverage_rollup(self):
        # Coverage tracks execution completeness; the Fail still produces a
        # finding because findings derive from raw per-result statuses.
        selected = {"CSAF-AWS-NET-001"}
        results = [cr("CSAF-AWS-NET-001", "Fail"), cr("CSAF-AWS-NET-001", "Error")]
        cov = compute_coverage(selected, results)
        self.assertEqual(cov.error, 1)
        self.assertEqual(cov.failed, 0)
        self.assertFalse(cov.all_selected_executed)
        self.assertTrue(any(r.is_finding for r in results), "the Fail result still yields a finding")

    def test_review_dominates_pass(self):
        selected = {"CSAF-AWS-IAM-010"}
        cov = compute_coverage(selected, [cr("CSAF-AWS-IAM-010", "Pass"), cr("CSAF-AWS-IAM-010", "Review")])
        self.assertEqual(cov.review, 1)
        self.assertEqual(cov.passed, 0)

    def test_executed_ratio_and_empty_selection(self):
        cov = compute_coverage(set(), [])
        self.assertEqual(cov.selected, 0)
        self.assertEqual(cov.executed_ratio, 0.0)
        partial = compute_coverage({"A", "B", "C", "D"}, [cr("A", "Pass"), cr("B", "Fail"), cr("C", "NotApplicable")])
        self.assertEqual(partial.executed, 3)
        self.assertEqual(partial.executed_ratio, 0.75)

    def test_risk_scoring_rating(self):
        clean = compute_risk_score([cr("CSAF-AWS-IAM-001", "Pass")])
        self.assertEqual(clean["rating"], "MINIMAL")
        crit = compute_risk_score([cr(f"C{i}", "Fail", "CRITICAL") for i in range(5)])
        self.assertEqual(crit["rating"], "CRITICAL")
        self.assertLessEqual(crit["normalised_score"], 100)

    def test_risk_rating_boundaries(self):
        # weighted/2: 1 HIGH = 10 -> LOW; 1 CRITICAL = 20 -> MEDIUM;
        # 1 CRITICAL + 1 HIGH + 1 MEDIUM = 35 -> MEDIUM; 2 CRITICAL + 1 MEDIUM = 45 -> HIGH;
        # 4 CRITICAL = 80 -> CRITICAL (>= 70).
        cases = [
            ([("A", "HIGH")], 10.0, "LOW"),
            ([("A", "CRITICAL")], 20.0, "MEDIUM"),
            ([("A", "CRITICAL"), ("B", "HIGH"), ("C", "MEDIUM")], 35.0, "MEDIUM"),
            ([("A", "CRITICAL"), ("B", "CRITICAL"), ("C", "MEDIUM")], 45.0, "HIGH"),
            ([("A", "CRITICAL"), ("B", "CRITICAL"), ("C", "CRITICAL"), ("D", "CRITICAL")], 80.0, "CRITICAL"),
        ]
        for spec, expected_score, expected_rating in cases:
            risk = compute_risk_score([cr(cid, "Fail", sev) for cid, sev in spec])
            self.assertEqual(risk["normalised_score"], expected_score, spec)
            self.assertEqual(risk["rating"], expected_rating, spec)

    def test_error_and_not_tested_never_contribute_to_risk(self):
        results = [cr("A", "Error"), cr("B", "NotTested"), cr("C", "NotApplicable"), cr("D", "Pass")]
        risk = compute_risk_score(results)
        self.assertEqual(risk["weighted_score"], 0)
        self.assertEqual(risk["rating"], "MINIMAL")


if __name__ == "__main__":
    unittest.main()
