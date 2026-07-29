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

    def test_risk_scoring_rating(self):
        clean = compute_risk_score([cr("CSAF-AWS-IAM-001", "Pass")])
        self.assertEqual(clean["rating"], "MINIMAL")
        crit = compute_risk_score([cr(f"C{i}", "Fail", "CRITICAL") for i in range(5)])
        self.assertEqual(crit["rating"], "CRITICAL")
        self.assertLessEqual(crit["normalised_score"], 100)


if __name__ == "__main__":
    unittest.main()
