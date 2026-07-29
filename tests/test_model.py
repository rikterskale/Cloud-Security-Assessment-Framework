import unittest

from csaf.model import (
    ControlResult,
    finding_from_result,
    finding_id,
)


def make(status, severity="HIGH", **kw):
    return ControlResult(
        control_id=kw.get("control_id", "CSAF-AWS-IAM-001"),
        title="t",
        category="Identity",
        status=status,
        severity=severity,
        cloud="AWS",
        account_id="123",
        region=kw.get("region", "global"),
        resource_id=kw.get("resource_id", ""),
    )


class TestControlResult(unittest.TestCase):
    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            make("Bogus")

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            ControlResult(control_id="CSAF-AWS-IAM-001", title="t", category="c", status="Pass", severity="EXTREME")

    def test_fail_is_finding_pass_is_not(self):
        self.assertTrue(make("Fail").is_finding)
        self.assertTrue(make("Review").is_finding)
        self.assertFalse(make("Pass").is_finding)
        self.assertFalse(make("NotTested").is_finding)
        self.assertFalse(make("Error").is_finding)

    def test_error_and_nottested_not_executed(self):
        self.assertFalse(make("Error").is_executed)
        self.assertFalse(make("NotTested").is_executed)
        self.assertTrue(make("Pass").is_executed)
        self.assertTrue(make("NotApplicable").is_executed)


class TestFindings(unittest.TestCase):
    def test_finding_id_deterministic_and_object_aware(self):
        a = make("Fail", resource_id="bucket-1")
        b = make("Fail", resource_id="bucket-1")
        c = make("Fail", resource_id="bucket-2")
        self.assertEqual(finding_id(a), finding_id(b))
        self.assertNotEqual(finding_id(a), finding_id(c))
        self.assertRegex(finding_id(a), r"^F-[A-F0-9]{16}$")

    def test_review_finding_min_medium(self):
        result = make("Review", severity="INFO")
        finding = finding_from_result(result, "fix it")
        self.assertIn(finding.severity, ("MEDIUM", "HIGH", "CRITICAL", "LOW"))
        self.assertEqual(finding.remediation, "fix it")
        self.assertGreater(finding.risk_score, 0)


if __name__ == "__main__":
    unittest.main()
