"""AwsProvider orchestration: global vs regional dispatch and attestations."""

import tempfile
import unittest

from csaf.baseline import Baseline
from csaf.clouds.aws.provider import AwsProvider
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore
from tests.fakes import FakeClient, FakeSession, NullLogger, make_control


def make_provider(tmp, clients=None, engagement=None):
    return AwsProvider(
        session=FakeSession(clients or {}),
        baseline=Baseline(),
        evidence=EvidenceStore(tmp),
        logger=NullLogger(),
        engagement=engagement or Engagement(),
        profile="Assessment",
    )


def analyzer_client():
    return FakeClient(responses={"list_analyzers": {"analyzers": [{"status": "ACTIVE"}]}})


def ebs_client(enabled=True):
    return FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": enabled}})


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_global_module_evaluated_once_regardless_of_regions(self):
        provider = make_provider(self.tmp.name, {"accessanalyzer": analyzer_client()})
        control = make_control(module="identity", check="access_analyzer")
        results = provider.evaluate([control], ["us-east-1", "us-west-2", "eu-central-1"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].region, "global")

    def test_regional_module_evaluated_per_region(self):
        provider = make_provider(self.tmp.name, {"ec2": ebs_client()})
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], ["us-east-1", "us-west-2"])
        self.assertEqual(len(results), 2)
        self.assertEqual({r.region for r in results}, {"us-east-1", "us-west-2"})

    def test_unknown_module_yields_no_results_so_coverage_flags_not_tested(self):
        provider = make_provider(self.tmp.name)
        control = make_control(module="nonexistent", check="whatever")
        self.assertEqual(provider.evaluate([control], ["us-east-1"]), [])

    def test_check_exception_in_one_region_still_evaluates_other_regions(self):
        calls = {"count": 0}

        def flaky(kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                return Exception("throttled")
            return {"EbsEncryptionByDefault": True}

        client = FakeClient(responses={"get_ebs_encryption_by_default": flaky})
        provider = make_provider(self.tmp.name, {"ec2": client})
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], ["us-east-1", "us-west-2"])
        self.assertEqual({r.status for r in results}, {"Error", "Pass"})


class TestAttestations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def attest(self, attestations, severity="HIGH"):
        engagement = Engagement(attestations=attestations)
        provider = make_provider(self.tmp.name, engagement=engagement)
        control = make_control(control_id="CSAF-AWS-OPS-001", module="attestation", check="manual", severity=severity)
        results = provider.evaluate([control], ["us-east-1"])
        self.assertEqual(len(results), 1)
        return results[0]

    def test_missing_attestation_is_not_tested_never_a_pass(self):
        result = self.attest({})
        self.assertEqual(result.status, "NotTested")
        self.assertEqual(result.severity, "INFO")
        self.assertFalse(result.is_finding)

    def test_supplied_pass_attestation(self):
        result = self.attest({"CSAF-AWS-OPS-001": {"status": "Pass", "evidence": "runbook attached"}})
        self.assertEqual(result.status, "Pass")
        self.assertEqual(result.severity, "INFO")
        self.assertEqual(result.observed_value, "runbook attached")

    def test_fail_attestation_keeps_control_severity(self):
        result = self.attest({"CSAF-AWS-OPS-001": {"status": "Fail"}}, severity="MEDIUM")
        self.assertEqual(result.status, "Fail")
        self.assertEqual(result.severity, "MEDIUM")

    def test_bogus_attestation_status_coerced_to_review(self):
        result = self.attest({"CSAF-AWS-OPS-001": {"status": "Totally-Fine"}})
        self.assertEqual(result.status, "Review")

    def test_attestation_confidence_is_low(self):
        result = self.attest({"CSAF-AWS-OPS-001": {"status": "Pass"}})
        self.assertEqual(result.confidence, "LOW")


if __name__ == "__main__":
    unittest.main()
