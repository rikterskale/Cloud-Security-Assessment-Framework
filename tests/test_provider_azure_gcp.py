"""Azure and GCP provider dispatch: module routing, attestations, unknown modules."""

import tempfile
import unittest
from pathlib import Path

from csaf.baseline import Baseline
from csaf.clouds.azure.provider import AzureProvider
from csaf.clouds.gcp.provider import GcpProvider
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore
from tests.fakes import FakeArmSession, FakeGcpSession, NullLogger, make_control

ROLE_DEFS = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions"


class ProviderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def evidence(self):
        return EvidenceStore(Path(self.tmp.name))


class TestAzureProvider(ProviderTestCase):
    def test_normal_module_dispatch(self):
        session = FakeArmSession(get_value={ROLE_DEFS: []})
        provider = AzureProvider(session, Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(module="identity", check="custom_owner_roles")
        results = provider.evaluate([control], [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "Pass")
        self.assertEqual(results[0].cloud, "Azure")
        self.assertEqual(results[0].account_id, "sub-1")

    def test_attestation_module_answered_from_engagement(self):
        engagement = Engagement(attestations={"CSAF-AZ-OPS-001": {"status": "Pass", "evidence": "Reviewed."}})
        provider = AzureProvider(FakeArmSession(), Baseline(), self.evidence(), NullLogger(), engagement, "Assessment")
        control = make_control(control_id="CSAF-AZ-OPS-001", module="attestation", check="n/a")
        results = provider.evaluate([control], [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "Pass")

    def test_attestation_missing_is_not_tested(self):
        provider = AzureProvider(
            FakeArmSession(), Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment"
        )
        control = make_control(control_id="CSAF-AZ-OPS-001", module="attestation", check="n/a")
        results = provider.evaluate([control], [])
        self.assertEqual(results[0].status, "NotTested")

    def test_unknown_module_produces_no_result(self):
        provider = AzureProvider(
            FakeArmSession(), Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment"
        )
        control = make_control(module="does-not-exist", check="whatever")
        results = provider.evaluate([control], [])
        self.assertEqual(results, [])

    def test_module_instance_reused_across_controls(self):
        session = FakeArmSession(get_value={ROLE_DEFS: []})
        provider = AzureProvider(session, Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        c1 = make_control(control_id="CSAF-AZ-IAM-001", module="identity", check="custom_owner_roles")
        c2 = make_control(control_id="CSAF-AZ-IAM-002", module="identity", check="custom_owner_roles")
        provider.evaluate([c1, c2], [])
        self.assertEqual(len(provider._module_instances), 1)


class TestGcpProvider(ProviderTestCase):
    def test_normal_module_dispatch(self):
        from csaf.clouds.gcp.modules.storage import GCS_V1

        session = FakeGcpSession(get_list={f"{GCS_V1}/b": []})
        provider = GcpProvider(session, Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(module="storage", check="bucket_public_iam")
        results = provider.evaluate([control], [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "NotApplicable")
        self.assertEqual(results[0].cloud, "GCP")
        self.assertEqual(results[0].account_id, "proj-1")

    def test_attestation_module_answered_from_engagement(self):
        engagement = Engagement(attestations={"CSAF-GCP-OPS-001": {"status": "Review", "evidence": "Pending."}})
        provider = GcpProvider(FakeGcpSession(), Baseline(), self.evidence(), NullLogger(), engagement, "Assessment")
        control = make_control(control_id="CSAF-GCP-OPS-001", module="attestation", check="n/a")
        results = provider.evaluate([control], [])
        self.assertEqual(results[0].status, "Review")

    def test_unknown_module_produces_no_result(self):
        provider = GcpProvider(FakeGcpSession(), Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(module="does-not-exist", check="whatever")
        results = provider.evaluate([control], [])
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
