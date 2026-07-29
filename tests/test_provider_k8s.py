"""K8sProvider dispatch: module routing, attestations, unknown modules."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from csaf.baseline import Baseline
from csaf.clouds.k8s.provider import K8sProvider
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore
from tests.fakes import FakeK8sApiGroup, FakeK8sSession, NullLogger, make_control


class ProviderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def evidence(self):
        return EvidenceStore(Path(self.tmp.name))


class TestK8sProvider(ProviderTestCase):
    def test_normal_module_dispatch(self):
        rbac_v1 = FakeK8sApiGroup(responses={"list_cluster_role_binding": SimpleNamespace(items=[])})
        session = FakeK8sSession(apis={"rbac_v1": rbac_v1})
        provider = K8sProvider(session, Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(module="rbac", check="cluster_admin_bindings")
        results = provider.evaluate([control], [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "Pass")
        self.assertEqual(results[0].cloud, "K8s")
        self.assertEqual(results[0].account_id, "test-cluster")

    def test_attestation_module_answered_from_engagement(self):
        engagement = Engagement(attestations={"CSAF-K8S-OPS-001": {"status": "Pass", "evidence": "Reviewed."}})
        provider = K8sProvider(FakeK8sSession(), Baseline(), self.evidence(), NullLogger(), engagement, "Assessment")
        control = make_control(control_id="CSAF-K8S-OPS-001", module="attestation", check="n/a")
        results = provider.evaluate([control], [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "Pass")

    def test_attestation_missing_is_not_tested(self):
        provider = K8sProvider(FakeK8sSession(), Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(control_id="CSAF-K8S-OPS-001", module="attestation", check="n/a")
        results = provider.evaluate([control], [])
        self.assertEqual(results[0].status, "NotTested")

    def test_unknown_module_produces_no_result(self):
        provider = K8sProvider(FakeK8sSession(), Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        control = make_control(module="does-not-exist", check="whatever")
        results = provider.evaluate([control], [])
        self.assertEqual(results, [])

    def test_module_instance_reused_across_controls(self):
        rbac_v1 = FakeK8sApiGroup(responses={"list_cluster_role_binding": SimpleNamespace(items=[])})
        session = FakeK8sSession(apis={"rbac_v1": rbac_v1})
        provider = K8sProvider(session, Baseline(), self.evidence(), NullLogger(), Engagement(), "Assessment")
        c1 = make_control(control_id="CSAF-K8S-RBAC-001", module="rbac", check="cluster_admin_bindings")
        c2 = make_control(control_id="CSAF-K8S-RBAC-002", module="rbac", check="cluster_admin_bindings")
        provider.evaluate([c1, c2], [])
        self.assertEqual(len(provider._module_instances), 1)


if __name__ == "__main__":
    unittest.main()
