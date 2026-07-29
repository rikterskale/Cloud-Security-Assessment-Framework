"""Kubernetes network-segmentation module checks against faked API responses."""

import tempfile
import unittest
from types import SimpleNamespace

from csaf.clouds.k8s.modules.network import NetworkModule
from tests.fakes import FakeK8sApiGroup, make_control, make_k8s_ctx


def namespace(name):
    return SimpleNamespace(metadata=SimpleNamespace(name=name))


def policy(namespace_name):
    return SimpleNamespace(metadata=SimpleNamespace(namespace=namespace_name))


class NetworkTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = NetworkModule()

    def ctx(self, namespaces, policies):
        core_v1 = FakeK8sApiGroup(responses={"list_namespace": SimpleNamespace(items=namespaces)})
        networking_v1 = FakeK8sApiGroup(
            responses={"list_network_policy_for_all_namespaces": SimpleNamespace(items=policies)}
        )
        return make_k8s_ctx(self.tmp.name, apis={"core_v1": core_v1, "networking_v1": networking_v1})


class TestNamespaceWithoutNetworkPolicy(NetworkTestCase):
    def test_no_workload_namespaces_not_applicable(self):
        ctx = self.ctx([namespace("kube-system")], [])
        self.assertEqual(self.module.namespace_without_network_policy(make_control(), ctx).status, "NotApplicable")

    def test_all_namespaces_have_a_policy_passes(self):
        ctx = self.ctx([namespace("default"), namespace("prod")], [policy("default"), policy("prod")])
        self.assertEqual(self.module.namespace_without_network_policy(make_control(), ctx).status, "Pass")

    def test_namespace_without_policy_flagged(self):
        ctx = self.ctx([namespace("default"), namespace("prod")], [policy("prod")])
        results = self.module.namespace_without_network_policy(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"default"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_system_namespaces_excluded_from_denominator(self):
        ctx = self.ctx([namespace("default"), namespace("kube-system"), namespace("kube-public")], [policy("default")])
        self.assertEqual(self.module.namespace_without_network_policy(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
