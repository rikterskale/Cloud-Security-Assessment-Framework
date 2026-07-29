"""Kubernetes RBAC module checks against faked API responses."""

import tempfile
import unittest
from types import SimpleNamespace

from csaf.clouds.k8s.modules.rbac import RbacModule
from tests.fakes import FakeK8sApiGroup, make_control, make_k8s_ctx


def subject(kind, name, namespace=None):
    return SimpleNamespace(kind=kind, name=name, namespace=namespace)


def binding(name, role_name, subjects):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name),
        role_ref=SimpleNamespace(name=role_name),
        subjects=subjects,
    )


class RbacTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = RbacModule()

    def ctx(self, bindings):
        rbac_v1 = FakeK8sApiGroup(responses={"list_cluster_role_binding": SimpleNamespace(items=bindings)})
        return make_k8s_ctx(self.tmp.name, apis={"rbac_v1": rbac_v1})


class TestClusterAdminBindings(RbacTestCase):
    def test_no_bindings_passes(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.cluster_admin_bindings(make_control(), ctx).status, "Pass")

    def test_non_cluster_admin_role_ignored(self):
        bindings = [binding("b1", "edit", [subject("User", "alice")])]
        ctx = self.ctx(bindings)
        self.assertEqual(self.module.cluster_admin_bindings(make_control(), ctx).status, "Pass")

    def test_user_bound_to_cluster_admin_flagged(self):
        bindings = [binding("demo-admin-binding", "cluster-admin", [subject("User", "alice")])]
        ctx = self.ctx(bindings)
        results = self.module.cluster_admin_bindings(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"demo-admin-binding"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_kube_system_service_account_not_flagged(self):
        bindings = [
            binding(
                "system-binding", "cluster-admin", [subject("ServiceAccount", "controller", namespace="kube-system")]
            )
        ]
        ctx = self.ctx(bindings)
        self.assertEqual(self.module.cluster_admin_bindings(make_control(), ctx).status, "Pass")

    def test_system_masters_group_not_flagged(self):
        bindings = [binding("masters-binding", "cluster-admin", [subject("Group", "system:masters")])]
        ctx = self.ctx(bindings)
        self.assertEqual(self.module.cluster_admin_bindings(make_control(), ctx).status, "Pass")

    def test_workload_service_account_flagged(self):
        bindings = [
            binding("app-binding", "cluster-admin", [subject("ServiceAccount", "app-sa", namespace="default")])
        ]
        ctx = self.ctx(bindings)
        results = self.module.cluster_admin_bindings(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"app-binding"})


if __name__ == "__main__":
    unittest.main()
