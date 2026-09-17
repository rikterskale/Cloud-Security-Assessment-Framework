"""Kubernetes default service-account automount checks."""

import tempfile
import unittest
from types import SimpleNamespace

from csaf.clouds.k8s.modules.service_accounts import ServiceAccountsModule
from tests.fakes import FakeK8sApiGroup, make_control, make_k8s_ctx


def account(name, namespace, automount=None):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        automount_service_account_token=automount,
    )


class TestDefaultSaAutomount(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = ServiceAccountsModule()

    def ctx(self, accounts):
        core_v1 = FakeK8sApiGroup(
            responses={"list_service_account_for_all_namespaces": SimpleNamespace(items=accounts)}
        )
        return make_k8s_ctx(self.tmp.name, apis={"core_v1": core_v1})

    def test_default_sa_automount_flagged(self):
        results = self.module.default_sa_automount(
            make_control(),
            self.ctx([account("default", "app"), account("default", "kube-system")]),
        )
        self.assertEqual({r.resource_id for r in results}, {"app/default"})

    def test_disabled_automount_passes(self):
        result = self.module.default_sa_automount(
            make_control(), self.ctx([account("default", "app", automount=False)])
        )
        self.assertEqual(result.status, "Pass")


if __name__ == "__main__":
    unittest.main()
