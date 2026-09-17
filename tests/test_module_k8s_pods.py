"""Kubernetes pod-security module checks against faked API responses."""

import tempfile
import unittest
from types import SimpleNamespace

from csaf.clouds.k8s.modules.pods import PodsModule
from tests.fakes import FakeK8sApiGroup, make_control, make_k8s_ctx


def container(name, privileged=None):
    security_context = SimpleNamespace(privileged=privileged) if privileged is not None else None
    return SimpleNamespace(name=name, security_context=security_context)


def pod(name, namespace="default", host_network=False, containers=None, init_containers=None):
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        spec=SimpleNamespace(
            host_network=host_network,
            containers=containers or [container("app")],
            init_containers=init_containers or [],
        ),
    )


class PodsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = PodsModule()

    def ctx(self, pods):
        core_v1 = FakeK8sApiGroup(responses={"list_pod_for_all_namespaces": SimpleNamespace(items=pods)})
        return make_k8s_ctx(self.tmp.name, apis={"core_v1": core_v1})


class TestPrivilegedContainers(PodsTestCase):
    def test_no_workload_pods_not_applicable(self):
        ctx = self.ctx([pod("kube-dns", namespace="kube-system")])
        self.assertEqual(self.module.privileged_containers(make_control(), ctx).status, "NotApplicable")

    def test_no_privileged_containers_passes(self):
        ctx = self.ctx([pod("app1", containers=[container("app", privileged=False)])])
        self.assertEqual(self.module.privileged_containers(make_control(), ctx).status, "Pass")

    def test_privileged_container_flagged(self):
        ctx = self.ctx([pod("legacy-app", containers=[container("app", privileged=True)])])
        results = self.module.privileged_containers(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"default/legacy-app"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_privileged_init_container_flagged(self):
        ctx = self.ctx(
            [pod("init-priv", containers=[container("app")], init_containers=[container("setup", privileged=True)])]
        )
        results = self.module.privileged_containers(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"default/init-priv"})

    def test_missing_security_context_not_flagged(self):
        ctx = self.ctx([pod("plain", containers=[container("app")])])
        self.assertEqual(self.module.privileged_containers(make_control(), ctx).status, "Pass")


class TestHostNetworkPods(PodsTestCase):
    def test_no_workload_pods_not_applicable(self):
        ctx = self.ctx([pod("kube-proxy", namespace="kube-system", host_network=True)])
        self.assertEqual(self.module.host_network_pods(make_control(), ctx).status, "NotApplicable")

    def test_no_host_network_passes(self):
        ctx = self.ctx([pod("app1", host_network=False)])
        self.assertEqual(self.module.host_network_pods(make_control(), ctx).status, "Pass")

    def test_host_network_pod_flagged(self):
        ctx = self.ctx([pod("host-net-debug", host_network=True)])
        results = self.module.host_network_pods(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"default/host-net-debug"})


class TestHostPidAndIpc(PodsTestCase):
    def test_host_pid_flagged(self):
        p = pod("pid-pod")
        p.spec.host_pid = True
        results = self.module.host_pid_pods(make_control(), self.ctx([p]))
        self.assertEqual({r.resource_id for r in results}, {"default/pid-pod"})

    def test_host_ipc_flagged(self):
        p = pod("ipc-pod")
        p.spec.host_ipc = True
        results = self.module.host_ipc_pods(make_control(), self.ctx([p]))
        self.assertEqual({r.resource_id for r in results}, {"default/ipc-pod"})

    def test_host_path_flagged(self):
        p = pod("hp")
        p.spec.volumes = [SimpleNamespace(host_path=SimpleNamespace(path="/var/run/docker.sock"))]
        results = self.module.host_path_volumes(make_control(), self.ctx([p]))
        self.assertEqual({r.resource_id for r in results}, {"default/hp"})

    def test_privilege_escalation_flagged(self):
        c = container("app", privileged=False)
        c.security_context = SimpleNamespace(privileged=False, allow_privilege_escalation=True)
        results = self.module.privilege_escalation(make_control(), self.ctx([pod("pe", containers=[c])]))
        self.assertEqual({r.resource_id for r in results}, {"default/pe"})


if __name__ == "__main__":
    unittest.main()
