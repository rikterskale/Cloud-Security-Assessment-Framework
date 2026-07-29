"""GCE compute module checks against faked GCP REST responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.compute import GCE_V1, ComputeModule
from tests.fakes import make_control, make_gcp_ctx

INSTANCES_URL = f"{GCE_V1}/projects/proj-1/aggregated/instances"
PROJECT_URL = f"{GCE_V1}/projects/proj-1"


def instance(name, service_accounts=None, external_ip=False, metadata=None):
    nic = {"accessConfigs": [{"natIP": "1.2.3.4"}]} if external_ip else {"accessConfigs": []}
    return {
        "name": name,
        "serviceAccounts": service_accounts or [],
        "networkInterfaces": [nic],
        "metadata": metadata or {},
    }


class ComputeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = ComputeModule()

    def ctx(self, instances, project=None):
        return make_gcp_ctx(
            self.tmp.name,
            get_aggregated={INSTANCES_URL: instances},
            get={PROJECT_URL: project or {"commonInstanceMetadata": {}}},
        )


class TestDefaultServiceAccount(ComputeTestCase):
    def test_no_non_gke_instances_not_applicable(self):
        ctx = self.ctx([instance("gke-node-1")])
        self.assertEqual(self.module.default_service_account(make_control(), ctx).status, "NotApplicable")

    def test_default_sa_flagged(self):
        ctx = self.ctx([instance("vm1", service_accounts=[{"email": "123-compute@developer.gserviceaccount.com"}])])
        results = self.module.default_service_account(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm1"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_custom_sa_passes(self):
        ctx = self.ctx([instance("vm1", service_accounts=[{"email": "custom-sa@proj-1.iam.gserviceaccount.com"}])])
        self.assertEqual(self.module.default_service_account(make_control(), ctx).status, "Pass")


class TestPublicIpInstances(ComputeTestCase):
    def test_no_instances_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.public_ip_instances(make_control(), ctx).status, "NotApplicable")

    def test_external_ip_flagged(self):
        ctx = self.ctx([instance("vm1", external_ip=True)])
        results = self.module.public_ip_instances(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm1"})

    def test_no_external_ip_passes(self):
        ctx = self.ctx([instance("vm1", external_ip=False)])
        self.assertEqual(self.module.public_ip_instances(make_control(), ctx).status, "Pass")


class TestOsLogin(ComputeTestCase):
    def test_project_metadata_disabled_fails(self):
        ctx = self.ctx([instance("vm1")], project={"commonInstanceMetadata": {}})
        result = self.module.os_login(make_control(), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertEqual(result.resource_type, "project")

    def test_project_enabled_no_overrides_passes(self):
        project = {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}
        ctx = self.ctx([instance("vm1")], project=project)
        self.assertEqual(self.module.os_login(make_control(), ctx).status, "Pass")

    def test_instance_override_disables_and_fails(self):
        project = {"commonInstanceMetadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}}
        overriding = instance("vm-override", metadata={"items": [{"key": "enable-oslogin", "value": "false"}]})
        ctx = self.ctx([overriding], project=project)
        results = self.module.os_login(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm-override"})


class TestSerialPortsDisabled(ComputeTestCase):
    def test_no_instances_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.serial_ports_disabled(make_control(), ctx).status, "NotApplicable")

    def test_serial_port_enabled_flagged(self):
        vm = instance("vm1", metadata={"items": [{"key": "serial-port-enable", "value": "true"}]})
        ctx = self.ctx([vm])
        results = self.module.serial_ports_disabled(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm1"})

    def test_serial_port_disabled_passes(self):
        ctx = self.ctx([instance("vm1")])
        self.assertEqual(self.module.serial_ports_disabled(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
