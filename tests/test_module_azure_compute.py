"""Azure VM compute module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.compute import ComputeModule
from tests.fakes import make_azure_ctx, make_control

VMS = "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines"


class ComputeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = ComputeModule()

    def ctx(self, vms):
        return make_azure_ctx(self.tmp.name, get_value={VMS: vms})


class TestVmManagedDisks(ComputeTestCase):
    def test_no_vms_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.vm_managed_disks(make_control(), ctx).status, "NotApplicable")

    def test_all_managed_disks_pass(self):
        vms = [{"name": "vm1", "properties": {"storageProfile": {"osDisk": {}, "dataDisks": []}}}]
        ctx = self.ctx(vms)
        self.assertEqual(self.module.vm_managed_disks(make_control(), ctx).status, "Pass")

    def test_unmanaged_vhd_disk_fails(self):
        vms = [
            {"name": "vm-managed", "properties": {"storageProfile": {"osDisk": {}, "dataDisks": []}}},
            {
                "name": "vm-vhd",
                "properties": {"storageProfile": {"osDisk": {"vhd": {"uri": "https://x/disk.vhd"}}, "dataDisks": []}},
            },
        ]
        ctx = self.ctx(vms)
        results = self.module.vm_managed_disks(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm-vhd"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_unmanaged_data_disk_also_flagged(self):
        vms = [
            {
                "name": "vm-data-vhd",
                "properties": {"storageProfile": {"osDisk": {}, "dataDisks": [{"vhd": {"uri": "https://x/d.vhd"}}]}},
            }
        ]
        ctx = self.ctx(vms)
        results = self.module.vm_managed_disks(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"vm-data-vhd"})


if __name__ == "__main__":
    unittest.main()
