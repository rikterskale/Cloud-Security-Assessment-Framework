"""Key Vault recoverability module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.keyvault import KeyVaultModule
from tests.fakes import make_azure_ctx, make_control

VAULTS = "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults"


class KeyVaultTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = KeyVaultModule()


class TestPurgeProtection(KeyVaultTestCase):
    def test_no_vaults_not_applicable(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={VAULTS: []})
        self.assertEqual(self.module.purge_protection(make_control(), ctx).status, "NotApplicable")

    def test_soft_delete_and_purge_protection_passes(self):
        vaults = [{"name": "kv1", "properties": {"enableSoftDelete": True, "enablePurgeProtection": True}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={VAULTS: vaults})
        self.assertEqual(self.module.purge_protection(make_control(), ctx).status, "Pass")

    def test_missing_purge_protection_fails(self):
        vaults = [{"name": "kv-recoverable", "properties": {"enableSoftDelete": True, "enablePurgeProtection": True}}]
        vaults.append({"name": "kv-no-purge", "properties": {"enableSoftDelete": True}})
        ctx = make_azure_ctx(self.tmp.name, get_value={VAULTS: vaults})
        results = self.module.purge_protection(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"kv-no-purge"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_soft_delete_explicitly_disabled_fails(self):
        vaults = [{"name": "kv-legacy", "properties": {"enableSoftDelete": False, "enablePurgeProtection": True}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={VAULTS: vaults})
        results = self.module.purge_protection(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"kv-legacy"})


if __name__ == "__main__":
    unittest.main()
