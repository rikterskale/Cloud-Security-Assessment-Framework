"""Azure metadata-only secret-location discovery tests."""

import tempfile
import unittest

from csaf.clouds.azure.modules.secret_discovery import SecretDiscoveryModule
from tests.fakes import make_azure_ctx, make_control

SUB = "/subscriptions/sub-1"
SITES = f"{SUB}/providers/Microsoft.Web/sites"
AUTOMATION = f"{SUB}/providers/Microsoft.Automation/automationAccounts"
VAULTS = f"{SUB}/providers/Microsoft.KeyVault/vaults"


class TestSecretDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = SecretDiscoveryModule()

    def _ctx(self, **kwargs):
        ctx = make_azure_ctx(self.tmp.name, **kwargs)
        ctx.profile = "Validation"
        return ctx

    def test_requires_explicit_cli_enablement(self):
        result = self.module.secret_bearing_locations(make_control(), self._ctx())
        self.assertEqual(result.status, "NotApplicable")
        self.assertIn("--allow-secret-discovery", result.observed_value)

    def test_reports_metadata_locations_without_writing_evidence(self):
        ctx = self._ctx(
            get_value={
                SITES: [{"name": "api", "kind": "app,linux"}, {"name": "worker", "kind": "functionapp,linux"}],
                AUTOMATION: [{"name": "runbooks"}],
                VAULTS: [{"name": "kv-prod"}],
            }
        )
        ctx.secret_discovery_enabled = True
        results = self.module.secret_bearing_locations(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"api", "worker", "runbooks", "kv-prod"})
        self.assertTrue(all(r.status == "Review" for r in results))
        self.assertTrue(all("No value was requested" in r.observed_value for r in results))
        self.assertFalse(list(ctx.evidence.evidence_dir.rglob("*")))

    def test_empty_inventory_passes(self):
        ctx = self._ctx(get_value={SITES: [], AUTOMATION: [], VAULTS: []})
        ctx.secret_discovery_enabled = True
        result = self.module.secret_bearing_locations(make_control(), ctx)
        self.assertEqual(result.status, "Pass")


if __name__ == "__main__":
    unittest.main()
