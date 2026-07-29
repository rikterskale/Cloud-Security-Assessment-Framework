"""Microsoft Defender for Cloud module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.defender import DefenderModule
from tests.fakes import make_azure_ctx, make_control

PRICINGS = "/subscriptions/sub-1/providers/Microsoft.Security/pricings"
CONTACTS = "/subscriptions/sub-1/providers/Microsoft.Security/securityContacts"


class DefenderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = DefenderModule()


class TestDefenderPlans(DefenderTestCase):
    def test_all_required_plans_standard_passes(self):
        pricings = {
            "value": [
                {"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}},
                {"name": "StorageAccounts", "properties": {"pricingTier": "Standard"}},
                {"name": "SqlServers", "properties": {"pricingTier": "Standard"}},
            ]
        }
        ctx = make_azure_ctx(self.tmp.name, get={PRICINGS: pricings})
        self.assertEqual(self.module.defender_plans(make_control(), ctx).status, "Pass")

    def test_missing_or_free_plan_fails(self):
        pricings = {
            "value": [
                {"name": "VirtualMachines", "properties": {"pricingTier": "Free"}},
                {"name": "StorageAccounts", "properties": {"pricingTier": "Standard"}},
            ]
        }
        ctx = make_azure_ctx(self.tmp.name, get={PRICINGS: pricings})
        results = self.module.defender_plans(make_control(), ctx)
        offenders = {r.resource_id for r in results}
        self.assertIn("VirtualMachines", offenders)
        self.assertIn("SqlServers", offenders)
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestSecurityContact(DefenderTestCase):
    def test_configured_email_passes(self):
        contacts = [{"properties": {"emails": "secteam@example.com"}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={CONTACTS: contacts})
        self.assertEqual(self.module.security_contact(make_control(), ctx).status, "Pass")

    def test_semicolon_separated_singular_email_field_passes(self):
        contacts = [{"properties": {"email": "a@example.com;b@example.com"}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={CONTACTS: contacts})
        self.assertEqual(self.module.security_contact(make_control(), ctx).status, "Pass")

    def test_no_contact_fails(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={CONTACTS: []})
        self.assertEqual(self.module.security_contact(make_control(), ctx).status, "Fail")


if __name__ == "__main__":
    unittest.main()
