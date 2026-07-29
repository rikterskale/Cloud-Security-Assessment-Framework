"""Storage-account module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.storage import StorageModule
from tests.fakes import make_azure_ctx, make_control

ACCOUNTS = "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts"


def account(name, **props):
    return {"name": name, "properties": props}


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = StorageModule()

    def ctx(self, accounts):
        return make_azure_ctx(self.tmp.name, get_value={ACCOUNTS: accounts})


class TestNoAccounts(StorageTestCase):
    def test_all_checks_not_applicable_when_no_accounts(self):
        ctx = self.ctx([])
        for check in (
            self.module.secure_transfer,
            self.module.blob_public_access,
            self.module.minimum_tls,
            self.module.default_network_deny,
        ):
            self.assertEqual(check(make_control(), ctx).status, "NotApplicable")


class TestSecureTransfer(StorageTestCase):
    def test_https_only_passes(self):
        ctx = self.ctx([account("sa1", supportsHttpsTrafficOnly=True)])
        self.assertEqual(self.module.secure_transfer(make_control(), ctx).status, "Pass")

    def test_missing_https_only_fails(self):
        ctx = self.ctx([account("sa1", supportsHttpsTrafficOnly=False)])
        results = self.module.secure_transfer(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"sa1"})


class TestBlobPublicAccess(StorageTestCase):
    def test_disallowed_passes(self):
        ctx = self.ctx([account("sa1", allowBlobPublicAccess=False)])
        self.assertEqual(self.module.blob_public_access(make_control(), ctx).status, "Pass")

    def test_missing_property_treated_as_offender(self):
        ctx = self.ctx([account("sa1")])
        results = self.module.blob_public_access(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"sa1"})


class TestMinimumTls(StorageTestCase):
    def test_tls12_passes(self):
        ctx = self.ctx([account("sa1", minimumTlsVersion="TLS1_2")])
        self.assertEqual(self.module.minimum_tls(make_control(), ctx).status, "Pass")

    def test_below_tls12_fails(self):
        ctx = self.ctx([account("sa1", minimumTlsVersion="TLS1_0")])
        results = self.module.minimum_tls(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"sa1"})


class TestDefaultNetworkDeny(StorageTestCase):
    def test_deny_default_passes(self):
        ctx = self.ctx([account("sa1", networkAcls={"defaultAction": "Deny"})])
        self.assertEqual(self.module.default_network_deny(make_control(), ctx).status, "Pass")

    def test_allow_default_fails(self):
        ctx = self.ctx([account("sa1", networkAcls={"defaultAction": "Allow"})])
        results = self.module.default_network_deny(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"sa1"})


if __name__ == "__main__":
    unittest.main()
