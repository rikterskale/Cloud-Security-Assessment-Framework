"""Azure SQL server module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.sql import SqlModule
from tests.fakes import make_azure_ctx, make_control

SERVERS = "/subscriptions/sub-1/providers/Microsoft.Sql/servers"


def server(name, public_network_access="Disabled"):
    return {
        "id": f"/subscriptions/sub-1/providers/Microsoft.Sql/servers/{name}",
        "name": name,
        "properties": {"publicNetworkAccess": public_network_access},
    }


class SqlTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = SqlModule()


class TestSqlAuditing(SqlTestCase):
    def test_no_servers_not_applicable(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={SERVERS: []})
        self.assertEqual(self.module.sql_auditing(make_control(), ctx).status, "NotApplicable")

    def test_auditing_enabled_passes(self):
        srv = server("srv1")
        ctx = make_azure_ctx(
            self.tmp.name,
            get_value={SERVERS: [srv]},
            get={f"{srv['id']}/auditingSettings/default": {"properties": {"state": "Enabled"}}},
        )
        self.assertEqual(self.module.sql_auditing(make_control(), ctx).status, "Pass")

    def test_auditing_disabled_fails(self):
        srv = server("srv1")
        ctx = make_azure_ctx(
            self.tmp.name,
            get_value={SERVERS: [srv]},
            get={f"{srv['id']}/auditingSettings/default": {"properties": {"state": "Disabled"}}},
        )
        results = self.module.sql_auditing(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"srv1"})
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestSqlPublicNetworkAccess(SqlTestCase):
    def test_no_servers_not_applicable(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={SERVERS: []})
        self.assertEqual(self.module.sql_public_network_access(make_control(), ctx).status, "NotApplicable")

    def test_disabled_passes(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={SERVERS: [server("srv1", "Disabled")]})
        self.assertEqual(self.module.sql_public_network_access(make_control(), ctx).status, "Pass")

    def test_enabled_fails(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={SERVERS: [server("srv1", "Enabled")]})
        results = self.module.sql_public_network_access(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"srv1"})

    def test_missing_property_defaults_to_enabled_and_fails(self):
        srv = {"id": "x", "name": "srv-default", "properties": {}}
        ctx = make_azure_ctx(self.tmp.name, get_value={SERVERS: [srv]})
        results = self.module.sql_public_network_access(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"srv-default"})


if __name__ == "__main__":
    unittest.main()
