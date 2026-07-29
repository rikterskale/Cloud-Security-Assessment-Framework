"""Cloud SQL module checks against faked GCP REST responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.sql import SQLADMIN_V1, SqlModule
from tests.fakes import make_control, make_gcp_ctx

INSTANCES_URL = f"{SQLADMIN_V1}/instances"


def instance(name, authorized_networks=(), ipv4_enabled=True, require_ssl=False, ssl_mode=None):
    ip_config = {
        "ipv4Enabled": ipv4_enabled,
        "authorizedNetworks": [{"value": n} for n in authorized_networks],
        "requireSsl": require_ssl,
    }
    if ssl_mode is not None:
        ip_config["sslMode"] = ssl_mode
    return {"name": name, "settings": {"ipConfiguration": ip_config}}


class SqlTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = SqlModule()

    def ctx(self, instances):
        return make_gcp_ctx(self.tmp.name, get_list={INSTANCES_URL: instances})


class TestSqlOpenToWorld(SqlTestCase):
    def test_no_instances_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.sql_open_to_world(make_control(), ctx).status, "NotApplicable")

    def test_no_open_networks_passes(self):
        ctx = self.ctx([instance("db1", authorized_networks=["10.0.0.0/8"])])
        self.assertEqual(self.module.sql_open_to_world(make_control(), ctx).status, "Pass")

    def test_world_open_flagged(self):
        ctx = self.ctx([instance("db1", authorized_networks=["0.0.0.0/0"])])
        results = self.module.sql_open_to_world(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"db1"})


class TestSqlRequireSsl(SqlTestCase):
    def test_no_instances_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.sql_require_ssl(make_control(), ctx).status, "NotApplicable")

    def test_private_ip_only_instance_skipped(self):
        ctx = self.ctx([instance("db-private", ipv4_enabled=False)])
        self.assertEqual(self.module.sql_require_ssl(make_control(), ctx).status, "Pass")

    def test_require_ssl_true_passes(self):
        ctx = self.ctx([instance("db1", require_ssl=True)])
        self.assertEqual(self.module.sql_require_ssl(make_control(), ctx).status, "Pass")

    def test_ssl_mode_enforcing_passes(self):
        ctx = self.ctx([instance("db1", ssl_mode="TRUSTED_CLIENT_CERTIFICATE_REQUIRED")])
        self.assertEqual(self.module.sql_require_ssl(make_control(), ctx).status, "Pass")

    def test_no_ssl_enforcement_fails(self):
        ctx = self.ctx([instance("db1")])
        results = self.module.sql_require_ssl(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"db1"})


if __name__ == "__main__":
    unittest.main()
