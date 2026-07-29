"""Cloud Logging / audit-configuration module checks against faked responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.identity import CRM_V1
from csaf.clouds.gcp.modules.logging_audit import LOGGING_V2, LoggingModule
from tests.fakes import make_control, make_gcp_ctx

IAM_POLICY_URL = f"{CRM_V1}/projects/proj-1:getIamPolicy"
SINKS_URL = f"{LOGGING_V2}/projects/proj-1/sinks"


class LoggingTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = LoggingModule()


class TestAuditLogging(LoggingTestCase):
    def test_no_all_services_config_fails(self):
        ctx = make_gcp_ctx(self.tmp.name, post={IAM_POLICY_URL: {"bindings": [], "auditConfigs": []}})
        self.assertEqual(self.module.audit_logging(make_control(), ctx).status, "Fail")

    def test_complete_coverage_no_exemptions_passes(self):
        config = {
            "service": "allServices",
            "auditLogConfigs": [
                {"logType": "ADMIN_READ"},
                {"logType": "DATA_READ"},
                {"logType": "DATA_WRITE"},
            ],
        }
        ctx = make_gcp_ctx(self.tmp.name, post={IAM_POLICY_URL: {"auditConfigs": [config]}})
        self.assertEqual(self.module.audit_logging(make_control(), ctx).status, "Pass")

    def test_missing_log_types_fails(self):
        config = {"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}
        ctx = make_gcp_ctx(self.tmp.name, post={IAM_POLICY_URL: {"auditConfigs": [config]}})
        result = self.module.audit_logging(make_control(), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertIn("DATA_READ", result.observed_value)

    def test_exempted_members_fails_even_with_full_coverage(self):
        config = {
            "service": "allServices",
            "auditLogConfigs": [
                {"logType": "ADMIN_READ", "exemptedMembers": ["user:vip@example.com"]},
                {"logType": "DATA_READ"},
                {"logType": "DATA_WRITE"},
            ],
        }
        ctx = make_gcp_ctx(self.tmp.name, post={IAM_POLICY_URL: {"auditConfigs": [config]}})
        result = self.module.audit_logging(make_control(), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertIn("exempted", result.observed_value)


class TestLogSinks(LoggingTestCase):
    def test_catch_all_sink_passes(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={SINKS_URL: [{"name": "catch-all"}]})
        self.assertEqual(self.module.log_sinks(make_control(), ctx).status, "Pass")

    def test_only_filtered_sinks_fails(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={SINKS_URL: [{"name": "filtered", "filter": "severity>=ERROR"}]})
        self.assertEqual(self.module.log_sinks(make_control(), ctx).status, "Fail")

    def test_no_sinks_fails(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={SINKS_URL: []})
        self.assertEqual(self.module.log_sinks(make_control(), ctx).status, "Fail")

    def test_disabled_catch_all_sink_does_not_count(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={SINKS_URL: [{"name": "disabled-sink", "disabled": True}]})
        self.assertEqual(self.module.log_sinks(make_control(), ctx).status, "Fail")


if __name__ == "__main__":
    unittest.main()
