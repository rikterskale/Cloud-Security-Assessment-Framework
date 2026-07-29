"""Azure Monitor / activity-log module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.monitor import MonitorModule
from tests.fakes import make_azure_ctx, make_control

SETTINGS = "/subscriptions/sub-1/providers/Microsoft.Insights/diagnosticSettings"


class MonitorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = MonitorModule()


class TestActivityLogExport(MonitorTestCase):
    def test_no_settings_fails(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={SETTINGS: []})
        self.assertEqual(self.module.activity_log_export(make_control(), ctx).status, "Fail")

    def test_all_logs_category_group_passes(self):
        settings = [{"name": "export-all", "properties": {"logs": [{"categoryGroup": "allLogs", "enabled": True}]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={SETTINGS: settings})
        self.assertEqual(self.module.activity_log_export(make_control(), ctx).status, "Pass")

    def test_all_required_categories_individually_pass(self):
        settings = [
            {
                "name": "export-cats",
                "properties": {
                    "logs": [
                        {"category": "Administrative", "enabled": True},
                        {"category": "Security", "enabled": True},
                        {"category": "Policy", "enabled": True},
                        {"category": "Alert", "enabled": True},
                    ]
                },
            }
        ]
        ctx = make_azure_ctx(self.tmp.name, get_value={SETTINGS: settings})
        self.assertEqual(self.module.activity_log_export(make_control(), ctx).status, "Pass")

    def test_partial_coverage_fails_with_missing_list(self):
        settings = [
            {
                "name": "partial",
                "properties": {
                    "logs": [
                        {"category": "Administrative", "enabled": True},
                        {"category": "Security", "enabled": False},
                    ]
                },
            }
        ]
        ctx = make_azure_ctx(self.tmp.name, get_value={SETTINGS: settings})
        result = self.module.activity_log_export(make_control(), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertIn("Security", result.observed_value)


if __name__ == "__main__":
    unittest.main()
