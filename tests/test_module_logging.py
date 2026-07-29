"""CloudTrail / Config / GuardDuty logging-and-detection module checks."""

import tempfile
import unittest

from csaf.clouds.aws.modules.logging_audit import LoggingModule
from tests.fakes import FakeClient, make_control, make_ctx


def cloudtrail_client(trails: list[dict], logging_by_arn: dict[str, bool]):
    def get_trail_status(kwargs):
        return {"IsLogging": logging_by_arn.get(kwargs["Name"], False)}

    return FakeClient(
        responses={
            "describe_trails": {"trailList": trails},
            "get_trail_status": get_trail_status,
        }
    )


def trail(name, multi_region=True, validation=True, kms_key="arn:kms:key"):
    data = {"Name": name, "TrailARN": f"arn:trail/{name}", "IsMultiRegionTrail": multi_region}
    data["LogFileValidationEnabled"] = validation
    if kms_key:
        data["KmsKeyId"] = kms_key
    return data


class LoggingTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = LoggingModule()

    def ctx(self, clients):
        return make_ctx(self.tmp.name, clients=clients, region="us-east-1")


class TestCloudTrail(LoggingTestCase):
    def test_active_multiregion_trail_passes(self):
        client = cloudtrail_client([trail("main")], {"arn:trail/main": True})
        result = self.module.cloudtrail_multiregion(make_control(), self.ctx({"cloudtrail": client}))
        self.assertEqual(result.status, "Pass")

    def test_multiregion_trail_not_logging_fails(self):
        client = cloudtrail_client([trail("main")], {"arn:trail/main": False})
        result = self.module.cloudtrail_multiregion(make_control(), self.ctx({"cloudtrail": client}))
        self.assertEqual(result.status, "Fail")

    def test_single_region_trail_only_fails(self):
        client = cloudtrail_client([trail("regional", multi_region=False)], {"arn:trail/regional": True})
        result = self.module.cloudtrail_multiregion(make_control(), self.ctx({"cloudtrail": client}))
        self.assertEqual(result.status, "Fail")

    def test_log_validation_offender_flagged_and_no_trails_fails(self):
        client = cloudtrail_client(
            [trail("good"), trail("unvalidated", validation=False)],
            {"arn:trail/good": True, "arn:trail/unvalidated": True},
        )
        results = self.module.cloudtrail_log_validation(make_control(), self.ctx({"cloudtrail": client}))
        self.assertEqual([r.resource_id for r in results], ["unvalidated"])

        empty = cloudtrail_client([], {})
        result = self.module.cloudtrail_log_validation(make_control(), self.ctx({"cloudtrail": empty}))
        self.assertEqual(result.status, "Fail")

    def test_kms_encryption_offender_flagged(self):
        client = cloudtrail_client(
            [trail("encrypted"), trail("plain", kms_key=None)],
            {"arn:trail/encrypted": True, "arn:trail/plain": True},
        )
        results = self.module.cloudtrail_kms(make_control(), self.ctx({"cloudtrail": client}))
        self.assertEqual([r.resource_id for r in results], ["plain"])

    def test_trail_inventory_cached_across_checks(self):
        client = cloudtrail_client([trail("main")], {"arn:trail/main": True})
        ctx = self.ctx({"cloudtrail": client})
        self.module.cloudtrail_multiregion(make_control(), ctx)
        self.module.cloudtrail_log_validation(make_control(), ctx)
        self.module.cloudtrail_kms(make_control(), ctx)
        describe_calls = [name for name, _ in client.calls if name == "describe_trails"]
        self.assertEqual(len(describe_calls), 1)


class TestConfigAndGuardDuty(LoggingTestCase):
    def test_config_recording_pass_and_fail(self):
        recording = FakeClient(
            responses={
                "describe_configuration_recorder_status": {"ConfigurationRecordersStatus": [{"recording": True}]}
            }
        )
        stopped = FakeClient(
            responses={
                "describe_configuration_recorder_status": {"ConfigurationRecordersStatus": [{"recording": False}]}
            }
        )
        self.assertEqual(self.module.config_enabled(make_control(), self.ctx({"config": recording})).status, "Pass")
        self.assertEqual(self.module.config_enabled(make_control(), self.ctx({"config": stopped})).status, "Fail")

    def test_guardduty_enabled_pass_disabled_and_absent_fail(self):
        enabled = FakeClient(
            responses={"list_detectors": {"DetectorIds": ["d-1"]}, "get_detector": {"Status": "ENABLED"}}
        )
        disabled = FakeClient(
            responses={"list_detectors": {"DetectorIds": ["d-1"]}, "get_detector": {"Status": "DISABLED"}}
        )
        absent = FakeClient(responses={"list_detectors": {"DetectorIds": []}})
        self.assertEqual(
            self.module.guardduty_enabled(make_control(), self.ctx({"guardduty": enabled})).status, "Pass"
        )
        self.assertEqual(
            self.module.guardduty_enabled(make_control(), self.ctx({"guardduty": disabled})).status, "Fail"
        )
        self.assertEqual(self.module.guardduty_enabled(make_control(), self.ctx({"guardduty": absent})).status, "Fail")


if __name__ == "__main__":
    unittest.main()
