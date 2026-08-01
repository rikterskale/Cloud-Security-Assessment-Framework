"""Per-region progress heartbeat for long AWS runs (UX-ENH-006)."""

import tempfile
import unittest

from csaf.baseline import Baseline
from csaf.clouds.aws.provider import AwsProvider
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore
from tests.fakes import FakeClient, FakeSession, make_control


class RecordingLogger:
    def __init__(self):
        self.records = []

    def _record(self, level, source, message, **kwargs):
        self.records.append((level, source, message))

    def debug(self, source, message, **kwargs):
        self._record("DEBUG", source, message, **kwargs)

    def info(self, source, message, **kwargs):
        self._record("INFO", source, message, **kwargs)

    def warn(self, source, message, **kwargs):
        self._record("WARN", source, message, **kwargs)

    def error(self, source, message, **kwargs):
        self._record("ERROR", source, message, **kwargs)

    def close(self):
        pass


class TestProgressHeartbeat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _provider(self, logger, max_workers=1):
        client = FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}})
        return AwsProvider(
            session=FakeSession({"ec2": client}),
            baseline=Baseline(),
            evidence=EvidenceStore(self.tmp.name),
            logger=logger,
            engagement=Engagement(),
            profile="Assessment",
            max_workers=max_workers,
        )

    def test_one_heartbeat_per_region(self):
        logger = RecordingLogger()
        regions = ["us-east-1", "us-west-2", "eu-central-1"]
        control = make_control(module="compute", check="ebs_default_encryption")
        self._provider(logger).evaluate([control], regions)

        heartbeats = [msg for level, source, msg in logger.records if source == "progress"]
        self.assertEqual(len(heartbeats), len(regions))
        for region in regions:
            self.assertTrue(any(region in hb for hb in heartbeats), f"no heartbeat for {region}")
        self.assertTrue(all("control(s) across" in hb for hb in heartbeats))

    def test_heartbeat_present_with_concurrency(self):
        logger = RecordingLogger()
        regions = ["us-east-1", "us-west-2"]
        control = make_control(module="compute", check="ebs_default_encryption")
        self._provider(logger, max_workers=2).evaluate([control], regions)
        heartbeats = [msg for level, source, msg in logger.records if source == "progress"]
        self.assertEqual(len(heartbeats), 2)


if __name__ == "__main__":
    unittest.main()
