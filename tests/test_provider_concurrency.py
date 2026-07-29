"""AwsProvider region concurrency: correctness and genuine parallel execution."""

import tempfile
import threading
import unittest

from csaf.baseline import Baseline
from csaf.clouds.aws.provider import AwsProvider
from csaf.engagement import Engagement
from csaf.evidence import EvidenceStore
from tests.fakes import FakeClient, FakeSession, NullLogger, make_control


def make_provider(tmp, clients, max_workers=1):
    return AwsProvider(
        session=FakeSession(clients),
        baseline=Baseline(),
        evidence=EvidenceStore(tmp),
        logger=NullLogger(),
        engagement=Engagement(),
        profile="Assessment",
        max_workers=max_workers,
    )


class TestConcurrentRegionCorrectness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_all_regions_represented_with_multiple_workers(self):
        client = FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}})
        regions = ["us-east-1", "us-west-2", "eu-central-1", "ap-southeast-1"]
        provider = make_provider(self.tmp.name, {"ec2": client}, max_workers=4)
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], regions)
        self.assertEqual({r.region for r in results}, set(regions))
        self.assertTrue(all(r.status == "Pass" for r in results))

    def test_matches_sequential_result_set(self):
        def ctx():
            client = FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}})
            return make_provider(self.tmp.name, {"ec2": client})

        regions = ["us-east-1", "us-west-2", "eu-central-1"]
        control = make_control(module="compute", check="ebs_default_encryption")

        sequential = ctx().evaluate([control], regions)
        parallel = make_provider(
            self.tmp.name,
            {"ec2": FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}})},
            max_workers=3,
        ).evaluate([control], regions)

        self.assertEqual({r.region for r in sequential}, {r.region for r in parallel})
        self.assertEqual({r.status for r in sequential}, {r.status for r in parallel})

    def test_error_in_one_region_does_not_lose_others(self):
        lock = threading.Lock()
        state = {"count": 0}

        def flaky(kwargs):
            with lock:
                state["count"] += 1
                first = state["count"] == 1
            if first:
                return Exception("throttled")
            return {"EbsEncryptionByDefault": True}

        client = FakeClient(responses={"get_ebs_encryption_by_default": flaky})
        provider = make_provider(self.tmp.name, {"ec2": client}, max_workers=2)
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], ["us-east-1", "us-west-2"])
        self.assertEqual(len(results), 2)
        self.assertEqual({r.status for r in results}, {"Error", "Pass"})

    def test_max_workers_capped_at_region_count(self):
        # max_workers=10 with only 2 regions must not error or hang.
        client = FakeClient(responses={"get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True}})
        provider = make_provider(self.tmp.name, {"ec2": client}, max_workers=10)
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], ["us-east-1", "us-west-2"])
        self.assertEqual(len(results), 2)

    def test_no_regions_with_regional_controls_returns_empty(self):
        provider = make_provider(self.tmp.name, {}, max_workers=4)
        control = make_control(module="compute", check="ebs_default_encryption")
        self.assertEqual(provider.evaluate([control], []), [])


class TestGenuineParallelExecution(unittest.TestCase):
    """Proves two regions actually run concurrently, not just correctly.

    Region A's fake call blocks waiting for a signal that only region B's
    fake call sets. Under sequential (or single-worker) execution this would
    deadlock and time out; under real concurrency both complete quickly.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_two_regions_rendezvous_under_max_workers_two(self):
        b_arrived = threading.Event()
        a_saw_b = threading.Event()
        seen_regions = []
        lock = threading.Lock()

        def flaky(kwargs):
            # FakeSession ignores region in client(), so both regions share
            # this one client/response callable; distinguish call order
            # instead of region identity.
            with lock:
                seen_regions.append(threading.current_thread().name)
                is_first = len(seen_regions) == 1
            if is_first:
                # Acts as "region A": wait for "region B" to arrive.
                if not b_arrived.wait(timeout=3):
                    raise AssertionError("Timed out waiting for the other region - execution was not concurrent.")
                a_saw_b.set()
            else:
                # Acts as "region B": signal arrival immediately.
                b_arrived.set()
            return {"EbsEncryptionByDefault": True}

        client = FakeClient(responses={"get_ebs_encryption_by_default": flaky})
        provider = make_provider(self.tmp.name, {"ec2": client}, max_workers=2)
        control = make_control(module="compute", check="ebs_default_encryption")
        results = provider.evaluate([control], ["us-east-1", "us-west-2"])
        self.assertEqual(len(results), 2)
        self.assertTrue(a_saw_b.is_set())


if __name__ == "__main__":
    unittest.main()
