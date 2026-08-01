"""Concurrency model is AWS-only and safe for other clouds (roadmap #11).

AWS parallelizes across independent regions (own cache per region). Azure/GCP/K8s
assess a single scope with a shared memoization cache and a session whose SDK
client is not guaranteed thread-safe, so they are sequential by design and must
not accept/misuse --max-workers.
"""

import inspect
import tempfile
import unittest

from csaf.clouds.aws.provider import AwsProvider
from csaf.clouds.azure.provider import AzureProvider
from csaf.clouds.gcp.provider import GcpProvider
from csaf.clouds.k8s.provider import K8sProvider
from csaf.runner import RunConfig, run_assessment


class TestConcurrencyModel(unittest.TestCase):
    def test_only_aws_provider_accepts_max_workers(self):
        self.assertIn("max_workers", inspect.signature(AwsProvider.__init__).parameters)
        for provider in (AzureProvider, GcpProvider, K8sProvider):
            self.assertNotIn(
                "max_workers",
                inspect.signature(provider.__init__).parameters,
                f"{provider.__name__} should not accept max_workers",
            )

    def test_max_workers_is_safely_ignored_for_non_aws(self):
        # A high --max-workers must not error or change behavior for non-AWS clouds
        # (the runner only forwards it to AWS). Offline self-check exercises the path.
        for cloud in ("azure", "gcp", "k8s"):
            with tempfile.TemporaryDirectory() as tmp:
                result = run_assessment(
                    RunConfig(cloud=cloud, self_check=True, max_workers=8, output_dir=tmp, log_level="ERROR")
                )
                self.assertIn(result.exit_code, (0, 2), f"{cloud} self-check with max_workers failed")


if __name__ == "__main__":
    unittest.main()
