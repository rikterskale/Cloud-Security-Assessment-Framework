"""Cloud Storage module checks against faked GCP REST responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.storage import GCS_V1, StorageModule
from tests.fakes import make_control, make_gcp_ctx

BUCKETS_URL = f"{GCS_V1}/b"


def bucket(name, uniform_access=True):
    return {
        "name": name,
        "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": uniform_access}},
    }


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = StorageModule()


class TestBucketPublicIam(StorageTestCase):
    def test_no_buckets_not_applicable(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={BUCKETS_URL: []})
        self.assertEqual(self.module.bucket_public_iam(make_control(), ctx).status, "NotApplicable")

    def test_no_public_grants_passes(self):
        b = bucket("private-bucket")
        ctx = make_gcp_ctx(
            self.tmp.name,
            get_list={BUCKETS_URL: [b]},
            get={
                f"{GCS_V1}/b/private-bucket/iam": {
                    "bindings": [{"role": "roles/storage.admin", "members": ["user:a@example.com"]}]
                }
            },
        )
        self.assertEqual(self.module.bucket_public_iam(make_control(), ctx).status, "Pass")

    def test_public_member_flagged(self):
        b = bucket("public-bucket")
        policy = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
        ctx = make_gcp_ctx(
            self.tmp.name,
            get_list={BUCKETS_URL: [b]},
            get={f"{GCS_V1}/b/public-bucket/iam": policy},
        )
        results = self.module.bucket_public_iam(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"public-bucket"})


class TestUniformBucketAccess(StorageTestCase):
    def test_no_buckets_not_applicable(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={BUCKETS_URL: []})
        self.assertEqual(self.module.uniform_bucket_access(make_control(), ctx).status, "NotApplicable")

    def test_enabled_passes(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={BUCKETS_URL: [bucket("b1", uniform_access=True)]})
        self.assertEqual(self.module.uniform_bucket_access(make_control(), ctx).status, "Pass")

    def test_disabled_fails(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={BUCKETS_URL: [bucket("b1", uniform_access=False)]})
        results = self.module.uniform_bucket_access(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"b1"})


if __name__ == "__main__":
    unittest.main()
