"""Cloud KMS module checks against faked GCP REST responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.kms import KMS_V1, KmsModule
from tests.fakes import make_control, make_gcp_ctx

RINGS_WILDCARD = f"{KMS_V1}/projects/proj-1/locations/-/keyRings"
LOCATIONS_URL = f"{KMS_V1}/projects/proj-1/locations"


def key(name, purpose="ENCRYPT_DECRYPT", state="ENABLED", rotation_seconds=7776000, has_next_rotation=True):
    return {
        "name": name,
        "purpose": purpose,
        "primary": {"state": state},
        "rotationPeriod": f"{rotation_seconds}s",
        "nextRotationTime": "2026-08-01T00:00:00Z" if has_next_rotation else None,
    }


class KmsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = KmsModule()

    def ctx(self, rings, keys_by_ring):
        get_list = {RINGS_WILDCARD: rings}
        for ring_name, keys in keys_by_ring.items():
            get_list[f"{KMS_V1}/{ring_name}/cryptoKeys"] = keys
        return make_gcp_ctx(self.tmp.name, get_list=get_list)


class TestKmsKeyRotation(KmsTestCase):
    def test_no_keys_not_applicable(self):
        ctx = self.ctx(
            [{"name": "projects/proj-1/locations/us/keyRings/ring1"}],
            {"projects/proj-1/locations/us/keyRings/ring1": []},
        )
        self.assertEqual(self.module.kms_key_rotation(make_control(), ctx).status, "NotApplicable")

    def test_rotation_within_threshold_passes(self):
        ring = "projects/proj-1/locations/us/keyRings/ring1"
        ctx = self.ctx([{"name": ring}], {ring: [key("k1")]})
        self.assertEqual(self.module.kms_key_rotation(make_control(), ctx).status, "Pass")

    def test_no_rotation_period_flagged(self):
        ring = "projects/proj-1/locations/us/keyRings/ring1"
        ctx = self.ctx([{"name": ring}], {ring: [key("k1", rotation_seconds=0, has_next_rotation=False)]})
        results = self.module.kms_key_rotation(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"k1"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_rotation_too_slow_flagged(self):
        ring = "projects/proj-1/locations/us/keyRings/ring1"
        # 200 days in seconds, exceeding the 90-day default threshold.
        ctx = self.ctx([{"name": ring}], {ring: [key("k1", rotation_seconds=200 * 86400)]})
        results = self.module.kms_key_rotation(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"k1"})

    def test_asymmetric_and_disabled_keys_skipped(self):
        ring = "projects/proj-1/locations/us/keyRings/ring1"
        keys = [
            key("asym", purpose="ASYMMETRIC_SIGN"),
            key("disabled", state="DISABLED"),
        ]
        ctx = self.ctx([{"name": ring}], {ring: keys})
        self.assertEqual(self.module.kms_key_rotation(make_control(), ctx).status, "NotApplicable")

    def test_fallback_to_per_location_listing_when_wildcard_fails(self):
        ring = "projects/proj-1/locations/us/keyRings/ring1"
        get_list = {
            RINGS_WILDCARD: KeyError("wildcard not supported"),
            LOCATIONS_URL: [{"name": "projects/proj-1/locations/us"}],
            f"{KMS_V1}/projects/proj-1/locations/us/keyRings": [{"name": ring}],
            f"{KMS_V1}/{ring}/cryptoKeys": [key("k1")],
        }
        ctx = make_gcp_ctx(self.tmp.name, get_list=get_list)
        self.assertEqual(self.module.kms_key_rotation(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
