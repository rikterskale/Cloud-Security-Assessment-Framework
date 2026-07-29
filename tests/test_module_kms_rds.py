"""KMS key-rotation and RDS data-protection module checks."""

import tempfile
import unittest

from csaf.clouds.aws.modules.kms import KmsModule
from csaf.clouds.aws.modules.rds import RdsModule
from tests.fakes import FakeClient, make_control, make_ctx


def kms_client(keys: dict):
    """keys maps key-id -> (metadata overrides, rotation enabled)."""

    def describe_key(kwargs):
        meta = {
            "KeyId": kwargs["KeyId"],
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
            "KeySpec": "SYMMETRIC_DEFAULT",
        }
        meta.update(keys[kwargs["KeyId"]][0])
        return {"KeyMetadata": meta}

    def rotation(kwargs):
        return {"KeyRotationEnabled": keys[kwargs["KeyId"]][1]}

    return FakeClient(
        responses={"describe_key": describe_key, "get_key_rotation_status": rotation},
        pages={"list_keys": [{"Keys": [{"KeyId": kid} for kid in keys]}]},
    )


class KmsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = KmsModule()

    def ctx(self, client):
        return make_ctx(self.tmp.name, clients={"kms": client}, region="us-east-1")

    def test_only_enabled_customer_symmetric_keys_evaluated(self):
        keys = {
            "aws-managed": ({"KeyManager": "AWS"}, False),
            "disabled": ({"KeyState": "PendingDeletion"}, False),
            "asymmetric": ({"KeySpec": "RSA_2048"}, False),
        }
        result = self.module.kms_key_rotation(make_control(), self.ctx(kms_client(keys)))
        self.assertEqual(result.status, "NotApplicable")

    def test_rotation_disabled_flagged(self):
        keys = {"rotates": ({}, True), "static": ({}, False)}
        results = self.module.kms_key_rotation(make_control(), self.ctx(kms_client(keys)))
        self.assertEqual([r.resource_id for r in results], ["static"])
        self.assertEqual(results[0].status, "Fail")

    def test_all_rotating_passes(self):
        result = self.module.kms_key_rotation(make_control(), self.ctx(kms_client({"k1": ({}, True)})))
        self.assertEqual(result.status, "Pass")


def rds_client(instances):
    return FakeClient(pages={"describe_db_instances": [{"DBInstances": list(instances)}]})


class RdsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = RdsModule()

    def ctx(self, client):
        return make_ctx(self.tmp.name, clients={"rds": client}, region="us-east-1")

    def test_no_instances_is_not_applicable_for_both_checks(self):
        for check in (self.module.rds_encryption, self.module.rds_public_access):
            result = check(make_control(), self.ctx(rds_client([])))
            self.assertEqual(result.status, "NotApplicable")

    def test_unencrypted_storage_flagged(self):
        instances = [
            {"DBInstanceIdentifier": "db-enc", "StorageEncrypted": True},
            {"DBInstanceIdentifier": "db-plain", "StorageEncrypted": False},
        ]
        results = self.module.rds_encryption(make_control(), self.ctx(rds_client(instances)))
        self.assertEqual([r.resource_id for r in results], ["db-plain"])
        self.assertEqual(results[0].status, "Fail")

    def test_public_access_flagged(self):
        instances = [
            {"DBInstanceIdentifier": "db-private", "PubliclyAccessible": False},
            {"DBInstanceIdentifier": "db-public", "PubliclyAccessible": True},
        ]
        results = self.module.rds_public_access(make_control(), self.ctx(rds_client(instances)))
        self.assertEqual([r.resource_id for r in results], ["db-public"])

    def test_clean_inventory_passes_and_is_cached(self):
        client = rds_client([{"DBInstanceIdentifier": "db-1", "StorageEncrypted": True, "PubliclyAccessible": False}])
        ctx = self.ctx(client)
        self.assertEqual(self.module.rds_encryption(make_control(), ctx).status, "Pass")
        self.assertEqual(self.module.rds_public_access(make_control(), ctx).status, "Pass")
        describe_calls = [name for name, _ in client.calls if name == "describe_db_instances"]
        self.assertEqual(len(describe_calls), 1)


if __name__ == "__main__":
    unittest.main()
