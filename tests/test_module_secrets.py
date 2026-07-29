"""Secrets Manager module checks against faked list_secrets responses."""

import tempfile
import unittest

from csaf.clouds.aws.modules.secrets import SecretsModule
from tests.fakes import FakeClient, make_control, make_ctx


def secret(name, rotation_enabled=True, kms_key_id="alias/custom-cmk"):
    entry = {"Name": name, "RotationEnabled": rotation_enabled}
    if kms_key_id is not None:
        entry["KmsKeyId"] = kms_key_id
    return entry


class SecretsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = SecretsModule()

    def ctx(self, secrets):
        client = FakeClient(pages={"list_secrets": [{"SecretList": secrets}]})
        return make_ctx(self.tmp.name, clients={"secretsmanager": client})


class TestSecretRotationEnabled(SecretsTestCase):
    def test_no_secrets_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.secret_rotation_enabled(make_control(), ctx).status, "NotApplicable")

    def test_all_rotating_passes(self):
        ctx = self.ctx([secret("s1", rotation_enabled=True), secret("s2", rotation_enabled=True)])
        self.assertEqual(self.module.secret_rotation_enabled(make_control(), ctx).status, "Pass")

    def test_non_rotating_secret_flagged(self):
        ctx = self.ctx([secret("s1", rotation_enabled=True), secret("s2", rotation_enabled=False)])
        results = self.module.secret_rotation_enabled(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"s2"})
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestSecretCmkEncryption(SecretsTestCase):
    def test_no_secrets_not_applicable(self):
        ctx = self.ctx([])
        self.assertEqual(self.module.secret_cmk_encryption(make_control(), ctx).status, "NotApplicable")

    def test_customer_managed_key_passes(self):
        ctx = self.ctx([secret("s1", kms_key_id="alias/custom-cmk")])
        self.assertEqual(self.module.secret_cmk_encryption(make_control(), ctx).status, "Pass")

    def test_missing_kms_key_id_flagged(self):
        ctx = self.ctx([secret("s1", kms_key_id=None)])
        results = self.module.secret_cmk_encryption(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"s1"})

    def test_secrets_list_collected_once_per_context(self):
        client = FakeClient(pages={"list_secrets": [{"SecretList": [secret("s1")]}]})
        ctx = make_ctx(self.tmp.name, clients={"secretsmanager": client})
        self.module.secret_rotation_enabled(make_control(), ctx)
        self.module.secret_cmk_encryption(make_control(), ctx)
        list_calls = [name for name, _ in client.calls if name == "list_secrets"]
        self.assertEqual(len(list_calls), 1)


if __name__ == "__main__":
    unittest.main()
