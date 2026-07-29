import unittest

from csaf.clouds.aws.session import ReadOnlyClient, ReadOnlyViolation


class FakeClient:
    def describe_instances(self, **kw):
        return {"ok": True}

    def list_buckets(self, **kw):
        return {"ok": True}

    def simulate_principal_policy(self, **kw):
        return {"ok": True}

    def create_bucket(self, **kw):
        return {"created": True}

    def delete_user(self, **kw):
        return {"deleted": True}

    def put_bucket_policy(self, **kw):
        return {"put": True}

    def get_paginator(self, name):
        return f"paginator:{name}"


class TestReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.client = ReadOnlyClient(FakeClient())

    def test_read_operations_allowed(self):
        self.assertTrue(self.client.describe_instances()["ok"])
        self.assertTrue(self.client.list_buckets()["ok"])
        self.assertTrue(self.client.simulate_principal_policy()["ok"])

    def test_mutating_operations_blocked(self):
        for op in ("create_bucket", "delete_user", "put_bucket_policy"):
            with self.assertRaises(ReadOnlyViolation):
                getattr(self.client, op)()

    def test_paginator_guarded(self):
        self.assertEqual(self.client.get_paginator("list_policies"), "paginator:list_policies")
        with self.assertRaises(ReadOnlyViolation):
            self.client.get_paginator("delete_objects")


if __name__ == "__main__":
    unittest.main()
