"""Read-only guardrail for the Kubernetes session."""

import unittest

from csaf.clouds.k8s.session import ReadOnlyApiClient, ReadOnlyViolation


class FakeRawApi:
    def list_pod_for_all_namespaces(self, **kw):
        return {"items": []}

    def read_namespaced_pod(self, **kw):
        return {"ok": True}

    def get_api_resources(self, **kw):
        return {"resources": []}

    def create_namespaced_pod(self, **kw):
        return {"created": True}

    def delete_namespaced_pod(self, **kw):
        return {"deleted": True}

    def patch_namespaced_deployment(self, **kw):
        return {"patched": True}

    def replace_namespaced_config_map(self, **kw):
        return {"replaced": True}

    def connect_get_namespaced_pod_exec(self, **kw):
        # This is how kubectl exec is implemented in the generated client -
        # it MUST be blocked as aggressively as any delete/create verb.
        return {"exec": True}


class TestReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.client = ReadOnlyApiClient(FakeRawApi())

    def test_read_operations_allowed(self):
        self.assertEqual(self.client.list_pod_for_all_namespaces()["items"], [])
        self.assertTrue(self.client.read_namespaced_pod()["ok"])
        self.assertEqual(self.client.get_api_resources()["resources"], [])

    def test_mutating_operations_blocked(self):
        for op in (
            "create_namespaced_pod",
            "delete_namespaced_pod",
            "patch_namespaced_deployment",
            "replace_namespaced_config_map",
        ):
            with self.assertRaises(ReadOnlyViolation):
                getattr(self.client, op)()

    def test_exec_attach_style_connect_verb_blocked(self):
        with self.assertRaises(ReadOnlyViolation):
            self.client.connect_get_namespaced_pod_exec()


if __name__ == "__main__":
    unittest.main()
