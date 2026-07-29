"""Read-only guardrails for the Azure ARM and GCP REST sessions.

These use injected fake credentials/HTTP so no cloud SDK or network is needed.
"""

import unittest

from csaf.clouds.azure.session import ArmSession
from csaf.clouds.azure.session import ReadOnlyViolation as AzureReadOnlyViolation
from csaf.clouds.gcp.session import GcpSession
from csaf.clouds.gcp.session import ReadOnlyViolation as GcpReadOnlyViolation


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload or {}
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload


class FakeToken:
    token = "fake-token"
    expires_on = 9999999999


class FakeCredential:
    def get_token(self, scope):
        return FakeToken()


class FakeArmHttp:
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append(("GET", url, params))
        return FakeResponse({"value": [{"subscriptionId": "sub-1", "state": "Enabled"}]})


class TestArmReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.http = FakeArmHttp()
        self.session = ArmSession(subscription_id="sub-1", credential=FakeCredential(), http=self.http)

    def test_get_allowed(self):
        data = self.session.get("/subscriptions", "2022-12-01")
        self.assertIn("value", data)
        self.assertEqual(self.http.calls[0][0], "GET")

    def test_mutating_verbs_blocked(self):
        for verb in ("PUT", "POST", "PATCH", "DELETE"):
            with self.assertRaises(AzureReadOnlyViolation):
                self.session.request(verb, "/subscriptions/sub-1/resourceGroups/x", "2022-12-01")

    def test_pagination_follows_next_link(self):
        pages = [
            FakeResponse({"value": [{"n": 1}], "nextLink": "https://management.azure.com/page2"}),
            FakeResponse({"value": [{"n": 2}]}),
        ]

        class PagedHttp(FakeArmHttp):
            def get(self, url, headers=None, params=None, timeout=None):
                self.calls.append(("GET", url, params))
                return pages[len(self.calls) - 1]

        session = ArmSession(subscription_id="sub-1", credential=FakeCredential(), http=PagedHttp())
        items = session.get_value("/things", "2022-12-01")
        self.assertEqual([i["n"] for i in items], [1, 2])


class FakeGcpHttp:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, json=None, timeout=None):
        self.calls.append((method, url))
        return FakeResponse({"bindings": []})


class TestGcpReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.http = FakeGcpHttp()
        self.session = GcpSession(project_id="proj-1", http=self.http)

    def test_get_allowed(self):
        self.session.get("https://compute.googleapis.com/compute/v1/projects/proj-1/global/firewalls")
        self.assertEqual(self.http.calls[0][0], "GET")

    def test_readonly_post_allowed(self):
        self.session.post(
            "https://cloudresourcemanager.googleapis.com/v1/projects/proj-1:getIamPolicy",
            json_body={"options": {"requestedPolicyVersion": 3}},
        )
        self.assertEqual(self.http.calls[0][0], "POST")

    def test_mutating_post_blocked(self):
        with self.assertRaises(GcpReadOnlyViolation):
            self.session.post("https://cloudresourcemanager.googleapis.com/v1/projects/proj-1:setIamPolicy")
        with self.assertRaises(GcpReadOnlyViolation):
            self.session.post("https://compute.googleapis.com/compute/v1/projects/proj-1/global/firewalls")

    def test_other_verbs_blocked(self):
        for verb in ("PUT", "PATCH", "DELETE"):
            with self.assertRaises(GcpReadOnlyViolation):
                self.session.request(verb, "https://compute.googleapis.com/compute/v1/projects/proj-1")

    def test_missing_project_raises(self):
        session = GcpSession(project_id=None, http=self.http)
        with self.assertRaises(RuntimeError):
            _ = session.project_id


if __name__ == "__main__":
    unittest.main()
