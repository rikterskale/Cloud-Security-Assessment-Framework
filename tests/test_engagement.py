import datetime
import unittest

from csaf.engagement import Engagement


class TestEngagement(unittest.TestCase):
    def test_readonly_profiles_always_authorized(self):
        eng = Engagement()  # no approvals
        for profile in ("Inventory", "Assessment"):
            allowed, _ = eng.authorize_profile(profile)
            self.assertTrue(allowed)

    def test_validation_requires_approval(self):
        eng = Engagement(active_validation_approved=False)
        allowed, reason = eng.authorize_profile("Validation")
        self.assertFalse(allowed)
        self.assertIn("does not approve", reason)

    def test_validation_requires_window(self):
        past = "2000-01-01T00:00:00Z"
        eng = Engagement(active_validation_approved=True, window_start_utc="1999-01-01T00:00:00Z", window_end_utc=past)
        allowed, reason = eng.authorize_profile("Validation")
        self.assertFalse(allowed)
        self.assertIn("window", reason)

    def test_validation_allowed_in_window(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        end = (now + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        eng = Engagement(active_validation_approved=True, window_start_utc=start, window_end_utc=end)
        allowed, _ = eng.authorize_profile("Validation")
        self.assertTrue(allowed)

    def test_account_scope(self):
        eng = Engagement(authorized_accounts=["111111111111"])
        self.assertTrue(eng.account_authorized("111111111111"))
        self.assertFalse(eng.account_authorized("222222222222"))
        self.assertTrue(Engagement().account_authorized("anything"))  # empty scope = unscoped


if __name__ == "__main__":
    unittest.main()
