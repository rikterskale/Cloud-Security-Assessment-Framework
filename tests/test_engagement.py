import datetime
import json
import tempfile
import unittest
from pathlib import Path

from csaf.engagement import Engagement
from csaf.engagement_signing import sign


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


def _write_engagement(path: Path, **overrides) -> dict:
    data = {
        "engagementId": "ENG-1",
        "activeValidationApproved": True,
        "windowStartUtc": None,
        "windowEndUtc": None,
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


class TestEngagementSignatureAuthorization(unittest.TestCase):
    def test_no_signing_key_skips_verification_even_when_unsigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            _write_engagement(path)
            eng = Engagement.load(path)
            allowed, _ = eng.authorize_profile("Validation")
            self.assertTrue(allowed)

    def test_signing_key_required_and_valid_signature_passes(self):
        key = b"shared-secret"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            data = _write_engagement(path)
            data["signature"] = sign(data, key)
            path.write_text(json.dumps(data), encoding="utf-8")
            eng = Engagement.load(path)
            allowed, reason = eng.authorize_profile("Validation", signing_key=key)
            self.assertTrue(allowed, reason)

    def test_signing_key_required_but_unsigned_file_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            _write_engagement(path)
            eng = Engagement.load(path)
            allowed, reason = eng.authorize_profile("Validation", signing_key=b"shared-secret")
            self.assertFalse(allowed)
            self.assertIn("signature", reason)

    def test_tampered_after_signing_is_refused(self):
        key = b"shared-secret"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            data = _write_engagement(path)
            data["signature"] = sign(data, key)
            path.write_text(json.dumps(data), encoding="utf-8")

            # Tamper after signing: flip a field the signature covered.
            tampered = json.loads(path.read_text(encoding="utf-8"))
            tampered["authorizedAccounts"] = ["999999999999"]
            path.write_text(json.dumps(tampered), encoding="utf-8")

            eng = Engagement.load(path)
            allowed, reason = eng.authorize_profile("Validation", signing_key=key)
            self.assertFalse(allowed)
            self.assertIn("signature", reason)

    def test_wrong_key_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            data = _write_engagement(path)
            data["signature"] = sign(data, b"key-a")
            path.write_text(json.dumps(data), encoding="utf-8")
            eng = Engagement.load(path)
            allowed, _ = eng.authorize_profile("Validation", signing_key=b"key-b")
            self.assertFalse(allowed)

    def test_default_engagement_never_verifies(self):
        self.assertFalse(Engagement().verify_signature(b"any-key"))


if __name__ == "__main__":
    unittest.main()
