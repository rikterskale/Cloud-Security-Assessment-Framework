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
        allowed, reason = eng.authorize_profile("Validation", signing_key=b"shared-secret")
        self.assertFalse(allowed)
        self.assertIn("does not approve", reason)

    def test_validation_requires_window(self):
        past = "2000-01-01T00:00:00Z"
        eng = Engagement(active_validation_approved=True, window_start_utc="1999-01-01T00:00:00Z", window_end_utc=past)
        allowed, reason = eng.authorize_profile("Validation", signing_key=b"shared-secret")
        self.assertFalse(allowed)
        self.assertIn("window", reason)

    def test_validation_in_window_still_requires_a_signature(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        end = (now + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        eng = Engagement(active_validation_approved=True, window_start_utc=start, window_end_utc=end)
        allowed, reason = eng.authorize_profile("Validation", signing_key=b"shared-secret")
        self.assertFalse(allowed)
        self.assertIn("signature", reason)

    def test_account_scope(self):
        eng = Engagement(authorized_accounts=["111111111111"])
        self.assertTrue(eng.account_authorized("111111111111"))
        self.assertFalse(eng.account_authorized("222222222222"))
        self.assertTrue(Engagement().account_authorized("anything"))  # empty scope = unscoped


def _write_engagement(path: Path, **overrides) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    data = {
        "schemaVersion": "1.0",
        "engagementId": "ENG-1",
        "cloud": "AWS",
        "authorizedAccounts": ["111111111111"],
        "authorizedRegions": ["us-east-1"],
        "activeValidationApproved": True,
        "windowStartUtc": (now - datetime.timedelta(hours=1)).isoformat(),
        "windowEndUtc": (now + datetime.timedelta(hours=1)).isoformat(),
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return data


class TestEngagementSignatureAuthorization(unittest.TestCase):
    def test_active_profile_requires_signing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.json"
            _write_engagement(path)
            eng = Engagement.load(path)
            allowed, reason = eng.authorize_profile("Validation")
            self.assertFalse(allowed)
            self.assertIn("engagement-key-file", reason)

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


class TestEngagementScopeAuthorization(unittest.TestCase):
    def test_readonly_without_engagement_remains_unscoped(self):
        allowed, _ = Engagement().authorize_scope("AWS", ["us-east-1"])
        self.assertTrue(allowed)

    def test_active_requires_explicit_account_and_region_scope(self):
        eng = Engagement(configured=True, cloud="AWS")
        allowed, reason = eng.authorize_scope("AWS", ["us-east-1"], active=True)
        self.assertFalse(allowed)
        self.assertIn("authorized account", reason)

    def test_cloud_account_and_region_must_match(self):
        eng = Engagement(
            configured=True,
            cloud="AWS",
            authorized_accounts=["111111111111"],
            authorized_regions=["us-east-1"],
        )
        self.assertFalse(eng.authorize_scope("Azure", [], "111111111111", active=True)[0])
        self.assertFalse(eng.authorize_scope("AWS", ["us-east-1"], "222222222222", active=True)[0])
        self.assertFalse(eng.authorize_scope("AWS", ["eu-west-1"], "111111111111", active=True)[0])
        self.assertTrue(eng.authorize_scope("AWS", ["us-east-1"], "111111111111", active=True)[0])

    def test_unenforceable_source_address_scope_fails_closed_for_active_run(self):
        eng = Engagement(
            configured=True,
            cloud="AWS",
            authorized_accounts=["111111111111"],
            authorized_regions=["us-east-1"],
            authorized_source_addresses=["192.0.2.1"],
        )
        allowed, reason = eng.authorize_scope("AWS", ["us-east-1"], "111111111111", active=True)
        self.assertFalse(allowed)
        self.assertIn("cannot be enforced", reason)


if __name__ == "__main__":
    unittest.main()
