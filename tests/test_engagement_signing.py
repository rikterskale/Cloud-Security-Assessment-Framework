"""HMAC signing/verification for engagement content."""

import unittest

from csaf.engagement_signing import canonical_bytes, sign, verify


class TestCanonicalBytes(unittest.TestCase):
    def test_key_order_does_not_affect_output(self):
        a = canonical_bytes({"b": 1, "a": 2})
        b = canonical_bytes({"a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_nested_dict_keys_also_sorted(self):
        a = canonical_bytes({"x": {"z": 1, "y": 2}})
        b = canonical_bytes({"x": {"y": 2, "z": 1}})
        self.assertEqual(a, b)


class TestSignVerify(unittest.TestCase):
    def test_valid_signature_verifies(self):
        data = {"engagementId": "ENG-1", "activeValidationApproved": True}
        key = b"secret-key"
        sig = sign(data, key)
        self.assertTrue(verify(data, sig, key))

    def test_wrong_key_fails(self):
        data = {"engagementId": "ENG-1"}
        sig = sign(data, b"key-a")
        self.assertFalse(verify(data, sig, b"key-b"))

    def test_tampered_content_fails(self):
        data = {"activeValidationApproved": False}
        key = b"secret-key"
        sig = sign(data, key)
        tampered = {"activeValidationApproved": True}
        self.assertFalse(verify(tampered, sig, key))

    def test_missing_signature_fails(self):
        self.assertFalse(verify({"a": 1}, None, b"key"))
        self.assertFalse(verify({"a": 1}, "", b"key"))

    def test_empty_key_cannot_sign_or_verify(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            sign({"a": 1}, b"")
        self.assertFalse(verify({"a": 1}, "deadbeef", b""))


if __name__ == "__main__":
    unittest.main()
