"""CLI behavior for the sign_engagement.py signing helper."""

import json
import tempfile
import unittest
from pathlib import Path

import sign_engagement
from csaf.engagement_signing import sign


class TestSignEngagementCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key_path = self.root / "key.bin"
        self.key_path.write_bytes(b"test-shared-secret")
        self.engagement_path = self.root / "engagement.json"
        self.engagement_path.write_text(
            json.dumps({"engagementId": "ENG-1", "activeValidationApproved": True}), encoding="utf-8"
        )

    def test_sign_writes_valid_signature_in_place(self):
        exit_code = sign_engagement.main(["--engagement", str(self.engagement_path), "--key-file", str(self.key_path)])
        self.assertEqual(exit_code, 0)
        data = json.loads(self.engagement_path.read_text(encoding="utf-8"))
        self.assertIn("signature", data)
        content = {k: v for k, v in data.items() if k != "signature"}
        self.assertEqual(data["signature"], sign(content, b"test-shared-secret"))

    def test_verify_only_on_signed_file_succeeds(self):
        sign_engagement.main(["--engagement", str(self.engagement_path), "--key-file", str(self.key_path)])
        exit_code = sign_engagement.main(
            ["--engagement", str(self.engagement_path), "--key-file", str(self.key_path), "--verify-only"]
        )
        self.assertEqual(exit_code, 0)

    def test_verify_only_on_unsigned_file_fails(self):
        exit_code = sign_engagement.main(
            ["--engagement", str(self.engagement_path), "--key-file", str(self.key_path), "--verify-only"]
        )
        self.assertEqual(exit_code, 1)

    def test_output_flag_writes_elsewhere_without_modifying_source(self):
        out_path = self.root / "signed.json"
        sign_engagement.main(
            [
                "--engagement",
                str(self.engagement_path),
                "--key-file",
                str(self.key_path),
                "--output",
                str(out_path),
            ]
        )
        self.assertTrue(out_path.exists())
        original = json.loads(self.engagement_path.read_text(encoding="utf-8"))
        self.assertNotIn("signature", original)


if __name__ == "__main__":
    unittest.main()
