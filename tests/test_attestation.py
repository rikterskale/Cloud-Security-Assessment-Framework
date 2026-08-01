"""Attested evidence bundle: sign/verify a run's manifest (OFF-FEAT-007)."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from csaf.attestation import main, verify_bundle, write_attestation
from csaf.evidence import write_manifest

KEY = b"shared-secret-key"


def make_run(tmp: str) -> Path:
    """Build a minimal but real run directory with two artifacts + a manifest."""
    root = Path(tmp)
    (root / "findings.json").write_text('[{"FindingId":"F-1"}]', encoding="utf-8")
    (root / "coverage-report.json").write_text('{"selected":1}', encoding="utf-8")
    write_manifest(root, "AWS", "123456789012", "Assessment", source_revision="a" * 40)
    return root


class TestAttestation(unittest.TestCase):
    def test_sign_then_verify_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            path = write_attestation(root, KEY)
            self.assertEqual(path.name, "attestation.json")
            ok, messages = verify_bundle(root, KEY)
            self.assertTrue(ok, messages)
            self.assertTrue(any("all 2 artifacts match" in m for m in messages))

    def test_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            write_attestation(root, KEY)
            ok, messages = verify_bundle(root, b"different-key")
            self.assertFalse(ok)
            self.assertTrue(any("signature does not verify" in m for m in messages))

    def test_tampered_artifact_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            write_attestation(root, KEY)
            # Modify an artifact after signing.
            (root / "findings.json").write_text('[{"FindingId":"F-EVIL"}]', encoding="utf-8")
            ok, messages = verify_bundle(root, KEY)
            self.assertFalse(ok)
            self.assertTrue(any("artifact changed since the run: findings.json" in m for m in messages))

    def test_tampered_manifest_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            write_attestation(root, KEY)
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["AccountScope"] = "999999999999"
            (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            ok, messages = verify_bundle(root, KEY)
            self.assertFalse(ok)
            self.assertTrue(any("manifest.json hash does not match" in m for m in messages))

    def test_missing_attestation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            ok, messages = verify_bundle(root, KEY)
            self.assertFalse(ok)
            self.assertIn("missing attestation.json", messages)

    def test_cli_sign_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_run(tmp)
            key_file = Path(tmp) / "k.key"
            key_file.write_bytes(KEY)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["sign", str(root), "--key-file", str(key_file)]), 0)
                self.assertEqual(main(["verify", str(root), "--key-file", str(key_file)]), 0)
            # Tamper -> verify exits 1.
            (root / "coverage-report.json").write_text("{}", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify", str(root), "--key-file", str(key_file)]), 1)


if __name__ == "__main__":
    unittest.main()
