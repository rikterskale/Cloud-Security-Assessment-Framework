"""Offline tests for Cosign descriptor/SBOM preparation."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csaf.evidence import write_manifest
from csaf.external_verification import external_sign, external_verify, write_descriptor, write_run_sbom


class TestExternalVerification(unittest.TestCase):
    def make_run(self, tmp):
        root = Path(tmp)
        (root / "findings.json").write_text("[]", encoding="utf-8")
        write_manifest(root, "AWS", "1", "Assessment", source_revision="a" * 40)
        return root

    def test_sbom_and_descriptor_bind_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_run(tmp)
            self.assertEqual(write_run_sbom(root).name, "run-sbom.cdx.json")
            data = json.loads(write_descriptor(root).read_text())
            self.assertEqual([item["path"] for item in data["Artifacts"]], ["manifest.json", "run-sbom.cdx.json"])

    @patch("csaf.external_verification.subprocess.run")
    def test_external_sign_invokes_cosign(self, run):
        with tempfile.TemporaryDirectory() as tmp:
            paths = external_sign(self.make_run(tmp), cosign="fake-cosign")
            self.assertIn("bundle", paths)
            self.assertIn("sign-blob", run.call_args.args[0])

    @patch("csaf.external_verification.subprocess.run")
    def test_verify_requires_matching_artifacts(self, run):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_run(tmp)
            write_descriptor(root)
            (root / "evidence-signature.bundle").write_text("bundle", encoding="utf-8")
            ok, messages = external_verify(root, identity="id", issuer="issuer", cosign="fake-cosign")
            self.assertTrue(ok, messages)
