"""Evidence store and the tamper-evident SHA-256 manifest."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from csaf.evidence import EvidenceStore, sha256_file, write_manifest

# SHA-256 of the ASCII string "abc" (NIST test vector).
SHA256_ABC = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"


class TestSha256(unittest.TestCase):
    def test_known_vector(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vector.txt"
            path.write_bytes(b"abc")
            self.assertEqual(sha256_file(path), SHA256_ABC)


class TestEvidenceStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root)

    def test_write_json_namespaced_and_relative_ref(self):
        ref = self.store.write_json("01_identity", "policy.json", {"a": 1})
        path = self.root / ref
        self.assertTrue(path.exists())
        self.assertEqual(path.parent.name, "01_identity")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 1})

    def test_write_json_serialises_non_json_types_via_str(self):
        import datetime

        ref = self.store.write_json("ns", "dates.json", {"when": datetime.date(2026, 7, 29)})
        data = json.loads((self.root / ref).read_text(encoding="utf-8"))
        self.assertEqual(data["when"], "2026-07-29")

    def test_write_text(self):
        ref = self.store.write_text("02_s3", "listing.txt", "bucket-a\n")
        self.assertEqual((self.root / ref).read_text(encoding="utf-8"), "bucket-a\n")


class TestManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write_artifacts(self):
        (self.root / "findings.json").write_text("[]", encoding="utf-8")
        store = EvidenceStore(self.root)
        store.write_text("01_identity", "report.csv", "user\nroot\n")

    def test_manifest_covers_every_artifact_except_itself(self):
        self.write_artifacts()
        manifest_path = write_manifest(self.root, "AWS", "111122223333", "Assessment")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        paths = {a["RelativePath"] for a in manifest["Artifacts"]}
        self.assertIn("findings.json", paths)
        self.assertIn("evidence/01_identity/report.csv", paths)
        self.assertNotIn("manifest.json", paths)
        self.assertEqual(manifest["ArtifactCount"], len(manifest["Artifacts"]))
        self.assertEqual(manifest["HashAlgorithm"], "SHA256")
        self.assertEqual(manifest["AccountScope"], "111122223333")

    def test_relative_paths_use_forward_slashes(self):
        self.write_artifacts()
        manifest = json.loads(write_manifest(self.root, "AWS", "1", "Assessment").read_text(encoding="utf-8"))
        for artifact in manifest["Artifacts"]:
            self.assertNotIn("\\", artifact["RelativePath"], "manifest paths must be platform-independent")

    def test_tampering_changes_the_recorded_hash(self):
        self.write_artifacts()
        before = json.loads(write_manifest(self.root, "AWS", "1", "Assessment").read_text(encoding="utf-8"))
        (self.root / "findings.json").write_text('[{"tampered": true}]', encoding="utf-8")
        after = json.loads(write_manifest(self.root, "AWS", "1", "Assessment").read_text(encoding="utf-8"))

        def hash_of(manifest, rel):
            return next(a["SHA256"] for a in manifest["Artifacts"] if a["RelativePath"] == rel)

        self.assertNotEqual(hash_of(before, "findings.json"), hash_of(after, "findings.json"))
        self.assertEqual(
            hash_of(before, "evidence/01_identity/report.csv"),
            hash_of(after, "evidence/01_identity/report.csv"),
        )

    def test_byte_lengths_recorded(self):
        self.write_artifacts()
        manifest = json.loads(write_manifest(self.root, "AWS", "1", "Assessment").read_text(encoding="utf-8"))
        findings = next(a for a in manifest["Artifacts"] if a["RelativePath"] == "findings.json")
        self.assertEqual(findings["ByteLength"], 2)

    def test_last_write_time_comes_from_file_metadata(self):
        self.write_artifacts()
        findings_path = self.root / "findings.json"
        expected_epoch = 1_700_000_000
        os.utime(findings_path, (expected_epoch, expected_epoch))
        manifest = json.loads(write_manifest(self.root, "AWS", "1", "Assessment").read_text(encoding="utf-8"))
        findings = next(a for a in manifest["Artifacts"] if a["RelativePath"] == "findings.json")
        self.assertEqual(findings["LastWriteTimeUtc"], "2023-11-14T22:13:20Z")

    def test_source_revision_is_recorded(self):
        self.write_artifacts()
        revision = "a" * 40
        manifest = json.loads(
            write_manifest(self.root, "AWS", "1", "Assessment", source_revision=revision).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["SourceRevision"], revision)


if __name__ == "__main__":
    unittest.main()
