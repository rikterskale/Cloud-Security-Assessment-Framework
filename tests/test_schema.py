"""Schema conformance: every record a real run emits must validate.

Skipped without jsonschema (it is installed in CI via requirements-ci.txt).
"""

import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

try:
    import jsonschema

    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False


def load_schema(name):
    return json.loads((REPO / "schemas" / name).read_text(encoding="utf-8"))


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class TestHandBuiltExamples(unittest.TestCase):
    def test_control_result_schema_example(self):
        from csaf.model import ControlResult

        result = ControlResult(
            control_id="CSAF-AWS-IAM-001",
            title="t",
            category="Identity",
            status="Fail",
            severity="CRITICAL",
            cloud="AWS",
            account_id="123",
            observed_value="x",
            expected_value="y",
        )
        jsonschema.validate(result.to_dict(), load_schema("control-result.schema.json"))

    def test_finding_schema_example(self):
        from csaf.model import ControlResult, finding_from_result

        result = ControlResult(
            control_id="CSAF-AWS-S3-002",
            title="t",
            category="DataProtection",
            status="Fail",
            severity="HIGH",
            cloud="AWS",
            account_id="123",
            resource_id="bucket",
        )
        finding = finding_from_result(result, "fix")
        jsonschema.validate(finding.to_dict(), load_schema("finding.schema.json"))

    def test_engagement_example_validates(self):
        example = json.loads((REPO / "schemas" / "engagement.example.json").read_text(encoding="utf-8"))
        jsonschema.validate(example, load_schema("engagement.schema.json"))

    def test_manifest_example_valid_json(self):
        manifest = json.loads((REPO / "schemas" / "manifest.example.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["ArtifactCount"], len(manifest["Artifacts"]))


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class TestFullRunConformance(unittest.TestCase):
    """Every record emitted by a complete self-check run must validate."""

    @classmethod
    def setUpClass(cls):
        from csaf.runner import RunConfig, run_assessment

        cls.tmp = tempfile.TemporaryDirectory()
        config = RunConfig(
            profile="Assessment",
            catalog_path=str(REPO / "controls" / "control-catalog.json"),
            baseline_path=str(REPO / "baselines" / "aws-cis-1.5.json"),
            output_dir=cls.tmp.name,
            self_check=True,
            log_level="ERROR",
        )
        run_assessment(config)
        cls.out = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_control_result_line_validates(self):
        schema = load_schema("control-result.schema.json")
        validator = jsonschema.Draft202012Validator(schema)
        lines = (self.out / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(lines), 20)
        for line in lines:
            record = json.loads(line)
            errors = list(validator.iter_errors(record))
            self.assertEqual(errors, [], f"{record.get('ControlId')}: {[e.message for e in errors]}")

    def test_every_finding_validates(self):
        schema = load_schema("finding.schema.json")
        validator = jsonschema.Draft202012Validator(schema)
        findings = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertGreater(len(findings), 0)
        for record in findings:
            errors = list(validator.iter_errors(record))
            self.assertEqual(errors, [], f"{record.get('FindingId')}: {[e.message for e in errors]}")

    def test_technical_report_control_results_match_jsonl(self):
        tech = json.loads((self.out / "technical-report.json").read_text(encoding="utf-8"))
        jsonl_ids = [
            json.loads(line)["ControlId"]
            for line in (self.out / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([r["ControlId"] for r in tech["ControlResults"]], jsonl_ids)

    def test_manifest_hashes_verify_against_artifacts(self):
        from csaf.evidence import sha256_file

        manifest = json.loads((self.out / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreater(manifest["ArtifactCount"], 5)
        for artifact in manifest["Artifacts"]:
            path = self.out / artifact["RelativePath"]
            self.assertTrue(path.exists(), artifact["RelativePath"])
            self.assertEqual(sha256_file(path), artifact["SHA256"], f"hash mismatch for {artifact['RelativePath']}")


if __name__ == "__main__":
    unittest.main()
