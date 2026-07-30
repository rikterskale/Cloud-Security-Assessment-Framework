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


class TestCloudVocabularies(unittest.TestCase):
    def test_output_schemas_use_runtime_cloud_labels(self):
        expected = {"AWS", "Azure", "GCP", "K8s"}
        self.assertEqual(set(load_schema("control-result.schema.json")["properties"]["Cloud"]["enum"]), expected)
        self.assertEqual(set(load_schema("finding.schema.json")["properties"]["Cloud"]["enum"]), expected)
        self.assertEqual(set(load_schema("engagement.schema.json")["properties"]["cloud"]["enum"]), expected)

    def test_engagement_scope_identifiers_are_provider_neutral(self):
        item_schema = load_schema("engagement.schema.json")["properties"]["authorizedAccounts"]["items"]
        self.assertNotIn("pattern", item_schema)
        self.assertEqual(item_schema["minLength"], 1)


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
    """Every record emitted by all four self-check pipelines must validate."""

    @classmethod
    def setUpClass(cls):
        from csaf.runner import RunConfig, run_assessment

        cls.tmp = tempfile.TemporaryDirectory()
        cls.outputs = {}
        inputs = {
            "aws": ("control-catalog.json", "aws-cis-1.5.json"),
            "azure": ("control-catalog-azure.json", "azure-cis-2.0.json"),
            "gcp": ("control-catalog-gcp.json", "gcp-cis-1.3.json"),
            "k8s": ("control-catalog-k8s.json", "k8s-cis-1.8.json"),
        }
        for cloud, (catalog, baseline) in inputs.items():
            output = Path(cls.tmp.name) / cloud
            config = RunConfig(
                profile="Assessment",
                cloud=cloud,
                catalog_path=str(REPO / "controls" / catalog),
                baseline_path=str(REPO / "baselines" / baseline),
                output_dir=str(output),
                self_check=True,
                log_level="ERROR",
            )
            result = run_assessment(config)
            cls.outputs[cloud] = Path(result.output_dir)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_control_result_line_validates(self):
        schema = load_schema("control-result.schema.json")
        validator = jsonschema.Draft202012Validator(schema)
        for cloud, output in self.outputs.items():
            with self.subTest(cloud=cloud):
                lines = (output / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
                self.assertGreater(len(lines), 0)
                for line in lines:
                    record = json.loads(line)
                    errors = list(validator.iter_errors(record))
                    self.assertEqual(errors, [], f"{record.get('ControlId')}: {[e.message for e in errors]}")

    def test_every_finding_validates(self):
        schema = load_schema("finding.schema.json")
        validator = jsonschema.Draft202012Validator(schema)
        for cloud, output in self.outputs.items():
            with self.subTest(cloud=cloud):
                findings = json.loads((output / "findings.json").read_text(encoding="utf-8"))
                self.assertGreater(len(findings), 0)
                for record in findings:
                    errors = list(validator.iter_errors(record))
                    self.assertEqual(errors, [], f"{record.get('FindingId')}: {[e.message for e in errors]}")

    def test_technical_report_control_results_match_jsonl(self):
        for cloud, output in self.outputs.items():
            with self.subTest(cloud=cloud):
                tech = json.loads((output / "technical-report.json").read_text(encoding="utf-8"))
                jsonl_ids = [
                    json.loads(line)["ControlId"]
                    for line in (output / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual([r["ControlId"] for r in tech["ControlResults"]], jsonl_ids)

    def test_manifest_hashes_verify_against_artifacts(self):
        from csaf.evidence import sha256_file

        for cloud, output in self.outputs.items():
            with self.subTest(cloud=cloud):
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertGreater(manifest["ArtifactCount"], 5)
                for artifact in manifest["Artifacts"]:
                    path = output / artifact["RelativePath"]
                    self.assertTrue(path.exists(), artifact["RelativePath"])
                    self.assertEqual(
                        sha256_file(path), artifact["SHA256"], f"hash mismatch for {artifact['RelativePath']}"
                    )


if __name__ == "__main__":
    unittest.main()
