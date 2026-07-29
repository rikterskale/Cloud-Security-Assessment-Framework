"""Validate generated records against the JSON schemas (skipped without jsonschema)."""

import json
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

try:
    import jsonschema

    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False


@unittest.skipUnless(HAVE_JSONSCHEMA, "jsonschema not installed")
class TestSchemas(unittest.TestCase):
    def _schema(self, name):
        return json.loads((REPO / "schemas" / name).read_text())

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
        jsonschema.validate(result.to_dict(), self._schema("control-result.schema.json"))

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
        jsonschema.validate(finding.to_dict(), self._schema("finding.schema.json"))

    def test_manifest_example_valid_json(self):
        # The example must stay parseable and self-consistent.
        manifest = json.loads((REPO / "schemas" / "manifest.example.json").read_text())
        self.assertEqual(manifest["ArtifactCount"], len(manifest["Artifacts"]))


if __name__ == "__main__":
    unittest.main()
