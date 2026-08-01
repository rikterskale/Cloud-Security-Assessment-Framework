"""SARIF and OSCAL export writers (OFF-FEAT-004)."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.export_formats import build_oscal, build_sarif, write_oscal, write_sarif
from csaf.model import ControlResult, finding_from_result


def make_finding(cid="CIS-1.1", severity="HIGH", resource_id="bucket-a", status="Fail"):
    result = ControlResult(
        control_id=cid,
        title="Public bucket",
        category="s3",
        status=status,
        severity=severity if status in ("Fail", "Review") else "INFO",
        cloud="AWS",
        account_id="123456789012",
        region="us-east-1",
        resource_type="s3-bucket",
        resource_id=resource_id,
        mappings=["CIS-AWS-1.5:1.1", "MITRE:T1530"],
    )
    return finding_from_result(result, "Block public access.")


CONTEXT = {
    "runId": "RUN-1",
    "cloud": "AWS",
    "accountId": "123456789012",
    "profile": "Assessment",
    "sourceRevision": "abc",
}


class TestSarif(unittest.TestCase):
    def test_sarif_structure_and_levels(self):
        findings = [
            make_finding(severity="CRITICAL"),
            make_finding(cid="CIS-2.1", severity="MEDIUM", resource_id="vpc-1"),
        ]
        doc = build_sarif(findings, CONTEXT)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "CSAF")
        # One rule per distinct control.
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"CIS-1.1", "CIS-2.1"})
        levels = [r["level"] for r in run["results"]]
        self.assertIn("error", levels)  # CRITICAL -> error
        self.assertIn("warning", levels)  # MEDIUM -> warning
        # Fingerprint carries the stable finding id.
        self.assertTrue(all("csafFindingId" in r["partialFingerprints"] for r in run["results"]))

    def test_sarif_empty_findings(self):
        doc = build_sarif([], CONTEXT)
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])

    def test_write_sarif_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_sarif([make_finding()], CONTEXT, Path(tmp))
            self.assertEqual(path.name, "findings.sarif.json")
            loaded = json.loads(path.read_text())
            self.assertEqual(loaded["version"], "2.1.0")


class TestOscal(unittest.TestCase):
    def test_oscal_structure(self):
        doc = build_oscal([make_finding()], CONTEXT)
        ar = doc["assessment-results"]
        self.assertIn("uuid", ar)
        self.assertEqual(ar["metadata"]["oscal-version"], "1.1.2")
        finding = ar["results"][0]["findings"][0]
        self.assertEqual(finding["target"]["status"]["state"], "not-satisfied")
        self.assertTrue(finding["remediations"])

    def test_oscal_uuids_are_deterministic(self):
        a = build_oscal([make_finding()], CONTEXT)
        b = build_oscal([make_finding()], CONTEXT)
        self.assertEqual(
            a["assessment-results"]["results"][0]["findings"][0]["uuid"],
            b["assessment-results"]["results"][0]["findings"][0]["uuid"],
        )

    def test_write_oscal_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_oscal([make_finding()], CONTEXT, Path(tmp))
            self.assertEqual(path.name, "findings.oscal.json")
            self.assertIn("assessment-results", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
