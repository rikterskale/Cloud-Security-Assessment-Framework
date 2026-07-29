"""End-to-end offline run of the whole pipeline via the self-check provider."""

import json
import tempfile
import unittest
from pathlib import Path

from csaf.runner import EXIT_INCOMPLETE, RunConfig, run_assessment

REPO = Path(__file__).resolve().parent.parent


class TestSelfCheckRun(unittest.TestCase):
    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = RunConfig(
                profile="Assessment",
                catalog_path=str(REPO / "controls" / "control-catalog.json"),
                baseline_path=str(REPO / "baselines" / "aws-cis-1.5.json"),
                output_dir=tmp,
                self_check=True,
                log_level="ERROR",
            )
            result = run_assessment(config)

            # OPS-001 is NotTested in the demo posture -> incomplete coverage.
            self.assertEqual(result.exit_code, EXIT_INCOMPLETE)
            self.assertFalse(result.all_executed)
            self.assertGreater(result.finding_count, 0)

            out = Path(tmp)
            for name in [
                "findings.csv",
                "findings.json",
                "control-results.jsonl",
                "control-results.csv",
                "coverage-report.json",
                "coverage-report.csv",
                "remediation-roadmap.csv",
                "technical-report.json",
                "executive-summary.html",
                "manifest.json",
            ]:
                self.assertTrue((out / name).exists(), f"missing report: {name}")

            tech = json.loads((out / "technical-report.json").read_text())
            self.assertEqual(tech["Context"]["cloud"], "AWS")
            self.assertIn("Coverage", tech)
            self.assertIn("Risk", tech)

            manifest = json.loads((out / "manifest.json").read_text())
            self.assertEqual(manifest["ArtifactCount"], len(manifest["Artifacts"]))
            self.assertTrue(all(a["SHA256"] for a in manifest["Artifacts"]))

    def test_azure_and_gcp_self_check_pipelines(self):
        baselines = {"azure": "azure-cis-2.0.json", "gcp": "gcp-cis-1.3.json", "k8s": "k8s-cis-1.8.json"}
        for cloud, label in (("azure", "Azure"), ("gcp", "GCP"), ("k8s", "K8s")):
            with self.subTest(cloud=cloud), tempfile.TemporaryDirectory() as tmp:
                config = RunConfig(
                    profile="Assessment",
                    cloud=cloud,
                    catalog_path=str(REPO / "controls" / f"control-catalog-{cloud}.json"),
                    baseline_path=str(REPO / "baselines" / baselines[cloud]),
                    output_dir=tmp,
                    self_check=True,
                    log_level="ERROR",
                )
                result = run_assessment(config)

                # OPS-001 is NotTested in each demo posture -> incomplete coverage.
                self.assertEqual(result.exit_code, EXIT_INCOMPLETE)
                self.assertGreater(result.finding_count, 0)

                tech = json.loads((Path(tmp) / "technical-report.json").read_text())
                self.assertEqual(tech["Context"]["cloud"], label)
                results = [json.loads(line) for line in (Path(tmp) / "control-results.jsonl").read_text().splitlines()]
                self.assertTrue(all(r["Cloud"] == label for r in results))

    def test_findings_are_subset_of_failed_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = RunConfig(
                profile="Assessment",
                catalog_path=str(REPO / "controls" / "control-catalog.json"),
                baseline_path=str(REPO / "baselines" / "aws-cis-1.5.json"),
                output_dir=tmp,
                self_check=True,
                log_level="ERROR",
            )
            run_assessment(config)
            out = Path(tmp)
            control_rows = [json.loads(line) for line in (out / "control-results.jsonl").read_text().splitlines()]
            findings = json.loads((out / "findings.json").read_text())
            fail_review = {r["ControlId"] for r in control_rows if r["Status"] in ("Fail", "Review")}
            finding_controls = {f["ControlId"] for f in findings}
            self.assertTrue(finding_controls.issubset(fail_review))
            # No Error/NotTested control ever becomes a finding.
            bad = {r["ControlId"] for r in control_rows if r["Status"] in ("Error", "NotTested")}
            self.assertTrue(finding_controls.isdisjoint(bad))


if __name__ == "__main__":
    unittest.main()
