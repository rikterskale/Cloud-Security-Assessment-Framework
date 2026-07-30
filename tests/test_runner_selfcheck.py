"""End-to-end offline run of the whole pipeline via the self-check provider."""

import contextlib
import io
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

            out = Path(result.output_dir)
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
            self.assertRegex(tech["Context"]["sourceRevision"], r"^(?:[0-9a-f]{40}|unknown)$")
            self.assertIn("Coverage", tech)
            self.assertIn("Risk", tech)

            manifest = json.loads((out / "manifest.json").read_text())
            self.assertEqual(manifest["ArtifactCount"], len(manifest["Artifacts"]))
            self.assertTrue(all(a["SHA256"] for a in manifest["Artifacts"]))
            self.assertEqual(manifest["SourceRevision"], tech["Context"]["sourceRevision"])

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

                out = Path(result.output_dir)
                tech = json.loads((out / "technical-report.json").read_text())
                self.assertEqual(tech["Context"]["cloud"], label)
                results = [json.loads(line) for line in (out / "control-results.jsonl").read_text().splitlines()]
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
            result = run_assessment(config)
            out = Path(result.output_dir)
            control_rows = [json.loads(line) for line in (out / "control-results.jsonl").read_text().splitlines()]
            findings = json.loads((out / "findings.json").read_text())
            fail_review = {r["ControlId"] for r in control_rows if r["Status"] in ("Fail", "Review")}
            finding_controls = {f["ControlId"] for f in findings}
            self.assertTrue(finding_controls.issubset(fail_review))
            # No Error/NotTested control ever becomes a finding.
            bad = {r["ControlId"] for r in control_rows if r["Status"] in ("Error", "NotTested")}
            self.assertTrue(finding_controls.isdisjoint(bad))

    def test_manifest_hashes_include_final_log_records(self):
        from csaf.evidence import sha256_file

        with tempfile.TemporaryDirectory() as tmp:
            config = RunConfig(
                profile="Assessment",
                catalog_path=str(REPO / "controls" / "control-catalog.json"),
                baseline_path=str(REPO / "baselines" / "aws-cis-1.5.json"),
                output_dir=tmp,
                self_check=True,
                log_level="INFO",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = run_assessment(config)
            out = Path(result.output_dir)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            for artifact in manifest["Artifacts"]:
                path = out / artifact["RelativePath"]
                self.assertEqual(sha256_file(path), artifact["SHA256"], artifact["RelativePath"])


if __name__ == "__main__":
    unittest.main()
