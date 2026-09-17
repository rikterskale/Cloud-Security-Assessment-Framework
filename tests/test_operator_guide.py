"""Operator playbooks for a first live assessment."""

import contextlib
import io
import unittest

from csaf.operator_guide import aftercare, render_guide, scan_command
from csaf.preflight import PreflightCheck, format_preflight
from invoke_assessment import main


class TestRenderGuide(unittest.TestCase):
    def test_each_cloud_has_copy_paste_steps(self):
        for cloud, token in (
            ("aws", "SecurityAudit"),
            ("azure", "Security Reader"),
            ("gcp", "roles/viewer"),
            ("k8s", "clusterrole=view"),
        ):
            text = render_guide(cloud)
            self.assertIn("read-only", text.lower())
            self.assertIn("csaf-assess --preflight --live", text)
            self.assertIn("executive-summary.html", text)
            self.assertIn(token, text)

    def test_unknown_cloud(self):
        text = render_guide("oracle")
        self.assertIn("Unknown cloud", text)
        self.assertIn("--guide --cloud aws", text)

    def test_cli_prints_guide(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["--guide", "--cloud", "azure"]), 0)
        self.assertIn("az login", buf.getvalue())
        self.assertIn("SUBSCRIPTION_ID", buf.getvalue())


class TestScanCommand(unittest.TestCase):
    def test_aws_includes_profile_and_region(self):
        cmd = scan_command("aws", aws_profile="csaf-audit", regions=["eu-west-1"])
        self.assertEqual(
            cmd,
            "csaf-assess --cloud aws --aws-profile csaf-audit --regions eu-west-1 --output-dir out",
        )

    def test_azure_and_gcp_placeholders(self):
        self.assertIn("SUBSCRIPTION_ID", scan_command("azure"))
        self.assertIn("--project my-proj", scan_command("gcp", project="my-proj"))


class TestAftercare(unittest.TestCase):
    def test_fatal_points_at_guide(self):
        text = aftercare(cloud="aws", output_dir="out/run", exit_code=1, self_check=False)
        self.assertIn("--guide --cloud aws", text)

    def test_success_explains_reports(self):
        text = aftercare(cloud="gcp", output_dir="out/run", exit_code=0, self_check=False)
        self.assertIn("did not change the cloud", text)
        self.assertIn("findings.csv", text)
        self.assertIn("coverage-report.csv", text)


class TestPreflightNextSteps(unittest.TestCase):
    def test_blocked_live_preflight_points_at_guide(self):
        checks = [
            PreflightCheck("Python version", "PASS", "3.12", required=True),
            PreflightCheck("sts", "FAIL", "no credentials", "aws sts get-caller-identity", required=True),
        ]
        text = format_preflight(checks, live=True, cloud="aws")
        self.assertIn("BLOCKED", text)
        self.assertIn("csaf-assess --guide --cloud aws", text)

    def test_passing_live_preflight_prints_scan_command(self):
        checks = [PreflightCheck("Python version", "PASS", "3.12", required=True)]
        text = format_preflight(checks, live=True, cloud="aws", aws_profile="csaf-audit")
        self.assertIn("Result: PASS", text)
        self.assertIn("--aws-profile csaf-audit", text)


if __name__ == "__main__":
    unittest.main()
