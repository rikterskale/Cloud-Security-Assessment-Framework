"""Report writers: CSV/JSON integrity, ordering, and HTML injection safety."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from csaf.coverage import Coverage
from csaf.model import ControlResult, finding_from_result
from csaf.reporting import (
    write_control_results,
    write_coverage,
    write_executive_html,
    write_findings,
    write_remediation_roadmap,
)


def make_result(cid, status="Fail", severity="HIGH", title="Title", resource_id=""):
    return ControlResult(
        control_id=cid,
        title=title,
        category="c",
        status=status,
        severity=severity if status in ("Fail", "Review") else "INFO",
        cloud="AWS",
        account_id="1",
        region="global",
        resource_id=resource_id,
    )


def make_finding(cid, severity="HIGH", title="Title", resource_id="r", remediation="fix"):
    return finding_from_result(make_result(cid, "Fail", severity, title, resource_id), remediation)


def full_coverage(**overrides):
    values = dict(selected=2, executed=2, passed=1, failed=1, review=0, not_applicable=0, not_tested=0, error=0)
    values.update(overrides)
    return Coverage(**values)


CONTEXT = {"cloud": "AWS", "accountId": "111122223333", "profile": "Assessment"}
RISK = {
    "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "weighted_score": 40,
    "normalised_score": 20.0,
    "rating": "MEDIUM",
}


class ReportingTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)


class TestControlResults(ReportingTestCase):
    def test_jsonl_and_csv_rows_align(self):
        results = [make_result("CSAF-AWS-IAM-001", "Pass"), make_result("CSAF-AWS-IAM-002", "Fail")]
        write_control_results(results, self.out)

        lines = (self.out / "control-results.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["ControlId"], "CSAF-AWS-IAM-001")

        with open(self.out / "control-results.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual([r["ControlId"] for r in rows], ["CSAF-AWS-IAM-001", "CSAF-AWS-IAM-002"])
        self.assertEqual(rows[1]["Status"], "Fail")


class TestFindings(ReportingTestCase):
    def test_ordered_most_severe_first(self):
        findings = [
            make_finding("CSAF-AWS-A-001", "LOW"),
            make_finding("CSAF-AWS-B-001", "CRITICAL"),
            make_finding("CSAF-AWS-C-001", "MEDIUM"),
        ]
        write_findings(findings, self.out)
        data = json.loads((self.out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual([f["Severity"] for f in data], ["CRITICAL", "MEDIUM", "LOW"])

    def test_csv_columns_populated(self):
        write_findings([make_finding("CSAF-AWS-A-001")], self.out)
        with open(self.out / "findings.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["ControlId"], "CSAF-AWS-A-001")
        self.assertEqual(rows[0]["Remediation"], "fix")
        self.assertRegex(rows[0]["FindingId"], r"^F-[A-F0-9]{16}$")


class TestCoverageReport(ReportingTestCase):
    def test_not_tested_ids_listed(self):
        write_coverage(full_coverage(not_tested=1, selected=3), ["CSAF-AWS-OPS-001"], self.out)
        payload = json.loads((self.out / "coverage-report.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["NotTestedControls"], ["CSAF-AWS-OPS-001"])
        self.assertEqual(payload["SelectedControls"], 3)

    def test_csv_metric_rows(self):
        write_coverage(full_coverage(), [], self.out)
        with open(self.out / "coverage-report.csv", newline="", encoding="utf-8") as handle:
            rows = {row[0]: row[1] for row in csv.reader(handle) if row}
        self.assertEqual(rows["SelectedControls"], "2")
        self.assertEqual(rows["AllSelectedControlsExecuted"], "True")


class TestRemediationRoadmap(ReportingTestCase):
    def test_horizons_by_severity_and_priority_order(self):
        findings = [
            make_finding("CSAF-AWS-A-001", "MEDIUM"),
            make_finding("CSAF-AWS-B-001", "CRITICAL"),
            make_finding("CSAF-AWS-C-001", "LOW"),
            make_finding("CSAF-AWS-D-001", "HIGH"),
        ]
        write_remediation_roadmap(findings, self.out)
        with open(self.out / "remediation-roadmap.csv", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual([r["Severity"] for r in rows], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.assertEqual([r["Horizon"] for r in rows], ["0-24h", "1-7d", "1-4w", "1-3m"])
        self.assertEqual([r["Priority"] for r in rows], ["1", "2", "3", "4"])


class TestExecutiveHtml(ReportingTestCase):
    def render(self, findings, coverage=None, compliance=None):
        write_executive_html(findings, coverage or full_coverage(), RISK, compliance or {}, CONTEXT, self.out)
        return (self.out / "executive-summary.html").read_text(encoding="utf-8")

    def test_untrusted_values_are_escaped(self):
        hostile = make_finding(
            "CSAF-AWS-X-001",
            title='<script>alert("xss")</script>',
            resource_id="<img src=x onerror=alert(1)>",
        )
        html_doc = self.render([hostile])
        self.assertNotIn("<script>alert", html_doc)
        self.assertNotIn("<img src=x", html_doc)
        self.assertIn("&lt;script&gt;", html_doc)

    def test_incomplete_coverage_banner(self):
        html_doc = self.render([], coverage=full_coverage(not_tested=1))
        self.assertIn("Coverage incomplete", html_doc)
        clean = self.render([], coverage=full_coverage())
        self.assertNotIn("Coverage incomplete", clean)

    def test_empty_states_render_fallback_rows(self):
        html_doc = self.render([])
        self.assertIn("No findings.", html_doc)
        self.assertIn("No mapped controls evaluated.", html_doc)

    def test_compliance_rollup_percentages(self):
        compliance = {"CIS-AWS": {"name": "CIS AWS Foundations", "evaluated": 4, "passed": 3, "failed": 1}}
        html_doc = self.render([], compliance=compliance)
        self.assertIn("3/4", html_doc)
        self.assertIn("75%", html_doc)

    def test_50_or_fewer_findings_has_no_all_findings_section(self):
        findings = [make_finding(f"CSAF-AWS-X-{i:03d}", resource_id=f"r{i}") for i in range(50)]
        html_doc = self.render(findings)
        self.assertNotIn("Show all", html_doc)
        self.assertIn("<h2>Findings</h2>", html_doc)

    def test_over_50_findings_adds_collapsible_full_list(self):
        findings = [make_finding(f"CSAF-AWS-X-{i:03d}", severity="CRITICAL", resource_id=f"r{i}") for i in range(75)]
        html_doc = self.render(findings)
        self.assertIn("<h2>Top Findings</h2>", html_doc)
        self.assertIn("Show all 75 findings", html_doc)
        self.assertIn("<details", html_doc)
        # Every finding's resource ID must appear somewhere (nothing silently dropped).
        for i in range(75):
            self.assertIn(f"r{i}", html_doc)
        # Preview table (50 rows) + full table inside <details> (75 rows) = 125 severity rows total.
        self.assertEqual(html_doc.count('<tr class="critical">'), 50 + 75)


if __name__ == "__main__":
    unittest.main()
