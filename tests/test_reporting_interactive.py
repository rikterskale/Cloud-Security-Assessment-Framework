"""Interactive HTML report toolbar (OFF-FEAT-010).

Verifies the client-side filter/pivot is present, is a single self-contained
file with no external calls, and does not weaken HTML-injection escaping.
"""

import tempfile
import unittest
from pathlib import Path

from csaf.coverage import Coverage
from csaf.model import ControlResult, finding_from_result
from csaf.reporting import write_executive_html

RISK = {"normalised_score": 50, "rating": "HIGH", "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}}
CONTEXT = {"cloud": "AWS", "accountId": "1", "profile": "Assessment"}


def full_coverage():
    return Coverage(selected=2, executed=2, passed=0, failed=2, review=0, not_applicable=0, not_tested=0, error=0)


def make_finding(cid, severity="HIGH", title="Title", resource_id="r"):
    result = ControlResult(
        control_id=cid,
        title=title,
        category="c",
        status="Fail",
        severity=severity,
        cloud="AWS",
        account_id="1",
        region="global",
        resource_id=resource_id,
    )
    return finding_from_result(result, "Fix it.")


class TestInteractiveReport(unittest.TestCase):
    def render(self, findings):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_executive_html(findings, full_coverage(), RISK, {}, CONTEXT, out)
            return (out / "executive-summary.html").read_text(encoding="utf-8")

    def test_toolbar_and_script_present(self):
        html_doc = self.render([make_finding("A", "CRITICAL"), make_finding("B", "HIGH")])
        self.assertIn('id="csaf-q"', html_doc)  # search box
        self.assertIn('data-sev="critical"', html_doc)  # severity filter
        self.assertIn('class="findings-table"', html_doc)  # filter target
        self.assertIn("addEventListener('input'", html_doc)  # wired up

    def test_no_external_resources(self):
        html_doc = self.render([make_finding("A")])
        for token in ("http://", "https://", "src=", "cdn", "<link"):
            self.assertNotIn(token, html_doc.lower() if token == "cdn" else html_doc)

    def test_injection_still_escaped_with_toolbar(self):
        hostile = make_finding("X", "HIGH", title='<script>alert("xss")</script>', resource_id="<img src=x>")
        html_doc = self.render([hostile])
        self.assertNotIn("<script>alert", html_doc)
        self.assertNotIn("<img src=x", html_doc)
        self.assertIn("&lt;script&gt;", html_doc)


if __name__ == "__main__":
    unittest.main()
