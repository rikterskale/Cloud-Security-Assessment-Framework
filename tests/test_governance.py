"""Governance files exist and are well-formed (roadmap #7 / REV-GOV-006)."""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class TestGovernanceFiles(unittest.TestCase):
    def test_codeowners_present_with_default_rule(self):
        codeowners = REPO / ".github" / "CODEOWNERS"
        self.assertTrue(codeowners.is_file(), "CODEOWNERS missing")
        text = codeowners.read_text(encoding="utf-8")
        rules = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        self.assertTrue(rules, "CODEOWNERS has no rules")
        # A catch-all default owner and every rule must name at least one @owner.
        self.assertTrue(any(line.split()[0] == "*" for line in rules), "no default '*' owner rule")
        for line in rules:
            self.assertTrue(any(tok.startswith("@") for tok in line.split()[1:]), f"rule has no owner: {line!r}")

    def test_codeowners_covers_security_critical_paths(self):
        text = (REPO / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        for path in ("engagement.py", "session.py", "/.github/workflows/"):
            self.assertIn(path, text, f"CODEOWNERS does not call out {path}")

    def test_contributing_covers_tests_and_security(self):
        contributing = REPO / "CONTRIBUTING.md"
        self.assertTrue(contributing.is_file(), "CONTRIBUTING.md missing")
        text = contributing.read_text(encoding="utf-8").lower()
        self.assertIn("read-only", text)
        self.assertIn("coverage", text)
        self.assertIn("security.md", text)

    def test_pr_template_has_safety_scope(self):
        pr = REPO / ".github" / "PULL_REQUEST_TEMPLATE.md"
        self.assertTrue(pr.is_file(), "PR template missing")
        text = pr.read_text(encoding="utf-8").lower()
        self.assertIn("safety scope", text)
        self.assertIn("read-only", text)

    def test_issue_templates_present(self):
        base = REPO / ".github" / "ISSUE_TEMPLATE"
        self.assertTrue((base / "bug_report.md").is_file())
        self.assertTrue((base / "feature_request.md").is_file())
        # Bug template must steer security issues to the private path.
        self.assertIn("SECURITY.md", (base / "bug_report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
