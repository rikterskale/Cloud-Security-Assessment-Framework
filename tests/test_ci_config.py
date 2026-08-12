"""Guard CI configuration invariants so security gates cannot silently vanish."""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI = REPO / ".github" / "workflows" / "ci.yml"
RELEASE = REPO / ".github" / "workflows" / "release.yml"
CODEQL = REPO / ".github" / "workflows" / "codeql.yml"


class TestCIConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI.read_text(encoding="utf-8")

    def test_ci_exists(self):
        self.assertTrue(CI.exists())

    def test_required_gates_present(self):
        for token in [
            "ruff check",
            "ruff format",
            "unittest",
            "pip-audit",
            "permissions:",
            "read-all",
            "coverage run",
            "--fail-under=90",
            "cyclonedx-json",
            "--require-hashes",
            "compileall",
            "pip check",
            "safe_load",
            "source-distribution",
            "installed-package smoke tests",
            "wheel-venv/bin/python -m pip check",
            "sdist-venv/bin/python -m pip check",
            "actionlint",
            "shellcheck",
            "generate_completions.py",
            "csaf.authoring",
            "dependency-review-action",
        ]:
            self.assertIn(token, self.text, f"CI is missing required gate: {token}")

    def test_sbom_job_required_for_ci_success(self):
        self.assertIn("sbom", self.text)
        needs_line = next(line for line in self.text.splitlines() if "needs:" in line)
        self.assertIn("sbom", needs_line, "ci-success must depend on the sbom job")

    def test_python_matrix(self):
        for version in ["3.10", "3.11", "3.12", "3.13", "3.14"]:
            self.assertIn(version, self.text, f"CI matrix missing Python {version}")

    def test_release_builds_and_attests_distributions(self):
        text = RELEASE.read_text(encoding="utf-8")
        for token in [
            "python -m build",
            "twine check",
            "cyclonedx-json",
            "SHA256SUMS",
            "gh release create",
        ]:
            self.assertIn(token, text)
        self.assert_pinned_action(text, "actions/attest")

    def test_codeql_scans_pushes_pull_requests_and_the_default_branch_weekly(self):
        text = CODEQL.read_text(encoding="utf-8")
        for token in [
            "security-and-quality",
            "security-events: write",
            "cron:",
        ]:
            self.assertIn(token, text, f"CodeQL is missing required configuration: {token}")
        self.assert_pinned_action(text, "github/codeql-action/init")
        self.assert_pinned_action(text, "github/codeql-action/analyze")

    def test_dependency_review_uses_a_pinned_action(self):
        self.assert_pinned_action(self.text, "actions/dependency-review-action")

    def assert_pinned_action(self, workflow_text, action):
        self.assertRegex(
            workflow_text,
            rf"{re.escape(action)}@[0-9a-f]{{40}}\b",
            f"{action} must use a full immutable commit SHA",
        )


if __name__ == "__main__":
    unittest.main()
