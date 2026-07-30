"""Guard CI configuration invariants so security gates cannot silently vanish."""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI = REPO / ".github" / "workflows" / "ci.yml"
RELEASE = REPO / ".github" / "workflows" / "release.yml"


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
            "installed-wheel smoke test",
        ]:
            self.assertIn(token, self.text, f"CI is missing required gate: {token}")

    def test_sbom_job_required_for_ci_success(self):
        self.assertIn("sbom", self.text)
        needs_line = next(line for line in self.text.splitlines() if "needs:" in line)
        self.assertIn("sbom", needs_line, "ci-success must depend on the sbom job")

    def test_python_matrix(self):
        for version in ["3.10", "3.12"]:
            self.assertIn(version, self.text, f"CI matrix missing Python {version}")

    def test_release_builds_and_attests_distributions(self):
        text = RELEASE.read_text(encoding="utf-8")
        for token in [
            "python -m build",
            "twine check",
            "cyclonedx-json",
            "SHA256SUMS",
            "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
            "gh release create",
        ]:
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
