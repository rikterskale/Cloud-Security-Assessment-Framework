"""Guard CI configuration invariants so security gates cannot silently vanish."""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CI = REPO / ".github" / "workflows" / "ci.yml"


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
        ]:
            self.assertIn(token, self.text, f"CI is missing required gate: {token}")

    def test_python_matrix(self):
        for version in ["3.10", "3.12"]:
            self.assertIn(version, self.text, f"CI matrix missing Python {version}")


if __name__ == "__main__":
    unittest.main()
