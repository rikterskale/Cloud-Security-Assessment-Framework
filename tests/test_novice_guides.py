"""Novice-guide validator (roadmap #3 / REV-DOC-004)."""

import tempfile
import unittest
from pathlib import Path

from tests.validate_novice_guides import REQUIRED_HEADINGS, main, validate_all, validate_guide


class TestRealGuides(unittest.TestCase):
    def test_shipped_guides_are_valid(self):
        problems = validate_all()
        self.assertEqual(problems, [], f"novice guide problems: {problems}")

    def test_main_exit_zero(self):
        self.assertEqual(main([]), 0)


def _synthetic_guide(**overrides) -> str:
    fm = {
        "guide_id": "linux-novice-usability",
        "platform": "linux",
        "canonical_path": "docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md",
        "project_name": "CSAF",
        "target_release": "1.0.0",
        "target_commit": "abc",
        "support_status": "native_supported",
        "validation_status": "partially_verified",
    }
    fm.update(overrides.get("front_matter", {}))
    lines = ["---"] + [f"{k}: {v}" for k, v in fm.items()] + ["---", ""]
    for i, heading in enumerate(REQUIRED_HEADINGS, 1):
        lines.append(f"## {i}. {heading}")
        lines.append("Body text.")
    body = "\n".join(lines) + "\n" + overrides.get("extra", "")
    return body


class TestValidatorCatchesProblems(unittest.TestCase):
    def _write(self, tmp, text):
        path = Path(tmp) / "LINUX_NOVICE_USABILITY_GUIDE.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_missing_heading_flagged(self):
        text = _synthetic_guide()
        text = text.replace("## 26. Troubleshooting Matrix\nBody text.\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            problems = validate_guide("linux", self._write(tmp, text))
        self.assertTrue(any("Troubleshooting Matrix" in p for p in problems))

    def test_bad_validation_status_flagged(self):
        text = _synthetic_guide(front_matter={"validation_status": "totally_verified"})
        with tempfile.TemporaryDirectory() as tmp:
            problems = validate_guide("linux", self._write(tmp, text))
        self.assertTrue(any("validation_status" in p for p in problems))

    def test_placeholder_flagged(self):
        text = _synthetic_guide(extra="Run this: {{FILL_ME_IN}}")
        with tempfile.TemporaryDirectory() as tmp:
            problems = validate_guide("linux", self._write(tmp, text))
        self.assertTrue(any("placeholder" in p for p in problems))

    def test_unsafe_instruction_flagged(self):
        text = _synthetic_guide(extra="If it fails, disable your antivirus and retry.")
        with tempfile.TemporaryDirectory() as tmp:
            problems = validate_guide("linux", self._write(tmp, text))
        self.assertTrue(any("unsafe" in p for p in problems))

    def test_missing_file_flagged(self):
        problems = validate_guide("linux", Path("/nonexistent/guide.md"))
        self.assertTrue(any("missing canonical guide" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
