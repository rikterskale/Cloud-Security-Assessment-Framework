"""Small documentation drift guards for the supported user-facing contract."""

import unittest
from pathlib import Path

from invoke_assessment import build_parser

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    def test_readme_mentions_every_cli_option(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        options = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
            if option.startswith("--")
        }
        self.assertEqual([], sorted(option for option in options if option not in readme))

    def test_readme_matches_cli_choice_sets(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for action in build_parser()._actions:
            if action.dest in {"cloud", "profile"}:
                for choice in action.choices:
                    self.assertIn(f"`{choice}`", readme)

    def test_documented_catalog_counts_are_present(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        catalogs = (
            (31, "control-catalog.json"),
            (16, "control-catalog-azure.json"),
            (19, "control-catalog-gcp.json"),
            (5, "control-catalog-k8s.json"),
        )
        for count, name in catalogs:
            self.assertIn(f"{count} controls", readme)
            self.assertTrue((ROOT / "controls" / name).is_file())

    def test_key_output_artifacts_are_documented(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        artifacts = (
            "assessment-<ts>.log",
            "control-results.jsonl",
            "findings.json",
            "technical-report.json",
            "executive-summary.html",
            "manifest.json",
        )
        for name in artifacts:
            self.assertIn(name, readme)


if __name__ == "__main__":
    unittest.main()
