"""Small documentation drift guards for the supported user-facing contract."""

import unittest
from pathlib import Path

import tomllib

from invoke_assessment import build_parser

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    def test_readme_mentions_every_cli_option(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        options = {
            option for action in build_parser()._actions for option in action.option_strings if option.startswith("--")
        }
        self.assertEqual([], sorted(option for option in options if option not in readme))

    def test_readme_matches_cli_choice_sets(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for action in build_parser()._actions:
            if action.dest in {"cloud", "profile"}:
                for choice in action.choices:
                    self.assertIn(f"`{choice}`", readme)

    def test_documented_catalog_counts_are_present(self):
        import json

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in (
            "control-catalog.json",
            "control-catalog-azure.json",
            "control-catalog-gcp.json",
            "control-catalog-k8s.json",
        ):
            path = ROOT / "controls" / name
            self.assertTrue(path.is_file())
            # Count is derived from the catalog so the README can never drift.
            count = len(json.loads(path.read_text(encoding="utf-8"))["controls"])
            self.assertIn(f"{count} controls", readme, f"README must state '{count} controls' for {name}")

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

    def test_readme_novice_guide_links_target_existing_canonical_guides(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for guide in (
            "docs/guides/WINDOWS_NOVICE_USABILITY_GUIDE.md",
            "docs/guides/LINUX_NOVICE_USABILITY_GUIDE.md",
        ):
            self.assertIn(f"]({guide})", readme)
            self.assertTrue((ROOT / guide).is_file())

    def test_campaign_documentation_distinguishes_signing_from_running(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Create, sign, verify, or run a replayable assessment", readme)
        self.assertIn("can contact the selected\ncloud unless", readme)

    def test_readme_links_to_companion_command_reference(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        reference = ROOT / "docs" / "COMPANION_COMMANDS.md"
        self.assertIn("](docs/COMPANION_COMMANDS.md)", readme)
        self.assertTrue(reference.is_file())
        text = reference.read_text(encoding="utf-8")
        for command in (
            "csaf-sign-engagement",
            "csaf-lint-catalog",
            "csaf-new-module",
            "csaf-attest",
            "csaf-drift",
            "csaf-aggregate",
            "csaf-detection-pack",
            "csaf-attack-path",
            "csaf-campaign",
        ):
            self.assertIn(command, text)

    def test_every_packaged_console_script_is_documented(self):
        manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        documented = "\n".join(
            (
                (ROOT / "README.md").read_text(encoding="utf-8"),
                (ROOT / "docs" / "COMPANION_COMMANDS.md").read_text(encoding="utf-8"),
            )
        )
        for command in manifest["project"]["scripts"]:
            self.assertIn(command, documented, f"Missing documentation for console script: {command}")


if __name__ == "__main__":
    unittest.main()
