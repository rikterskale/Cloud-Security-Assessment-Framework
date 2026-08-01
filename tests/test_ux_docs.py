"""Docs/UX guarantees: one-command quickstart + authorizedSourceAddresses clarity.

Covers UX-ENH-002 (README leads with a verified one-command first success) and
UX-ENH-005 (the authorizedSourceAddresses fail-closed behavior is explained with
an actionable message and in the docs).
"""

import unittest
from pathlib import Path

from csaf.engagement import Engagement

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


class TestOneCommandQuickstart(unittest.TestCase):
    def test_readme_leads_with_self_check(self):
        cmd = "python3 invoke_assessment.py --self-check --output-dir out"
        self.assertIn(cmd, README)
        # It must appear before the "Assess a real environment" step.
        self.assertLess(README.index(cmd), README.index("Assess a real environment"))

    def test_guides_open_with_offline_demo(self):
        for name in ("WINDOWS_NOVICE_USABILITY_GUIDE.md", "LINUX_NOVICE_USABILITY_GUIDE.md"):
            text = (ROOT / "docs" / "guides" / name).read_text(encoding="utf-8")
            self.assertIn("--self-check", text)


class TestAuthorizedSourceAddressesClarity(unittest.TestCase):
    def test_active_run_with_source_addresses_fails_closed_with_guidance(self):
        eng = Engagement(
            configured=True,
            cloud="AWS",
            authorized_accounts=["123456789012"],
            authorized_regions=["us-east-1"],
            authorized_source_addresses=["203.0.113.10"],
            active_validation_approved=True,
        )
        allowed, reason = eng.authorize_scope("AWS", ["us-east-1"], "123456789012", active=True)
        self.assertFalse(allowed)
        self.assertIn("source", reason.lower())
        self.assertIn("externally", reason.lower())

    def test_readme_documents_the_field(self):
        self.assertIn("authorizedSourceAddresses", README)
        self.assertIn("fails closed", README)


if __name__ == "__main__":
    unittest.main()
