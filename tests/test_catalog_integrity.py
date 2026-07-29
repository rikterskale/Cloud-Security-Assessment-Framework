"""Every catalog control must map to a real module and an implemented check."""

import unittest
from pathlib import Path

from csaf.catalog import Catalog
from csaf.clouds.aws.modules import MODULE_REGISTRY

CATALOG = Path(__file__).resolve().parent.parent / "controls" / "control-catalog.json"


class TestCatalogIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = Catalog.load(CATALOG)

    def test_every_control_has_an_implementation(self):
        for control in self.catalog.controls:
            if control.module == "attestation":
                continue
            self.assertIn(control.module, MODULE_REGISTRY, f"{control.id} references unknown module {control.module}")
            module = MODULE_REGISTRY[control.module]()
            self.assertTrue(
                hasattr(module, control.check) and callable(getattr(module, control.check)),
                f"{control.id} references missing check {control.module}.{control.check}",
            )

    def test_every_control_has_remediation(self):
        from csaf.remediation import REMEDIATION

        for control in self.catalog.controls:
            self.assertIn(control.id, REMEDIATION, f"{control.id} has no remediation entry")


if __name__ == "__main__":
    unittest.main()
