"""Every catalog control must map to a real module and an implemented check."""

import unittest
from pathlib import Path

from csaf.catalog import Catalog
from csaf.clouds.aws.modules import MODULE_REGISTRY as AWS_REGISTRY
from csaf.clouds.azure.modules import MODULE_REGISTRY as AZURE_REGISTRY
from csaf.clouds.gcp.modules import MODULE_REGISTRY as GCP_REGISTRY
from csaf.clouds.k8s.modules import MODULE_REGISTRY as K8S_REGISTRY

CONTROLS_DIR = Path(__file__).resolve().parent.parent / "controls"

CATALOGS = {
    "control-catalog.json": AWS_REGISTRY,
    "control-catalog-azure.json": AZURE_REGISTRY,
    "control-catalog-gcp.json": GCP_REGISTRY,
    "control-catalog-k8s.json": K8S_REGISTRY,
}


class TestCatalogIntegrity(unittest.TestCase):
    def test_every_control_has_an_implementation(self):
        for filename, registry in CATALOGS.items():
            catalog = Catalog.load(CONTROLS_DIR / filename)
            for control in catalog.controls:
                if control.module == "attestation":
                    continue
                self.assertIn(control.module, registry, f"{control.id} references unknown module {control.module}")
                module = registry[control.module]()
                self.assertTrue(
                    hasattr(module, control.check) and callable(getattr(module, control.check)),
                    f"{control.id} references missing check {control.module}.{control.check}",
                )

    def test_every_control_has_remediation(self):
        from csaf.remediation import REMEDIATION

        for filename in CATALOGS:
            catalog = Catalog.load(CONTROLS_DIR / filename)
            for control in catalog.controls:
                self.assertIn(control.id, REMEDIATION, f"{control.id} has no remediation entry")

    def test_control_ids_are_unique_across_clouds(self):
        seen: dict[str, str] = {}
        for filename in CATALOGS:
            catalog = Catalog.load(CONTROLS_DIR / filename)
            for control in catalog.controls:
                self.assertNotIn(
                    control.id, seen, f"{control.id} appears in both {seen.get(control.id)} and {filename}"
                )
                seen[control.id] = filename


if __name__ == "__main__":
    unittest.main()
