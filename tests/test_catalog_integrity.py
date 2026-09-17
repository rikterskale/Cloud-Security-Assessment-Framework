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

    def test_aws_cis_ids_match_foundations_v5(self):
        """Guard the Security Hub CIS AWS Foundations v5.0.0 recommendation numbers."""
        expected = {
            "CSAF-AWS-IAM-001": {"CIS-AWS:1.4"},
            "CSAF-AWS-IAM-002": {"CIS-AWS:1.3"},
            "CSAF-AWS-IAM-003": {"CIS-AWS:1.6"},
            "CSAF-AWS-IAM-004": {"CIS-AWS:1.7", "CIS-AWS:1.8"},
            "CSAF-AWS-IAM-005": {"CIS-AWS:1.9"},
            "CSAF-AWS-IAM-006": {"CIS-AWS:1.13"},
            "CSAF-AWS-IAM-007": {"CIS-AWS:1.11"},
            "CSAF-AWS-IAM-008": set(),
            "CSAF-AWS-IAM-009": {"CIS-AWS:1.19"},
            "CSAF-AWS-S3-001": {"CIS-AWS:2.1.4"},
            "CSAF-AWS-S3-002": {"CIS-AWS:2.1.4"},
            "CSAF-AWS-S3-003": set(),
            "CSAF-AWS-S3-004": {"CIS-AWS:2.1.1"},
            "CSAF-AWS-EC2-001": {"CIS-AWS:5.7"},
            "CSAF-AWS-EC2-002": {"CIS-AWS:5.1.1"},
            "CSAF-AWS-EC2-004": set(),
            "CSAF-AWS-NET-001": {"CIS-AWS:5.3", "CIS-AWS:5.4"},
            "CSAF-AWS-NET-002": {"CIS-AWS:5.5"},
            "CSAF-AWS-NET-003": {"CIS-AWS:3.7"},
            "CSAF-AWS-LOG-001": {"CIS-AWS:3.1"},
            "CSAF-AWS-LOG-002": {"CIS-AWS:3.2"},
            "CSAF-AWS-LOG-003": {"CIS-AWS:3.5"},
            "CSAF-AWS-LOG-004": {"CIS-AWS:3.3"},
            "CSAF-AWS-LOG-006": set(),
            "CSAF-AWS-KMS-001": {"CIS-AWS:3.6"},
            "CSAF-AWS-RDS-001": {"CIS-AWS:2.2.1"},
            "CSAF-AWS-RDS-002": {"CIS-AWS:2.2.3"},
            "CSAF-AWS-SEC-001": set(),
        }
        catalog = Catalog.load(CONTROLS_DIR / "control-catalog.json")
        by_id = {control.id: control for control in catalog.controls}
        for control_id, cis_ids in expected.items():
            mappings = {m for m in by_id[control_id].mappings if m.startswith("CIS-AWS:")}
            self.assertEqual(mappings, cis_ids, control_id)

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
