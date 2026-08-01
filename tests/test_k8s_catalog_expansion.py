"""Kubernetes catalog expansion + version alignment (roadmap #8 / REV-K8S-008)."""

import json
import unittest

from csaf.resource_paths import read_resource_text


class TestK8sCatalogExpansion(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(read_resource_text("controls", "control-catalog-k8s.json"))
        self.ids = {c["id"] for c in self.catalog["controls"]}

    def test_version_aligned_with_peers(self):
        self.assertEqual(self.catalog["catalogVersion"], "2026.1")

    def test_new_operations_controls_present(self):
        for cid in ("CSAF-K8S-OPS-002", "CSAF-K8S-OPS-003", "CSAF-K8S-OPS-004"):
            self.assertIn(cid, self.ids)

    def test_control_count_grew(self):
        self.assertGreaterEqual(len(self.catalog["controls"]), 8)

    def test_new_controls_have_mappings_and_expected_state(self):
        for control in self.catalog["controls"]:
            if control["id"].startswith("CSAF-K8S-OPS-00") and control["id"] != "CSAF-K8S-OPS-001":
                self.assertTrue(control["mappings"], f"{control['id']} missing mappings")
                self.assertTrue(control["expectedState"], f"{control['id']} missing expectedState")


if __name__ == "__main__":
    unittest.main()
