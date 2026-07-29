import unittest
from pathlib import Path

from csaf.catalog import Catalog

CATALOG = Path(__file__).resolve().parent.parent / "controls" / "control-catalog.json"


class TestCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = Catalog.load(CATALOG)

    def test_loads_controls(self):
        self.assertGreaterEqual(len(self.catalog.controls), 25)

    def test_control_ids_unique_and_prefixed(self):
        ids = [c.id for c in self.catalog.controls]
        self.assertEqual(len(ids), len(set(ids)))
        for cid in ids:
            self.assertRegex(cid, r"^CSAF-AWS-[A-Z0-9-]+$")

    def test_assessment_excludes_validation_only(self):
        assessment = {c.id for c in self.catalog.for_profile("Assessment")}
        validation = {c.id for c in self.catalog.for_profile("Validation")}
        vo = {c.id for c in self.catalog.controls if c.validation_only}
        self.assertTrue(vo)  # there is at least one validation-only control
        self.assertTrue(vo.isdisjoint(assessment))
        self.assertTrue(vo.issubset(validation))

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            self.catalog.for_profile("Nope")

    def test_adversary_simulation_is_a_strict_mitre_mapped_subset_of_validation(self):
        validation = {c.id for c in self.catalog.for_profile("Validation")}
        adversary = {c.id for c in self.catalog.for_profile("AdversarySimulation")}
        self.assertTrue(adversary)  # the filter must not eliminate every control
        self.assertTrue(adversary.issubset(validation))
        self.assertLess(len(adversary), len(validation))  # must be a real, non-trivial narrowing
        selected = [c for c in self.catalog.controls if c.id in adversary]
        self.assertTrue(all(any(m.startswith("MITRE:") for m in c.mappings) for c in selected))

    def test_adversary_simulation_excludes_non_mitre_mapped_validation_controls(self):
        validation = {c.id for c in self.catalog.for_profile("Validation")}
        adversary = {c.id for c in self.catalog.for_profile("AdversarySimulation")}
        non_mitre_validation_only = {
            c.id
            for c in self.catalog.controls
            if c.id in validation and not any(m.startswith("MITRE:") for m in c.mappings)
        }
        self.assertTrue(non_mitre_validation_only)  # such controls exist in this catalog
        self.assertTrue(non_mitre_validation_only.isdisjoint(adversary))


if __name__ == "__main__":
    unittest.main()
