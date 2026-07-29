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


if __name__ == "__main__":
    unittest.main()
