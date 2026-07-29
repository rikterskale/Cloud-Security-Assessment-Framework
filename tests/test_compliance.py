"""Compliance framework rollup from control mappings."""

import unittest

from csaf.compliance import framework_of, rollup
from csaf.model import ControlResult


def result(cid, status, mappings):
    return ControlResult(
        control_id=cid,
        title="t",
        category="c",
        status=status,
        severity="HIGH" if status in ("Fail", "Review") else "INFO",
        cloud="AWS",
        account_id="1",
        mappings=mappings,
    )


class TestFrameworkOf(unittest.TestCase):
    def test_known_prefixes(self):
        self.assertEqual(framework_of("CIS-AWS:1.5"), "CIS-AWS")
        self.assertEqual(framework_of("NIST-800-53:IA-2"), "NIST-800-53")
        self.assertEqual(framework_of("MITRE:T1078.004"), "MITRE")

    def test_unknown_prefix_returns_none(self):
        self.assertIsNone(framework_of("PCI-DSS:8.3"))
        self.assertIsNone(framework_of("freetext"))


class TestRollup(unittest.TestCase):
    def test_evaluated_passed_failed_counts(self):
        results = [
            result("C1", "Pass", ["CIS-AWS:1.1"]),
            result("C2", "Fail", ["CIS-AWS:1.2"]),
            result("C3", "Review", ["CIS-AWS:1.3"]),
        ]
        summary = rollup(results)
        entry = summary["CIS-AWS"]
        self.assertEqual(entry["evaluated"], 3)
        self.assertEqual(entry["passed"], 1)
        self.assertEqual(entry["failed"], 2)  # Review counts as not-passed
        self.assertEqual(entry["controls"], ["CIS-AWS:1.1", "CIS-AWS:1.2", "CIS-AWS:1.3"])

    def test_error_and_not_tested_do_not_count_as_evaluated(self):
        results = [
            result("C1", "Error", ["CIS-AWS:1.1"]),
            result("C2", "NotTested", ["CIS-AWS:1.2"]),
            result("C3", "NotApplicable", ["CIS-AWS:1.3"]),
        ]
        summary = rollup(results)
        entry = summary["CIS-AWS"]
        self.assertEqual(entry["evaluated"], 0)
        self.assertEqual(entry["passed"], 0)
        self.assertEqual(entry["failed"], 0)
        # The mappings are still tracked so coverage of the framework is visible.
        self.assertEqual(len(entry["controls"]), 3)

    def test_one_result_can_feed_multiple_frameworks(self):
        results = [result("C1", "Fail", ["CIS-AWS:1.4", "NIST-800-53:IA-2", "MITRE:T1078"])]
        summary = rollup(results)
        self.assertEqual(set(summary), {"CIS-AWS", "NIST-800-53", "MITRE"})
        for entry in summary.values():
            self.assertEqual(entry["failed"], 1)

    def test_unknown_prefixes_ignored_and_empty_input_ok(self):
        self.assertEqual(rollup([result("C1", "Fail", ["PCI-DSS:8.3"])]), {})
        self.assertEqual(rollup([]), {})

    def test_summary_is_json_serialisable(self):
        import json

        summary = rollup([result("C1", "Pass", ["CIS-AWS:1.1"])])
        json.dumps(summary)  # raises if the controls set was not converted


if __name__ == "__main__":
    unittest.main()
