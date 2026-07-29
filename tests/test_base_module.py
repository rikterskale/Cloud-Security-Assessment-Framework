"""AssessmentModule dispatch: exceptions become Error results, never passes."""

import tempfile
import unittest

from csaf.baseline import Baseline
from csaf.clouds.base import AssessmentModule
from csaf.model import ControlResult
from tests.fakes import make_control, make_ctx


class DemoModule(AssessmentModule):
    name = "demo"

    def raises(self, control, ctx):
        raise RuntimeError("collector exploded")

    def returns_none(self, control, ctx):
        return None

    def returns_single(self, control, ctx):
        return self.result(control, ctx, "Pass", "fine")

    def returns_many(self, control, ctx):
        return [
            self.result(control, ctx, "Fail", "bad-1", resource_id="r1"),
            self.result(control, ctx, "Fail", "bad-2", resource_id="r2"),
        ]

    def fails(self, control, ctx):
        return self.result(control, ctx, "Fail", "weak")


class TestEvaluateDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = DemoModule()

    def ctx(self, **kwargs):
        return make_ctx(self.tmp.name, **kwargs)

    def test_exception_becomes_single_error_result(self):
        results = self.module.evaluate(make_control(check="raises"), self.ctx())
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, "Error")
        self.assertIn("RuntimeError", result.error_reason)
        self.assertIn("collector exploded", result.error_reason)
        self.assertEqual(result.severity, "INFO")
        self.assertFalse(result.is_finding, "an Error must never become a finding")
        self.assertFalse(result.is_executed, "an Error must never count as executed coverage")

    def test_missing_check_name_becomes_error(self):
        results = self.module.evaluate(make_control(check="does_not_exist"), self.ctx())
        self.assertEqual([r.status for r in results], ["Error"])
        self.assertIn("does_not_exist", results[0].error_reason)

    def test_none_outcome_becomes_empty_list(self):
        self.assertEqual(self.module.evaluate(make_control(check="returns_none"), self.ctx()), [])

    def test_single_result_wrapped_in_list(self):
        results = self.module.evaluate(make_control(check="returns_single"), self.ctx())
        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], ControlResult)

    def test_result_list_passed_through(self):
        results = self.module.evaluate(make_control(check="returns_many"), self.ctx())
        self.assertEqual([r.resource_id for r in results], ["r1", "r2"])


class TestResultHelper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = DemoModule()

    def test_pass_results_forced_to_info_severity(self):
        results = self.module.evaluate(
            make_control(check="returns_single", severity="CRITICAL"), make_ctx(self.tmp.name)
        )
        self.assertEqual(results[0].severity, "INFO")

    def test_fail_uses_control_default_severity(self):
        results = self.module.evaluate(make_control(check="fails", severity="CRITICAL"), make_ctx(self.tmp.name))
        self.assertEqual(results[0].severity, "CRITICAL")

    def test_baseline_severity_override_applied(self):
        baseline = Baseline({"severityOverrides": {"CSAF-AWS-TST-001": "LOW"}})
        ctx = make_ctx(self.tmp.name, baseline=baseline)
        results = self.module.evaluate(make_control(check="fails", severity="CRITICAL"), ctx)
        self.assertEqual(results[0].severity, "LOW")

    def test_control_metadata_propagated(self):
        control = make_control(check="fails", mappings=["CIS-AWS:1.4"], expected="hardened")
        results = self.module.evaluate(control, make_ctx(self.tmp.name, region="eu-west-1"))
        result = results[0]
        self.assertEqual(result.control_id, control.id)
        self.assertEqual(result.region, "eu-west-1")
        self.assertEqual(result.expected_value, "hardened")
        self.assertEqual(result.mappings, ["CIS-AWS:1.4"])


if __name__ == "__main__":
    unittest.main()
