"""Engagement-gated non-destructive active validation primitive (OFF-FEAT-009)."""

import tempfile
import unittest

from csaf.clouds.base import AssessmentModule
from csaf.engagement import Engagement
from tests.fakes import make_control, make_ctx


class DemoActiveModule(AssessmentModule):
    name = "demo-active"

    def check_simulate(self, control, ctx):
        # A stand-in for a read-only iam:SimulatePrincipalPolicy-style evaluation.
        return self.active_validation(control, ctx, self._simulate)

    def _simulate(self, control, ctx):
        # Pretend the read-only simulation found the principal *could* do the action.
        return self.result(control, ctx, "Fail", "Simulation shows the principal is over-privileged.")

    def check_boom(self, control, ctx):
        return self.active_validation(control, ctx, self._explode)

    def _explode(self, control, ctx):
        raise RuntimeError("simulate call failed")


class TestActiveValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = DemoActiveModule()

    def _ctx(self, profile, approved):
        eng = Engagement(active_validation_approved=approved, configured=True)
        return make_ctx(self.tmp.name, profile=profile, engagement=eng)

    def test_non_active_profile_is_not_applicable(self):
        ctx = self._ctx("Assessment", approved=True)
        result = self.module.check_simulate(make_control(check="check_simulate"), ctx)
        self.assertEqual(result.status, "NotApplicable")
        self.assertIn("only under the Validation", result.observed_value)

    def test_active_profile_without_approval_is_not_tested(self):
        ctx = self._ctx("Validation", approved=False)
        result = self.module.check_simulate(make_control(check="check_simulate"), ctx)
        self.assertEqual(result.status, "NotTested")
        self.assertIn("not approved", result.observed_value)

    def test_approved_active_profile_runs_check(self):
        ctx = self._ctx("Validation", approved=True)
        result = self.module.check_simulate(make_control(check="check_simulate"), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertIn("over-privileged", result.observed_value)

    def test_adversary_simulation_profile_also_runs(self):
        ctx = self._ctx("AdversarySimulation", approved=True)
        result = self.module.check_simulate(make_control(check="check_simulate"), ctx)
        self.assertEqual(result.status, "Fail")

    def test_error_in_active_check_becomes_error_not_pass(self):
        ctx = self._ctx("Validation", approved=True)
        result = self.module.check_boom(make_control(check="check_boom"), ctx)
        self.assertEqual(result.status, "Error")
        self.assertIn("active validation error", result.error_reason)

    def test_dispatch_through_evaluate(self):
        # Full dispatch path: evaluate() -> check method -> active_validation.
        ctx = self._ctx("Validation", approved=True)
        results = self.module.evaluate(make_control(check="check_simulate"), ctx)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "Fail")


if __name__ == "__main__":
    unittest.main()
