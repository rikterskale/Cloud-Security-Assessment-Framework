"""Offline self-check provider.

Synthesises a deterministic set of control results without contacting any cloud
so the full evaluation, coverage, and reporting pipeline can be exercised in CI
and demonstrated without AWS credentials. It never makes network calls.
"""

from __future__ import annotations

from .catalog import Control
from .model import ControlResult

# A deterministic demo posture: a handful of representative weaknesses.
_DEMO_STATUS = {
    "CSAF-AWS-IAM-001": ("Fail", "root mfa_active=False"),
    "CSAF-AWS-IAM-005": ("Fail", "console user without MFA: alice"),
    "CSAF-AWS-S3-002": ("Fail", "public-assets: policy public"),
    "CSAF-AWS-NET-001": ("Fail", "sg-0abc opens ports [22] to 0.0.0.0/0"),
    "CSAF-AWS-LOG-001": ("Fail", "active multi-region trails=0"),
    "CSAF-AWS-IAM-010": ("Review", "deployer-policy grants iam:PassRole"),
    "CSAF-AWS-OPS-001": ("NotTested", "No operator attestation supplied."),
}


class SelfCheckProvider:
    account_id = "000000000000"

    def evaluate(self, controls: list[Control], regions: list[str]) -> list[ControlResult]:
        results = []
        for control in controls:
            status, observed = _DEMO_STATUS.get(control.id, ("Pass", "Meets expected state (synthetic)."))
            severity = "INFO" if status in ("Pass", "NotApplicable", "NotTested") else control.default_severity
            confidence = "MEDIUM" if status == "Review" else "HIGH"
            results.append(
                ControlResult(
                    control_id=control.id,
                    title=control.title,
                    category=control.category,
                    status=status,
                    severity=severity,
                    confidence=confidence,
                    cloud="AWS",
                    account_id=self.account_id,
                    region="global",
                    observed_value=observed,
                    expected_value=control.expected_state,
                    mappings=control.mappings,
                )
            )
        return results
