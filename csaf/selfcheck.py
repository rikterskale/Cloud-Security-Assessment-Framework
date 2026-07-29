"""Offline self-check provider.

Synthesises a deterministic set of control results without contacting any cloud
so the full evaluation, coverage, and reporting pipeline can be exercised in CI
and demonstrated without cloud credentials. It never makes network calls.
"""

from __future__ import annotations

from .catalog import Control
from .model import ControlResult

# A deterministic demo posture per cloud: a handful of representative weaknesses.
_DEMO_STATUS = {
    "AWS": {
        "CSAF-AWS-IAM-001": ("Fail", "root mfa_active=False"),
        "CSAF-AWS-IAM-005": ("Fail", "console user without MFA: alice"),
        "CSAF-AWS-S3-002": ("Fail", "public-assets: policy public"),
        "CSAF-AWS-NET-001": ("Fail", "sg-0abc opens ports [22] to 0.0.0.0/0"),
        "CSAF-AWS-LOG-001": ("Fail", "active multi-region trails=0"),
        "CSAF-AWS-IAM-010": ("Review", "deployer-policy grants iam:PassRole"),
        "CSAF-AWS-OPS-001": ("NotTested", "No operator attestation supplied."),
    },
    "Azure": {
        "CSAF-AZ-IAM-001": ("Fail", "custom role grants Actions:* at subscription scope: sub-admin"),
        "CSAF-AZ-STO-002": ("Fail", "blob public access is not disabled: publicweb"),
        "CSAF-AZ-NET-001": ("Fail", "nsg-web/allow-rdp allows internet ingress to ports [3389]"),
        "CSAF-AZ-SQL-002": ("Fail", "public network access enabled: sql-prod"),
        "CSAF-AZ-IAM-002": ("Review", "5 Owner assignment(s) at subscription scope (threshold 3)."),
        "CSAF-AZ-OPS-001": ("NotTested", "No operator attestation supplied."),
    },
    "GCP": {
        "CSAF-GCP-IAM-002": ("Fail", "deployer@demo.iam.gserviceaccount.com has 2 user-managed key(s)"),
        "CSAF-GCP-STO-001": ("Fail", "public-assets grants roles/storage.objectViewer to ['allUsers']"),
        "CSAF-GCP-NET-002": ("Fail", "allow-ssh allows 0.0.0.0/0 ingress to ports [22]"),
        "CSAF-GCP-LOG-001": ("Fail", "No allServices audit configuration on the project IAM policy."),
        "CSAF-GCP-IAM-004": ("Review", "user:dev@example.com holds basic role roles/editor"),
        "CSAF-GCP-OPS-001": ("NotTested", "No operator attestation supplied."),
    },
}

_DEMO_ACCOUNT = {
    "AWS": "000000000000",
    "Azure": "00000000-0000-0000-0000-000000000000",
    "GCP": "csaf-selfcheck-project",
}


class SelfCheckProvider:
    def __init__(self, cloud: str = "AWS"):
        self.cloud = cloud
        self.account_id = _DEMO_ACCOUNT.get(cloud, "000000000000")
        self._demo = _DEMO_STATUS.get(cloud, {})

    def evaluate(self, controls: list[Control], regions: list[str]) -> list[ControlResult]:
        results = []
        for control in controls:
            status, observed = self._demo.get(control.id, ("Pass", "Meets expected state (synthetic)."))
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
                    cloud=self.cloud,
                    account_id=self.account_id,
                    region="global",
                    observed_value=observed,
                    expected_value=control.expected_state,
                    mappings=control.mappings,
                )
            )
        return results
