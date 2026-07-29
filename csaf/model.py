"""Core data model: statuses, severities, control results, and findings.

Central design invariants (mirrored from the AD assessment framework):

* Every selected control receives exactly one control-result status.
* ``NotTested`` and ``Error`` are never treated as a security pass and never
  produce a finding. Execution errors are tracked separately from security
  weaknesses.
* Findings are a strict subset of control results derived only from ``Fail``
  and ``Review`` states.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import SCHEMA_VERSION

# --- Controlled vocabularies ------------------------------------------------

CONTROL_STATUSES = ["Pass", "Fail", "Review", "NotApplicable", "NotTested", "Error"]
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
FINDING_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCES = ["LOW", "MEDIUM", "HIGH"]

# Severity contribution to the weighted risk score.
SEVERITY_SCORES = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}

# Risk score assigned to an individual finding (0-100).
FINDING_RISK_SCORE = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25}

# States that represent a security weakness and therefore produce a finding.
FINDING_STATES = {"Fail", "Review"}

# States that count as an executed check for coverage purposes.
EXECUTED_STATES = {"Pass", "Fail", "Review", "NotApplicable"}


def utcnow_iso() -> str:
    """Return an ISO-8601 UTC timestamp with a trailing Z."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class ControlResult:
    """One evaluated control for one account/region scope."""

    control_id: str
    title: str
    category: str
    status: str
    severity: str = "INFO"
    confidence: str = "MEDIUM"
    cloud: str = "AWS"
    account_id: str = ""
    region: str = ""
    resource_type: str = ""
    resource_id: str = ""
    observed_value: str = ""
    expected_value: str = ""
    mappings: list[str] = field(default_factory=list)
    evidence_ref: str = ""
    error_reason: str = ""
    collected_at_utc: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if self.status not in CONTROL_STATUSES:
            raise ValueError(f"Invalid control status: {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"Invalid confidence: {self.confidence!r}")

    @property
    def is_finding(self) -> bool:
        return self.status in FINDING_STATES

    @property
    def is_executed(self) -> bool:
        return self.status in EXECUTED_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "SchemaVersion": SCHEMA_VERSION,
            "ControlId": self.control_id,
            "Title": self.title,
            "Category": self.category,
            "Status": self.status,
            "Severity": self.severity,
            "Confidence": self.confidence,
            "Cloud": self.cloud,
            "AccountId": self.account_id,
            "Region": self.region,
            "ResourceType": self.resource_type,
            "ResourceId": self.resource_id,
            "ObservedValue": self.observed_value,
            "ExpectedValue": self.expected_value,
            "Mappings": self.mappings,
            "EvidenceRef": self.evidence_ref,
            "ErrorReason": self.error_reason,
            "CollectedAtUtc": self.collected_at_utc,
        }


def finding_id(result: ControlResult) -> str:
    """Deterministic, object-aware finding identifier.

    Stable across runs for the same control + resource so that deltas and
    retests can correlate findings.
    """
    seed = f"{result.cloud}|{result.account_id}|{result.region}|{result.control_id}|{result.resource_id}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
    return f"F-{digest}"


@dataclass
class Finding:
    """A prioritized security finding derived from a Fail/Review control result."""

    finding_id: str
    control_id: str
    title: str
    severity: str
    risk_score: int
    confidence: str
    cloud: str
    account_id: str
    finding: str
    remediation: str
    status: str = "Open"
    region: str = ""
    resource_type: str = ""
    resource_id: str = ""
    observed_value: str = ""
    expected_value: str = ""
    mappings: list[str] = field(default_factory=list)
    evidence_ref: str = ""
    first_observed_utc: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "SchemaVersion": SCHEMA_VERSION,
            "FindingId": self.finding_id,
            "ControlId": self.control_id,
            "Title": self.title,
            "Status": self.status,
            "Severity": self.severity,
            "RiskScore": self.risk_score,
            "Confidence": self.confidence,
            "Cloud": self.cloud,
            "AccountId": self.account_id,
            "Region": self.region,
            "ResourceType": self.resource_type,
            "ResourceId": self.resource_id,
            "ObservedValue": self.observed_value,
            "ExpectedValue": self.expected_value,
            "Finding": self.finding,
            "Remediation": self.remediation,
            "Mappings": self.mappings,
            "EvidenceRef": self.evidence_ref,
            "FirstObservedUtc": self.first_observed_utc,
        }


def finding_from_result(result: ControlResult, remediation: str) -> Finding:
    """Build a Finding from a Fail/Review ControlResult.

    Review results are normalised to MEDIUM at minimum because the weakness is
    unconfirmed but not dismissible.
    """
    severity = result.severity if result.severity in FINDING_RISK_SCORE else "MEDIUM"
    verb = "does not meet" if result.status == "Fail" else "requires manual review against"
    return Finding(
        finding_id=finding_id(result),
        control_id=result.control_id,
        title=result.title,
        severity=severity,
        risk_score=FINDING_RISK_SCORE[severity],
        confidence=result.confidence,
        cloud=result.cloud,
        account_id=result.account_id,
        region=result.region,
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        observed_value=result.observed_value,
        expected_value=result.expected_value,
        finding=f"{result.title}: the assessed state {verb} the expected state.",
        remediation=remediation,
        mappings=result.mappings,
        evidence_ref=result.evidence_ref,
    )
