"""Base assessment-module abstraction shared across clouds.

A module owns a set of check functions. The runner dispatches each selected
control to the method named by ``control.check``. Any exception raised by a
check is converted into a single ``Error`` control result, so an execution
failure is recorded as an execution failure and never as a security pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..model import ControlResult

if TYPE_CHECKING:  # pragma: no cover
    from ..baseline import Baseline
    from ..catalog import Control
    from ..engagement import Engagement
    from ..evidence import EvidenceStore
    from ..logging_ import AssessmentLogger


@dataclass
class CheckContext:
    cloud: str
    account_id: str
    region: str
    profile: str
    baseline: "Baseline"
    evidence: "EvidenceStore"
    logger: "AssessmentLogger"
    engagement: "Engagement"
    session: object = None
    cache: dict = field(default_factory=dict)


def attestation_results(controls, engagement, cloud: str, account_id: str) -> list[ControlResult]:
    """Resolve manual attestation controls from the engagement file.

    Shared by every cloud provider: an attestation control is answered by an
    operator-supplied record in the engagement, never by an API call.
    """
    out = []
    attest = engagement.attestations
    for control in controls:
        record = attest.get(control.id)
        if record:
            status = record.get("status", "Review")
            observed = record.get("evidence", "Operator attestation provided.")
        else:
            status = "NotTested"
            observed = "No operator attestation supplied for this manual control."
        severity = "INFO" if status in ("Pass", "NotApplicable", "NotTested") else control.default_severity
        out.append(
            ControlResult(
                control_id=control.id,
                title=control.title,
                category=control.category,
                status=status
                if status in ("Pass", "Fail", "Review", "NotApplicable", "NotTested", "Error")
                else "Review",
                severity=severity,
                confidence="LOW",
                cloud=cloud,
                account_id=account_id,
                observed_value=observed,
                expected_value=control.expected_state,
                mappings=control.mappings,
            )
        )
    return out


class AssessmentModule:
    """Subclasses implement check methods named to match catalog ``check`` keys."""

    name: str = "base"

    def evaluate(self, control: "Control", ctx: CheckContext) -> list[ControlResult]:
        method = getattr(self, control.check, None)
        if method is None or not callable(method):
            return [
                self.error(
                    control,
                    ctx,
                    f"No check implementation '{control.check}' in module '{self.name}'.",
                )
            ]
        try:
            outcome = method(control, ctx)
        except Exception as exc:  # noqa: BLE001 - errors become Error results, never passes
            ctx.logger.error(self.name, f"{control.id} raised {type(exc).__name__}: {exc}", controlId=control.id)
            return [self.error(control, ctx, f"{type(exc).__name__}: {exc}")]
        if outcome is None:
            return []
        if isinstance(outcome, ControlResult):
            return [outcome]
        return list(outcome)

    # --- Result helpers ----------------------------------------------------

    def _base_kwargs(self, control: "Control", ctx: CheckContext) -> dict:
        return {
            "control_id": control.id,
            "title": control.title,
            "category": control.category,
            "cloud": ctx.cloud,
            "account_id": ctx.account_id,
            "region": ctx.region,
            "expected_value": control.expected_state,
            "mappings": control.mappings,
        }

    def result(
        self,
        control: "Control",
        ctx: CheckContext,
        status: str,
        observed: str,
        severity: str | None = None,
        confidence: str = "HIGH",
        resource_type: str = "",
        resource_id: str = "",
        evidence_ref: str = "",
    ) -> ControlResult:
        sev = ctx.baseline.severity_for(control.id, severity or control.default_severity)
        # Pass/NotApplicable results are informational for severity purposes.
        if status in ("Pass", "NotApplicable", "NotTested"):
            sev = "INFO"
        return ControlResult(
            status=status,
            severity=sev,
            confidence=confidence,
            observed_value=observed,
            resource_type=resource_type,
            resource_id=resource_id,
            evidence_ref=evidence_ref,
            **self._base_kwargs(control, ctx),
        )

    def error(self, control: "Control", ctx: CheckContext, reason: str) -> ControlResult:
        kwargs = self._base_kwargs(control, ctx)
        return ControlResult(
            status="Error",
            severity="INFO",
            confidence="LOW",
            observed_value="Check did not complete.",
            error_reason=reason,
            **kwargs,
        )
