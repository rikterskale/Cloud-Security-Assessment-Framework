"""Coverage accounting and risk scoring.

Coverage is tracked independently of findings so that an empty findings list is
never mistaken for a clean, fully-executed assessment. ``NotTested`` and
``Error`` are never security passes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import EXECUTED_STATES, SEVERITY_SCORES, ControlResult


@dataclass
class Coverage:
    selected: int
    executed: int
    passed: int
    failed: int
    review: int
    not_applicable: int
    not_tested: int
    error: int

    @property
    def executed_ratio(self) -> float:
        return round(self.executed / self.selected, 3) if self.selected else 0.0

    @property
    def all_selected_executed(self) -> bool:
        return self.not_tested == 0 and self.error == 0

    def to_dict(self) -> dict:
        return {
            "CoverageSchemaVersion": "1.0",
            "SelectedControls": self.selected,
            "Executed": self.executed,
            "ExecutedRatio": self.executed_ratio,
            "Pass": self.passed,
            "Fail": self.failed,
            "Review": self.review,
            "NotApplicable": self.not_applicable,
            "NotTested": self.not_tested,
            "Error": self.error,
            "AllSelectedControlsExecuted": self.all_selected_executed,
        }


def compute_coverage(selected_control_ids: set[str], results: list[ControlResult]) -> Coverage:
    """Compute coverage against the set of selected control IDs.

    Any selected control with no result is counted as NotTested. A control may
    produce many results (per resource or per region); the rolled-up status is
    the highest-ranked one: an Error anywhere dominates, because coverage tracks
    execution completeness and a partially-errored control did not fully
    execute. Findings are derived from the raw per-result statuses, so a Fail in
    one region still produces a finding even if another region errored.
    """
    status_by_control: dict[str, str] = {}
    for result in results:
        current = status_by_control.get(result.control_id)
        if current is None or _rank(result.status) > _rank(current):
            status_by_control[result.control_id] = result.status

    for control_id in selected_control_ids:
        status_by_control.setdefault(control_id, "NotTested")

    counts = {s: 0 for s in ["Pass", "Fail", "Review", "NotApplicable", "NotTested", "Error"]}
    for status in status_by_control.values():
        counts[status] += 1

    executed = sum(counts[s] for s in EXECUTED_STATES)
    return Coverage(
        selected=len(selected_control_ids),
        executed=executed,
        passed=counts["Pass"],
        failed=counts["Fail"],
        review=counts["Review"],
        not_applicable=counts["NotApplicable"],
        not_tested=counts["NotTested"],
        error=counts["Error"],
    )


# Rollup dominance for multi-result controls. Error ranks highest so partial
# execution failures always surface in coverage and the exit code; Fail/Review
# outrank Pass so a weakness anywhere is never averaged away.
_STATUS_RANK = {"NotTested": 0, "NotApplicable": 1, "Pass": 2, "Review": 3, "Fail": 4, "Error": 5}


def _rank(status: str) -> int:
    return _STATUS_RANK.get(status, 0)


def compute_risk_score(results: list[ControlResult]) -> dict:
    """Weighted risk score in 0-100 based on failed/review controls by severity."""
    severity_counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for result in results:
        if result.is_finding:
            severity_counts[result.severity] += 1

    weighted = sum(severity_counts[s] * SEVERITY_SCORES[s] for s in severity_counts)
    # Normalise against a saturating denominator so a handful of criticals is
    # already a high score without requiring hundreds of findings.
    normalised = round(min(100.0, weighted / 2.0), 1)

    if normalised >= 70:
        rating = "CRITICAL"
    elif normalised >= 45:
        rating = "HIGH"
    elif normalised >= 20:
        rating = "MEDIUM"
    elif normalised > 0:
        rating = "LOW"
    else:
        rating = "MINIMAL"

    return {
        "severity_counts": severity_counts,
        "weighted_score": weighted,
        "normalised_score": normalised,
        "rating": rating,
    }
