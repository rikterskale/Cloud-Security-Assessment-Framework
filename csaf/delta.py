"""Finding delta: compare a run's findings against a prior run's ``findings.json``.

Finding IDs are deterministic and object-aware (see ``model.finding_id``), so
the same weakness on the same resource carries the same ID across runs. This
module is purely opt-in: when no previous findings path is supplied, callers
get ``None`` back and reporting behaves exactly as before.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import EXECUTED_STATES, ControlResult, Finding

NEW = "New"
PERSISTED = "Persisted"


@dataclass
class FindingDelta:
    """Per-finding New/Persisted status for the current run, plus resolved records."""

    statuses: dict[str, str] = field(default_factory=dict)
    resolved: list[dict] = field(default_factory=list)
    unverified: list[dict] = field(default_factory=list)

    def status_for(self, finding_id: str) -> str:
        return self.statuses.get(finding_id, NEW)

    def to_summary(self) -> dict:
        return {
            "new": sum(1 for s in self.statuses.values() if s == NEW),
            "persisted": sum(1 for s in self.statuses.values() if s == PERSISTED),
            "resolved": len(self.resolved),
            "unverified": len(self.unverified),
        }


def load_previous_findings(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def partition_absent(
    previous: list[dict], current_ids: set[str], results: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Require completed evaluation in the same scope before claiming resolution."""
    scopes: dict[tuple, list[str]] = {}
    fields = ("Cloud", "AccountId", "Region", "ControlId")
    for result in results:
        if all(field in result for field in fields):
            key = tuple(result[field] for field in fields)
            scopes.setdefault(key, []).append(result.get("Status", ""))
    resolved, unverified = [], []
    for record in previous:
        if record["FindingId"] in current_ids:
            continue
        statuses = scopes.get(tuple(record.get(field) for field in fields), [])
        confirmed = (
            all(field in record for field in fields) and statuses and all(s in EXECUTED_STATES for s in statuses)
        )
        (resolved if confirmed else unverified).append(record)
    return resolved, unverified


def compute_delta(
    current: list[Finding], previous_path: str | Path | None, *, results: list[ControlResult] | None = None
) -> FindingDelta | None:
    """Return ``None`` when no previous findings were supplied (delta is opt-in)."""
    if not previous_path:
        return None
    previous = load_previous_findings(previous_path)
    previous_ids = {record["FindingId"] for record in previous}
    current_ids = {f.finding_id for f in current}
    statuses = {fid: (PERSISTED if fid in previous_ids else NEW) for fid in current_ids}
    resolved, unverified = partition_absent(previous, current_ids, [result.to_dict() for result in (results or [])])
    return FindingDelta(statuses=statuses, resolved=resolved, unverified=unverified)
