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

from .model import Finding

NEW = "New"
PERSISTED = "Persisted"


@dataclass
class FindingDelta:
    """Per-finding New/Persisted status for the current run, plus resolved records."""

    statuses: dict[str, str] = field(default_factory=dict)
    resolved: list[dict] = field(default_factory=list)

    def status_for(self, finding_id: str) -> str:
        return self.statuses.get(finding_id, NEW)

    def to_summary(self) -> dict:
        return {
            "new": sum(1 for s in self.statuses.values() if s == NEW),
            "persisted": sum(1 for s in self.statuses.values() if s == PERSISTED),
            "resolved": len(self.resolved),
        }


def load_previous_findings(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def compute_delta(current: list[Finding], previous_path: str | Path | None) -> FindingDelta | None:
    """Return ``None`` when no previous findings were supplied (delta is opt-in)."""
    if not previous_path:
        return None
    previous = load_previous_findings(previous_path)
    previous_ids = {record["FindingId"] for record in previous}
    current_ids = {f.finding_id for f in current}
    statuses = {fid: (PERSISTED if fid in previous_ids else NEW) for fid in current_ids}
    resolved = [record for record in previous if record["FindingId"] not in current_ids]
    return FindingDelta(statuses=statuses, resolved=resolved)
