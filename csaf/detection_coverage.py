"""ATT&CK technique detection-coverage rollup.

Every control mapped to a MITRE ATT&CK technique (``mappings`` entries like
``MITRE:T1078.004``) already tells us, from data collected during a normal
run, whether that technique currently has a real gap in this account: this
module rolls per-technique status up from the individual ``ControlResult``
objects already produced, so a report reader can see at a glance which
techniques have a Fail/Review-state gap versus which are fully covered,
without any additional API calls or a second scan.
"""

from __future__ import annotations

from .model import ControlResult

MITRE_PREFIX = "MITRE:"

GAP = "Gap"
COVERED = "Covered"
UNKNOWN = "Unknown"


def _techniques(result: ControlResult) -> list[str]:
    return [m[len(MITRE_PREFIX) :] for m in result.mappings if m.startswith(MITRE_PREFIX)]


def compute_detection_coverage(results: list[ControlResult]) -> list[dict]:
    """Return one row per MITRE technique referenced by any result.

    Status per technique:
    * ``Gap`` — at least one mapped control result is Fail/Review.
    * ``Covered`` — every mapped result is Pass/NotApplicable and at least
      one actually executed.
    * ``Unknown`` — every mapped result is NotTested/Error; there is no
      executed evidence either way for this technique in this run.
    """
    by_technique: dict[str, list[ControlResult]] = {}
    for result in results:
        for technique in _techniques(result):
            by_technique.setdefault(technique, []).append(result)

    rows = []
    for technique in sorted(by_technique):
        mapped = by_technique[technique]
        if any(r.is_finding for r in mapped):
            status = GAP
        elif any(r.is_executed for r in mapped):
            status = COVERED
        else:
            status = UNKNOWN
        rows.append(
            {
                "Technique": technique,
                "Status": status,
                "ControlIds": sorted({r.control_id for r in mapped}),
                "GapControlIds": sorted({r.control_id for r in mapped if r.is_finding}),
            }
        )
    return rows
