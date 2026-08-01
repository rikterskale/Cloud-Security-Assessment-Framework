"""Purple-team detection-coverage pack (OFF-FEAT-003).

CSAF already rolls control results up to per-MITRE-technique detection coverage
(:mod:`csaf.detection_coverage`). This module turns that into a **purple-team
pack**: a summary of covered/gap/unknown techniques plus, optionally,
*benign validation markers* — data-source-oriented hints a detection engineer
can use to confirm their pipeline would alert on the weaknesses CSAF found.

Safety: the markers are deliberately **non-executable and non-offensive**. They
name the authorized, defender-visible log source to check (e.g. CloudTrail) and
point back at the failing control; they never contain attack commands, exploit
steps, or evasion guidance. This keeps the feature inside CSAF's read-only,
defensive scope.

Exposed as ``csaf-detection-pack``; it reads a completed run's
``detection-coverage.json`` (and ``manifest.json`` for cloud context).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Authorized, defender-visible audit-log source per cloud (where to look to
# confirm detection). Purely informational; no attack guidance.
_DATA_SOURCE = {
    "AWS": "AWS CloudTrail (management + relevant data events)",
    "Azure": "Azure Monitor / Activity Log and resource diagnostic logs",
    "GCP": "GCP Cloud Audit Logs (Admin Activity / Data Access)",
    "K8s": "Kubernetes API server audit log",
}


def _benign_marker(row: dict, cloud: str) -> dict:
    """A safe, non-executable validation hint for one technique row."""
    gap = row.get("Status") == "Gap"
    controls = row.get("GapControlIds") or row.get("ControlIds") or []
    return {
        "technique": row.get("Technique", ""),
        "priority": "high" if gap else "informational",
        "dataSource": _DATA_SOURCE.get(cloud, "the cloud's authorized audit log"),
        "benignValidation": (
            "In an authorized lab, confirm your detection pipeline raises an alert for the control(s) "
            f"{controls} using benign, approved test activity; verify the event appears in the data source above. "
            "Use only benign, approved test activity; never run intrusive tooling in production."
        ),
        "relatedControls": controls,
    }


def build_detection_pack(detection_rows: list[dict], cloud: str = "", *, include_markers: bool = True) -> dict:
    """Build the purple-team pack from detection-coverage rows."""
    summary = {"Covered": 0, "Gap": 0, "Unknown": 0}
    techniques = []
    for row in detection_rows:
        status = row.get("Status", "Unknown")
        if status in summary:
            summary[status] += 1
        entry = dict(row)
        if include_markers:
            entry["purpleTeamMarker"] = _benign_marker(row, cloud)
        techniques.append(entry)
    return {
        "cloud": cloud,
        "techniqueCount": len(detection_rows),
        "summary": summary,
        "gapTechniques": sorted(r.get("Technique", "") for r in detection_rows if r.get("Status") == "Gap"),
        "techniques": techniques,
        "note": "Benign, defender-focused validation aid. Contains no attack commands or intrusive guidance.",
    }


def build_pack_from_run(run_dir: str | Path, *, include_markers: bool = True) -> dict:
    run_dir = Path(run_dir)
    coverage_path = run_dir / "detection-coverage.json"
    if not coverage_path.is_file():
        raise FileNotFoundError(f"{run_dir} has no detection-coverage.json")
    rows = json.loads(coverage_path.read_text(encoding="utf-8"))
    cloud = ""
    manifest_path = run_dir / "manifest.json"
    if manifest_path.is_file():
        cloud = json.loads(manifest_path.read_text(encoding="utf-8")).get("Cloud", "")
    return build_detection_pack(rows, cloud, include_markers=include_markers)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a purple-team detection-coverage pack from a completed CSAF run."
    )
    parser.add_argument("run_dir", help="A completed assessment run directory (with detection-coverage.json).")
    parser.add_argument("--out", default=None, help="Path to write detection-pack.json (default: inside run_dir).")
    parser.add_argument("--no-markers", action="store_true", help="Omit benign validation markers.")
    args = parser.parse_args(argv)

    pack = build_pack_from_run(args.run_dir, include_markers=not args.no_markers)
    out = Path(args.out) if args.out else Path(args.run_dir) / "detection-pack.json"
    out.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
    print(
        f"Detection pack: {pack['summary']['Covered']} covered, {pack['summary']['Gap']} gap, "
        f"{pack['summary']['Unknown']} unknown across {pack['techniqueCount']} technique(s)."
    )
    print(f"[*] Wrote {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
