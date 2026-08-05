"""Multi-account / org-wide aggregation and cross-account analysis (OFF-FEAT-005).

Assessors typically run CSAF once per account, subscription, project, or
cluster. This module rolls several completed run directories into one view:

* a per-scope summary (cloud, account, profile, finding counts by severity),
* a combined findings list tagged with the originating scope, and
* a **cross-scope** roll-up of the same control failing in more than one scope,
  which is what an org-wide reviewer most wants to see (systemic weaknesses).

It reads only artifacts CSAF already wrote (``manifest.json`` for identity and
``findings.json`` for findings), so it performs no cloud calls. Exposed as
``csaf-aggregate``.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .console import next_steps
from .model import FINDING_SEVERITIES


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _scope_label(manifest: dict) -> str:
    return f"{manifest.get('Cloud', '?')}:{manifest.get('AccountScope', '?')}"


def aggregate_runs(run_dirs: list[str | Path]) -> dict:
    """Aggregate several completed run directories into one report."""
    scopes = []
    combined: list[dict] = []
    by_control: dict[str, set[str]] = {}
    control_titles: dict[str, str] = {}

    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        manifest_path = run_dir / "manifest.json"
        findings_path = run_dir / "findings.json"
        if not manifest_path.is_file() or not findings_path.is_file():
            raise FileNotFoundError(f"{run_dir} is missing manifest.json or findings.json")
        manifest = _read_json(manifest_path)
        findings = _read_json(findings_path)
        scope = _scope_label(manifest)

        severity_counts = {sev: 0 for sev in FINDING_SEVERITIES}
        for finding in findings:
            sev = finding.get("Severity", "")
            if sev in severity_counts:
                severity_counts[sev] += 1
            tagged = dict(finding)
            tagged["Scope"] = scope
            combined.append(tagged)
            control = finding.get("ControlId", "")
            by_control.setdefault(control, set()).add(scope)
            control_titles.setdefault(control, finding.get("Title", ""))

        scopes.append(
            {
                "scope": scope,
                "cloud": manifest.get("Cloud", ""),
                "account": manifest.get("AccountScope", ""),
                "profile": manifest.get("AssessmentProfile", ""),
                "runId": manifest.get("runId", run_dir.name),
                "findingCount": len(findings),
                "severityCounts": severity_counts,
            }
        )

    cross_scope = [
        {
            "controlId": control,
            "title": control_titles.get(control, ""),
            "scopes": sorted(scopes_set),
            "scopeCount": len(scopes_set),
        }
        for control, scopes_set in by_control.items()
        if len(scopes_set) > 1
    ]
    cross_scope.sort(key=lambda item: (-item["scopeCount"], item["controlId"]))

    totals = {sev: sum(s["severityCounts"][sev] for s in scopes) for sev in FINDING_SEVERITIES}
    return {
        "scopeCount": len(scopes),
        "scopes": scopes,
        "totalFindings": len(combined),
        "severityTotals": totals,
        "crossScopeControls": cross_scope,
        "combinedFindings": combined,
    }


def write_aggregate(aggregate: dict, out_dir: str | Path) -> dict:
    """Write aggregate.json + aggregate.csv (per-scope summary). Returns paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "aggregate.json"
    json_path.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")

    csv_path = out_dir / "aggregate.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Scope", "Cloud", "Account", "Profile", "Findings", *FINDING_SEVERITIES])
        for scope in aggregate["scopes"]:
            writer.writerow(
                [scope["scope"], scope["cloud"], scope["account"], scope["profile"], scope["findingCount"]]
                + [scope["severityCounts"][sev] for sev in FINDING_SEVERITIES]
            )
    return {"json": str(json_path), "csv": str(csv_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate multiple CSAF run directories into one org-wide report.")
    parser.add_argument("run_dir", nargs="+", help="Completed assessment run directories (each with findings.json).")
    parser.add_argument("--out", required=True, help="Output directory for aggregate.json and aggregate.csv.")
    args = parser.parse_args(argv)

    aggregate = aggregate_runs(args.run_dir)
    paths = write_aggregate(aggregate, args.out)
    print(
        f"Aggregated {aggregate['scopeCount']} scope(s), {aggregate['totalFindings']} findings, "
        f"{len(aggregate['crossScopeControls'])} control(s) failing in multiple scopes."
    )
    print(f"[*] Wrote {paths['json']} and {paths['csv']}")
    print(
        next_steps(
            f"Open {paths['csv']} to prioritize cross-scope controls.",
            "Completed runs were consolidated into an organization-wide summary.",
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
