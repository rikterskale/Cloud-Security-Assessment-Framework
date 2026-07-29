"""Report generation: JSON, JSONL, CSV, and an executive HTML rollup."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from . import FRAMEWORK_VERSION
from .coverage import Coverage
from .model import ControlResult, Finding, utcnow_iso

REMEDIATION_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def write_control_results(results: list[ControlResult], out_dir: Path) -> None:
    jsonl_path = out_dir / "control-results.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result.to_dict()) + "\n")

    csv_path = out_dir / "control-results.csv"
    fields = [
        "ControlId",
        "Title",
        "Category",
        "Status",
        "Severity",
        "Confidence",
        "Cloud",
        "AccountId",
        "Region",
        "ResourceType",
        "ResourceId",
        "ObservedValue",
        "ExpectedValue",
        "ErrorReason",
        "CollectedAtUtc",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_dict())


def write_findings(findings: list[Finding], out_dir: Path, delta=None) -> None:
    """Write findings.json/csv. When ``delta`` (a ``FindingDelta``) is given,
    each row also carries a ``DeltaStatus`` (New/Persisted) and
    ``findings-resolved.json`` is written with findings absent from this run.
    """
    ordered = sorted(findings, key=lambda f: (REMEDIATION_ORDER.get(f.severity, 9), f.control_id))

    def row(finding: Finding) -> dict:
        data = finding.to_dict()
        if delta is not None:
            data["DeltaStatus"] = delta.status_for(finding.finding_id)
        return data

    json_path = out_dir / "findings.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump([row(f) for f in ordered], handle, indent=2)

    csv_path = out_dir / "findings.csv"
    fields = [
        "FindingId",
        "ControlId",
        "Title",
        "Status",
        "Severity",
        "RiskScore",
        "Confidence",
        "Cloud",
        "AccountId",
        "Region",
        "ResourceType",
        "ResourceId",
        "ObservedValue",
        "ExpectedValue",
        "Finding",
        "Remediation",
        "FirstObservedUtc",
    ]
    if delta is not None:
        fields.append("DeltaStatus")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in ordered:
            writer.writerow(row(finding))

    if delta is not None:
        with open(out_dir / "findings-resolved.json", "w", encoding="utf-8") as handle:
            json.dump(delta.resolved, handle, indent=2)


def write_coverage(coverage: Coverage, not_tested_ids: list[str], out_dir: Path) -> None:
    payload = coverage.to_dict()
    payload["NotTestedControls"] = sorted(not_tested_ids)
    with open(out_dir / "coverage-report.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    with open(out_dir / "coverage-report.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Metric", "Value"])
        for key, value in coverage.to_dict().items():
            writer.writerow([key, value])


def write_remediation_roadmap(findings: list[Finding], out_dir: Path) -> None:
    ordered = sorted(findings, key=lambda f: (REMEDIATION_ORDER.get(f.severity, 9), -f.risk_score))
    horizon = {"CRITICAL": "0-24h", "HIGH": "1-7d", "MEDIUM": "1-4w", "LOW": "1-3m"}
    with open(out_dir / "remediation-roadmap.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Priority", "Horizon", "Severity", "ControlId", "Title", "ResourceId", "Remediation"])
        for i, finding in enumerate(ordered, 1):
            writer.writerow(
                [
                    i,
                    horizon.get(finding.severity, "1-3m"),
                    finding.severity,
                    finding.control_id,
                    finding.title,
                    finding.resource_id,
                    finding.remediation,
                ]
            )


def write_detection_coverage(rows: list[dict], out_dir: Path) -> None:
    json_path = out_dir / "detection-coverage.json"
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)

    csv_path = out_dir / "detection-coverage.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Technique", "Status", "ControlIds", "GapControlIds"])
        for row in rows:
            writer.writerow(
                [row["Technique"], row["Status"], ";".join(row["ControlIds"]), ";".join(row["GapControlIds"])]
            )


def write_technical_report(
    results: list[ControlResult],
    findings: list[Finding],
    coverage: Coverage,
    risk: dict,
    compliance: dict,
    context: dict,
    out_dir: Path,
    detection_coverage: list[dict] | None = None,
) -> None:
    payload = {
        "SchemaVersion": "3.0",
        "FrameworkVersion": FRAMEWORK_VERSION,
        "GeneratedAtUtc": utcnow_iso(),
        "Context": context,
        "Coverage": coverage.to_dict(),
        "Risk": risk,
        "Compliance": compliance,
        "DetectionCoverage": detection_coverage or [],
        "ControlResults": [r.to_dict() for r in results],
        "Findings": [f.to_dict() for f in findings],
    }
    with open(out_dir / "technical-report.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def write_executive_html(
    findings: list[Finding],
    coverage: Coverage,
    risk: dict,
    compliance: dict,
    context: dict,
    out_dir: Path,
    delta=None,
    detection_coverage=None,
) -> None:
    sev = risk["severity_counts"]
    gap_count = sum(1 for row in (detection_coverage or []) if row["Status"] == "Gap")
    gap_card = ""
    if detection_coverage is not None:
        gap_card = f'<div class="card critical"><div class="num">{gap_count}</div><div class="label">ATT&amp;CK Technique Gaps</div></div>'
    ordered = sorted(findings, key=lambda f: (REMEDIATION_ORDER.get(f.severity, 9), -f.risk_score))

    delta_banner = ""
    if delta is not None:
        summary = delta.to_summary()
        delta_banner = (
            f'<div class="banner delta">Delta vs previous run: {summary["new"]} new, '
            f"{summary['persisted']} persisted, {summary['resolved']} resolved.</div>"
        )

    rows = ""
    for finding in ordered[:50]:
        rows += (
            f'<tr class="{finding.severity.lower()}">'
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{html.escape(finding.control_id)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.resource_id[:60])}</td>"
            f"<td>{html.escape(finding.remediation[:120])}</td></tr>\n"
        )

    comp_rows = ""
    for entry in compliance.values():
        total = entry["evaluated"] or 1
        pct = round(100 * entry["passed"] / total)
        comp_rows += (
            f"<tr><td>{html.escape(entry['name'])}</td>"
            f"<td>{entry['passed']}/{entry['evaluated']}</td>"
            f"<td>{pct}%</td></tr>\n"
        )

    coverage_banner = ""
    if not coverage.all_selected_executed:
        coverage_banner = (
            f'<div class="banner">Coverage incomplete: {coverage.not_tested} not tested, '
            f"{coverage.error} errored. An empty findings list does not prove a clean assessment.</div>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Security Assessment — Executive Summary</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
h1{{font-size:1.6rem;margin-bottom:.3rem}}
h2{{font-size:1.1rem;margin:1.6rem 0 .8rem}}
.sub{{color:#94a3b8;margin-bottom:1.4rem;font-size:.9rem}}
.banner{{background:#7c2d12;color:#fed7aa;padding:.8rem 1rem;border-radius:8px;margin-bottom:1.4rem;font-size:.9rem}}
.banner.delta{{background:#1e3a8a;color:#bfdbfe}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:1rem}}
.card{{background:#1e293b;border-radius:12px;padding:1.1rem;text-align:center}}
.card .num{{font-size:1.9rem;font-weight:700}}
.card .label{{color:#94a3b8;font-size:.8rem;margin-top:.3rem}}
.score .num{{color:#38bdf8}}.critical .num{{color:#ef4444}}.high .num{{color:#f97316}}
.medium .num{{color:#eab308}}.low .num{{color:#22c55e}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden;margin-bottom:1rem}}
th{{background:#334155;padding:.7rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:.55rem 1rem;border-top:1px solid #334155;font-size:.85rem}}
tr.critical td:first-child{{color:#ef4444;font-weight:700}}
tr.high td:first-child{{color:#f97316;font-weight:700}}
tr.medium td:first-child{{color:#eab308}}tr.low td:first-child{{color:#22c55e}}
</style></head><body>
<h1>Cloud Security Assessment — Executive Summary</h1>
<p class="sub">{html.escape(context.get("cloud", ""))} account {html.escape(context.get("accountId", ""))}
&middot; profile {html.escape(context.get("profile", ""))}
&middot; generated {utcnow_iso()} &middot; CSAF v{FRAMEWORK_VERSION}</p>
{coverage_banner}
{delta_banner}
<div class="cards">
<div class="card score"><div class="num">{risk["normalised_score"]}</div><div class="label">Risk Score ({risk["rating"]})</div></div>
<div class="card"><div class="num">{len(findings)}</div><div class="label">Findings</div></div>
<div class="card critical"><div class="num">{sev["CRITICAL"]}</div><div class="label">Critical</div></div>
<div class="card high"><div class="num">{sev["HIGH"]}</div><div class="label">High</div></div>
<div class="card medium"><div class="num">{sev["MEDIUM"]}</div><div class="label">Medium</div></div>
<div class="card low"><div class="num">{sev["LOW"]}</div><div class="label">Low</div></div>
</div>
<div class="cards">
<div class="card"><div class="num">{coverage.executed}/{coverage.selected}</div><div class="label">Controls Executed</div></div>
<div class="card"><div class="num">{coverage.passed}</div><div class="label">Passed</div></div>
<div class="card"><div class="num">{coverage.not_tested}</div><div class="label">Not Tested</div></div>
<div class="card"><div class="num">{coverage.error}</div><div class="label">Errors</div></div>
{gap_card}
</div>
<h2>Compliance Rollup</h2>
<table><thead><tr><th>Framework</th><th>Passed / Evaluated</th><th>Pass Rate</th></tr></thead>
<tbody>{comp_rows or "<tr><td colspan=3>No mapped controls evaluated.</td></tr>"}</tbody></table>
<h2>Top Findings</h2>
<table><thead><tr><th>Severity</th><th>Control</th><th>Title</th><th>Resource</th><th>Remediation</th></tr></thead>
<tbody>{rows or "<tr><td colspan=5>No findings.</td></tr>"}</tbody></table>
</body></html>"""
    with open(out_dir / "executive-summary.html", "w", encoding="utf-8") as handle:
        handle.write(doc)
