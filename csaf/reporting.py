"""Report generation: JSON, JSONL, CSV, and an executive HTML rollup."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from . import FRAMEWORK_VERSION
from .coverage import Coverage
from .io_utils import atomic_text_writer
from .model import ControlResult, Finding, utcnow_iso

REMEDIATION_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def spreadsheet_cell(value):
    """Keep cloud-controlled text inert when a CSV is opened in a spreadsheet.

    JSON retains original values. CSV quoting alone does not stop formula
    execution; leading whitespace can conceal a formula introducer.
    """
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@"))
    ):
        return "'" + value
    return value


def _csv_row(values):
    return [spreadsheet_cell(value) for value in values]


def write_control_results(results: list[ControlResult], out_dir: Path) -> None:
    jsonl_path = out_dir / "control-results.jsonl"
    with atomic_text_writer(jsonl_path) as handle:
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
    with atomic_text_writer(csv_path, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            writer.writerow({key: spreadsheet_cell(value) for key, value in result.to_dict().items()})


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
    with atomic_text_writer(json_path) as handle:
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
    with atomic_text_writer(csv_path, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in ordered:
            writer.writerow({key: spreadsheet_cell(value) for key, value in row(finding).items()})

    if delta is not None:
        with atomic_text_writer(out_dir / "findings-resolved.json") as handle:
            json.dump(delta.resolved, handle, indent=2)
        with atomic_text_writer(out_dir / "findings-unverified.json") as handle:
            json.dump(delta.unverified, handle, indent=2)


def write_coverage(coverage: Coverage, not_tested_ids: list[str], out_dir: Path) -> None:
    payload = {
        "CoverageSchemaVersion": "1.0",
        **coverage.to_dict(),
    }
    payload["NotTestedControls"] = sorted(not_tested_ids)
    with atomic_text_writer(out_dir / "coverage-report.json") as handle:
        json.dump(payload, handle, indent=2)

    with atomic_text_writer(out_dir / "coverage-report.csv", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Metric", "Value"])
        for key, value in payload.items():
            writer.writerow(_csv_row([key, value]))


def write_remediation_roadmap(findings: list[Finding], out_dir: Path) -> None:
    ordered = sorted(findings, key=lambda f: (REMEDIATION_ORDER.get(f.severity, 9), -f.risk_score))
    horizon = {"CRITICAL": "0-24h", "HIGH": "1-7d", "MEDIUM": "1-4w", "LOW": "1-3m"}
    with atomic_text_writer(out_dir / "remediation-roadmap.csv", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Priority", "Horizon", "Severity", "ControlId", "Title", "ResourceId", "Remediation"])
        for i, finding in enumerate(ordered, 1):
            writer.writerow(
                _csv_row(
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
            )


def write_detection_coverage(rows: list[dict], out_dir: Path) -> None:
    json_path = out_dir / "detection-coverage.json"
    with atomic_text_writer(json_path) as handle:
        json.dump(rows, handle, indent=2)

    csv_path = out_dir / "detection-coverage.csv"
    with atomic_text_writer(csv_path, newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Technique", "Status", "ControlIds", "GapControlIds"])
        for row in rows:
            writer.writerow(
                _csv_row(
                    [row["Technique"], row["Status"], ";".join(row["ControlIds"]), ";".join(row["GapControlIds"])]
                )
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
    with atomic_text_writer(out_dir / "technical-report.json") as handle:
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
    results: list[ControlResult] | None = None,
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
            f"{summary['persisted']} persisted, {summary['resolved']} resolved, "
            f"{summary.get('unverified', 0)} unverified. "
            "Unverified findings need a completed assessment in the same scope.</div>"
        )

    def finding_rows(items: list[Finding]) -> str:
        out = ""
        for finding in items:
            details = "".join(
                f"<dt>{label}</dt><dd>{html.escape(str(value or 'Not recorded'))}</dd>"
                for label, value in (
                    ("Finding", finding.finding),
                    ("Observed state", finding.observed_value),
                    ("Expected state", finding.expected_value),
                    ("Scope", f"{finding.cloud} / {finding.account_id} / {finding.region}"),
                    ("Confidence", finding.confidence),
                    ("Framework mappings", ", ".join(finding.mappings)),
                    ("Evidence reference", finding.evidence_ref),
                )
            )
            out += (
                f'<tr class="{finding.severity.lower()}">'
                f"<td>{html.escape(finding.severity)}</td>"
                f"<td>{html.escape(finding.control_id)}</td>"
                f"<td><details><summary>{html.escape(finding.title)}</summary><dl>{details}</dl></details></td>"
                f"<td>{html.escape(finding.resource_id or 'Control scope')}</td>"
                f"<td class=remediation>{html.escape(finding.remediation)}</td></tr>\n"
            )
        return out

    rows = finding_rows(ordered)
    findings_heading = "Findings"

    # Client-side filter/pivot toolbar (OFF-FEAT-010). Operates only on rows
    # already rendered in the page; performs no network calls. The script is
    # static (contains no untrusted data), so escaping guarantees are unchanged.
    filters_toolbar = (
        '<div class="filters">'
        '<input id="csaf-q" type="search" placeholder="Filter findings by any text…" aria-label="Filter findings">'
        '<span class="sevbtns">'
        '<button type="button" data-sev="all" class="active" aria-pressed="true">All</button>'
        '<button type="button" data-sev="critical" aria-pressed="false">Critical</button>'
        '<button type="button" data-sev="high" aria-pressed="false">High</button>'
        '<button type="button" data-sev="medium" aria-pressed="false">Medium</button>'
        '<button type="button" data-sev="low" aria-pressed="false">Low</button>'
        f'</span><span id="csaf-count" class="count" role="status" aria-live="polite">{len(ordered)} findings</span></div>'
        '<p id="csaf-no-matches" hidden>No matching findings. Clear search or choose All.</p>'
        "<noscript><p>Search needs JavaScript. All findings and details remain available below.</p></noscript>"
    )
    interactive_script = """<script>
(function(){
  var q=document.getElementById('csaf-q');
  var count=document.getElementById('csaf-count');
  var btns=document.querySelectorAll('.sevbtns button');
  var sev='all';
  function apply(){
    var term=(q&&q.value||'').toLowerCase();
    var shown=0,total=0;
    document.querySelectorAll('table.findings-table tbody tr').forEach(function(tr){
      if(!tr.className){return;}
      total++;
      var okSev=(sev==='all')||tr.classList.contains(sev);
      var okTerm=(!term)||tr.textContent.toLowerCase().indexOf(term)>=0;
      var show=okSev&&okTerm;
      tr.style.display=show?'':'none';
      if(show){shown++;}
    });
    if(count){count.textContent=shown+' of '+total+' shown';}
    var empty=document.getElementById('csaf-no-matches');
    if(empty){empty.hidden=shown!==0||total===0;}
  }
  if(q){q.addEventListener('input',apply);}
  btns.forEach(function(b){b.addEventListener('click',function(){
    sev=b.getAttribute('data-sev');
    btns.forEach(function(x){x.classList.remove('active');x.setAttribute('aria-pressed','false');});
    b.classList.add('active');
    b.setAttribute('aria-pressed','true');
    apply();
  });});
  apply();
})();
</script>"""

    gap_rows = "".join(
        f"<tr><td>{html.escape(result.control_id)}</td><td>{html.escape(result.title)}</td>"
        f"<td>{html.escape(result.status)}</td><td>{html.escape(result.error_reason or result.observed_value or 'No reason recorded; inspect control-results.jsonl.')}</td></tr>"
        for result in (results or [])
        if result.status in {"NotTested", "Error"}
    )
    gaps_section = ""
    if not coverage.all_selected_executed:
        gaps_section = '<section id="assessment-gaps"><h2>Assessment gaps</h2><p>Resolve missing access or attestations and rerun before relying on full coverage.</p>'
        if gap_rows:
            gaps_section += (
                '<div class="table-wrap"><table><caption>Controls that need follow-up</caption><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Reason</th></tr></thead><tbody>'
                + gap_rows
                + "</tbody></table></div>"
            )
        else:
            gaps_section += (
                '<p>See <a href="control-results.csv">control results</a> for NotTested and Error details.</p>'
            )
        gaps_section += "</section>"

    comp_rows = ""
    for entry in compliance.values():
        total = entry["evaluated"]
        pct = f"{round(100 * entry['passed'] / total)}%" if total else "Not evaluated"
        comp_rows += (
            f"<tr><td>{html.escape(entry['name'])}</td>"
            f"<td>{entry['passed']}/{entry['evaluated']}</td>"
            f"<td>{pct}</td></tr>\n"
        )

    coverage_banner = ""
    if not coverage.all_selected_executed:
        coverage_banner = (
            f'<div class="banner">Coverage incomplete: {coverage.not_tested} not tested, '
            f"{coverage.error} errored. An empty findings list does not prove a clean assessment.</div>"
        )

    mode_banner = ""
    if context.get("selfCheck"):
        mode_banner = '<div class="banner delta"><strong>Demo report — synthetic data.</strong> These findings do not describe your cloud environment. No cloud calls were made.</div>'
    elif context.get("profile") == "Inventory":
        mode_banner = '<div class="banner delta"><strong>Inventory mode.</strong> Security findings are not issued in this profile. Review control results or run the Assessment profile.</div>'
    empty_message = "No findings."
    if not coverage.all_selected_executed:
        empty_message += " Coverage is incomplete; untested controls may contain weaknesses."
    elif context.get("profile") == "Inventory":
        empty_message += " Inventory mode does not issue findings."
    else:
        empty_message += " No Fail or Review results in the selected scope. This is not a certification."

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Security Assessment — Executive Summary</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;line-height:1.5}}
main{{max-width:1440px;margin:auto}}
a{{color:#38bdf8;text-underline-offset:3px}}
.report-nav{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0 1.5rem}}
.intro{{color:#cbd5e1;margin-bottom:1rem;max-width:90ch}}
.table-wrap{{overflow-x:auto}}
td{{overflow-wrap:anywhere;vertical-align:top}}
.remediation,dd{{white-space:pre-wrap}}
dt{{font-weight:600;margin-top:.6rem}}dd{{margin:.2rem 0 .6rem;color:#cbd5e1}}
summary{{cursor:pointer}}details[open]{{min-width:240px}}
footer{{border-top:1px solid #334155;padding-top:1rem;margin-top:2rem;color:#94a3b8;font-size:.85rem}}
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
table.findings-table td:first-child{{white-space:nowrap}}
tr.critical td:first-child{{color:#ef4444;font-weight:700}}
tr.high td:first-child{{color:#f97316;font-weight:700}}
tr.medium td:first-child{{color:#eab308}}tr.low td:first-child{{color:#22c55e}}
.filters{{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:.4rem 0 1rem}}
.filters input{{flex:1;min-width:200px;background:#1e293b;border:1px solid #334155;color:#e2e8f0;
  padding:.5rem .8rem;border-radius:8px;font-size:.85rem}}
.filters .sevbtns{{display:flex;gap:.3rem;flex-wrap:wrap}}
.filters button{{background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:.45rem .8rem;
  border-radius:8px;font-size:.8rem;cursor:pointer}}
.filters button.active{{background:#334155;color:#e2e8f0}}
.filters .count{{color:#94a3b8;font-size:.8rem;margin-left:auto}}
details.all-findings{{margin-bottom:1rem}}
details.all-findings summary{{cursor:pointer;padding:.6rem 1rem;background:#1e293b;border-radius:8px;
  font-size:.85rem;color:#94a3b8;margin-bottom:.6rem}}
details.all-findings table{{margin-bottom:0}}
button:focus-visible,input:focus-visible,summary:focus-visible,a:focus-visible{{outline:3px solid #38bdf8;outline-offset:2px}}
caption{{text-align:left;padding:.7rem 1rem;color:#cbd5e1;font-weight:600}}
@media (prefers-color-scheme: light){{
  body{{background:#f8fafc;color:#0f172a}}
  .card,table,.filters input,.filters button,details.all-findings summary{{background:#ffffff;color:#0f172a}}
  th{{background:#e2e8f0}} td{{border-top-color:#cbd5e1}}
  .sub,.card .label,.filters .count,details.all-findings summary{{color:#475569}}
  .intro,dd,footer,caption{{color:#475569}}a{{color:#0369a1}}
  tr.critical td:first-child,.critical .num{{color:#b91c1c}}
  tr.high td:first-child,.high .num{{color:#9a3412}}
  tr.medium td:first-child,.medium .num{{color:#854d0e}}
  tr.low td:first-child,.low .num{{color:#166534}}
  .score .num{{color:#0369a1}}
}}
@media(max-width:640px){{body{{padding:1rem}}.cards{{gap:.5rem}}.card{{padding:.7rem}}}}
@media print{{
  body{{background:white;color:black;padding:0;font-size:10pt}}
  .card,table,.banner,.banner.delta{{background:white;color:black;border:1px solid #aaa}}
  th{{background:#eee;color:black}}td{{border-color:#ccc}}
  .sub,.card .label,.intro,dd,footer{{color:#333}}
  .filters,#csaf-no-matches,noscript,.report-nav{{display:none}}
  .table-wrap{{overflow:visible}}tr{{break-inside:avoid}}
  tr[style]{{display:table-row!important}}h2{{break-after:avoid}}
  a{{color:black}}
}}
</style></head><body><main>
<h1>Cloud Security Assessment — Executive Summary</h1>
<p class="sub">{html.escape(context.get("cloud", ""))} account {html.escape(context.get("accountId", ""))}
&middot; profile {html.escape(context.get("profile", ""))}
&middot; generated {utcnow_iso()} &middot; CSAF v{FRAMEWORK_VERSION}</p>
{mode_banner}
{coverage_banner}
{delta_banner}
<nav class="report-nav" aria-label="Report navigation">
<a href="#findings">Findings</a><a href="#compliance">Compliance</a>
<a href="findings.csv" download>Download findings CSV</a>
<a href="remediation-roadmap.csv" download>Remediation roadmap</a>
<a href="coverage-report.csv" download>Coverage</a>
<a href="technical-report.json" download>Technical report</a>
<a href="manifest.json" download>Evidence manifest</a>
</nav>
<p class="intro">Start with Critical and High findings. Expand a finding title for observed and expected states,
scope, and evidence references. Resolve assessment gaps, then rerun to verify improvements.</p>
<div class="cards">
<div class="card score"><div class="num">{risk["normalised_score"]}/100</div><div class="label">Risk Score ({html.escape(str(risk["rating"]))}) · higher is worse</div></div>
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
{gaps_section}
<section id="compliance"><h2>Compliance Rollup</h2>
<p class="intro">Pass rates cover evaluated, mapped controls only. They do not establish framework certification.</p>
<div class="table-wrap"><table><caption>Compliance results</caption><thead><tr><th scope="col">Framework</th><th scope="col">Passed / Evaluated</th><th scope="col">Pass Rate</th></tr></thead>
<tbody>{comp_rows or "<tr><td colspan=3>No mapped controls evaluated.</td></tr>"}</tbody></table></div></section>
<section id="findings"><h2>{findings_heading}</h2>
{filters_toolbar}
<div class="table-wrap"><table class="findings-table"><caption>Findings sorted by remediation priority</caption><thead><tr><th scope="col">Severity</th><th scope="col">Control</th><th scope="col">Title and evidence</th><th scope="col">Resource</th><th scope="col">Remediation</th></tr></thead>
<tbody>{rows or f"<tr><td colspan=5>{empty_message}</td></tr>"}</tbody></table></div></section>
<footer>Read-only assessment · selected scope and collection time only.
Reports may contain sensitive resource information; share with authorized recipients.
The evidence manifest records SHA-256 hashes for verification.</footer>
{interactive_script}
</main></body></html>"""
    with atomic_text_writer(out_dir / "executive-summary.html") as handle:
        handle.write(doc)
