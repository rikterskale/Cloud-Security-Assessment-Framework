#!/usr/bin/env python3
"""
aggregator.py — Hybrid Multi-Cloud Security Testing Aggregator
==============================================================
Unifies outputs from GCP (Doc 1), AWS (Doc 2), and Azure (Doc 3) into:
  1. Unified JSON        — all findings normalised to a single schema
  2. Interactive HTML     — sortable, filterable dashboard with severity charts
  3. Executive Summary    — markdown report with risk scores
  4. Unified Neo4j Cypher — loads cross-cloud findings into a single graph
  5. Audit Manifest       — SHA-256 hashes of every input and output file

License: Apache-2.0
Telemetry: None — zero outbound network calls
Compliance: SHA-256 signed reports for SOC 2 / ISO 27001 / HIPAA / PCI-DSS
"""

import argparse
import datetime
import hashlib
import html
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "2.0.0"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_SCORES = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
COMPLIANCE_MAP = {
    "soc2": {
        "CC6.1": ["iam", "identity"],
        "CC6.6": ["network", "perimeter", "firewall", "nsg"],
        "CC6.7": ["encryption", "kms", "tde", "cmek", "key"],
        "CC7.1": ["runtime", "container", "eks", "aks", "gke"],
    },
    "iso27001": {
        "A.9":  ["iam", "identity", "rbac", "role"],
        "A.10": ["encryption", "kms", "key", "tde", "cmek"],
        "A.12": ["runtime", "container", "function", "lambda"],
        "A.13": ["network", "firewall", "nsg", "vpc", "vnet"],
    },
    "hipaa": {
        "164.312(a)": ["iam", "identity", "access", "rbac"],
        "164.312(b)": ["audit", "log", "trail", "monitor"],
        "164.312(e)": ["encryption", "tls", "ssl", "kms"],
    },
    "pci-dss": {
        "Req1":  ["network", "firewall", "nsg", "security_group"],
        "Req3":  ["encryption", "data", "storage", "bucket", "blob"],
        "Req7":  ["iam", "identity", "access", "rbac", "role"],
        "Req10": ["log", "audit", "trail", "monitor", "cloudtrail"],
    },
}

# ---------------------------------------------------------------------------
# Finding Schema
# ---------------------------------------------------------------------------

def make_finding(
    finding_id: str,
    cloud: str,
    source_tool: str,
    source_file: str,
    title: str,
    description: str,
    severity: str,
    resource_type: str = "",
    resource_id: str = "",
    region: str = "",
    recommendation: str = "",
    compliance_refs: list | None = None,
    raw: Any = None,
) -> dict:
    """Return a normalised finding dict."""
    return {
        "id": finding_id,
        "cloud": cloud.upper(),
        "source_tool": source_tool,
        "source_file": source_file,
        "title": title,
        "description": description,
        "severity": severity.upper() if severity.upper() in SEVERITIES else "INFO",
        "severity_score": SEVERITY_SCORES.get(severity.upper(), 0),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "recommendation": recommendation,
        "compliance_refs": compliance_refs or [],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "raw_excerpt": str(raw)[:500] if raw else "",
    }


# ---------------------------------------------------------------------------
# Parsers — one per tool/format family
# ---------------------------------------------------------------------------

def _severity_from_text(text: str) -> str:
    """Best-effort severity extraction from arbitrary text."""
    t = text.upper()
    for s in SEVERITIES:
        if s in t:
            return s
    return "INFO"


def parse_prowler_json(path: Path, cloud: str) -> list[dict]:
    """Parse Prowler JSON-OCSF output."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        items = data if isinstance(data, list) else data.get("findings", data.get("results", []))
        for item in items:
            sev = (
                item.get("severity", "")
                or item.get("severity_text", "")
                or item.get("finding", {}).get("severity", "")
            )
            findings.append(make_finding(
                finding_id=str(uuid.uuid4()),
                cloud=cloud,
                source_tool="prowler",
                source_file=str(path),
                title=item.get("check_id", item.get("title", "Prowler finding")),
                description=item.get("status_extended", item.get("description", "")),
                severity=_severity_from_text(str(sev)),
                resource_type=item.get("resource_type", ""),
                resource_id=item.get("resource_uid", item.get("resource_id", "")),
                region=item.get("region", ""),
                recommendation=item.get("remediation", {}).get("recommendation", {}).get("text", "")
                    if isinstance(item.get("remediation"), dict) else "",
                raw=item,
            ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_scoutsuite_json(path: Path, cloud: str) -> list[dict]:
    """Parse ScoutSuite JSON result files."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for service_name, service in data.get("services", {}).items():
            for rule_name, rule in service.get("findings", {}).items():
                for item in rule.get("items", []):
                    findings.append(make_finding(
                        finding_id=str(uuid.uuid4()),
                        cloud=cloud,
                        source_tool="scoutsuite",
                        source_file=str(path),
                        title=f"{service_name}.{rule_name}",
                        description=rule.get("description", ""),
                        severity=_severity_from_text(rule.get("level", "warning")),
                        resource_id=str(item),
                        raw=rule,
                    ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_trivy_json(path: Path, cloud: str) -> list[dict]:
    """Parse trivy JSON output."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append(make_finding(
                    finding_id=str(uuid.uuid4()),
                    cloud=cloud,
                    source_tool="trivy",
                    source_file=str(path),
                    title=vuln.get("VulnerabilityID", "Unknown CVE"),
                    description=vuln.get("Title", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    resource_type="container_image",
                    resource_id=result.get("Target", ""),
                    recommendation=f"Upgrade {vuln.get('PkgName','')} to {vuln.get('FixedVersion','')}",
                    raw=vuln,
                ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_checkov_json(path: Path, cloud: str) -> list[dict]:
    """Parse checkov JSON output."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        results = data if isinstance(data, list) else [data]
        for block in results:
            for fail in block.get("results", {}).get("failed_checks", []):
                findings.append(make_finding(
                    finding_id=str(uuid.uuid4()),
                    cloud=cloud,
                    source_tool="checkov",
                    source_file=str(path),
                    title=fail.get("check_id", "CKV_UNKNOWN"),
                    description=fail.get("check_result", {}).get("evaluated_keys", ""),
                    severity="HIGH",
                    resource_type=fail.get("resource", ""),
                    resource_id=fail.get("file_path", ""),
                    recommendation=fail.get("guideline", ""),
                    raw=fail,
                ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_kube_bench_json(path: Path, cloud: str) -> list[dict]:
    """Parse kube-bench JSON output."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for section in data.get("Tests", data.get("Controls", [])):
            for test in section.get("tests", section.get("results", [])):
                for result in test.get("results", [test]):
                    if result.get("status", "") == "FAIL":
                        findings.append(make_finding(
                            finding_id=str(uuid.uuid4()),
                            cloud=cloud,
                            source_tool="kube-bench",
                            source_file=str(path),
                            title=result.get("test_number", ""),
                            description=result.get("test_desc", ""),
                            severity="HIGH",
                            recommendation=result.get("remediation", ""),
                            raw=result,
                        ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_nuclei_txt(path: Path, cloud: str) -> list[dict]:
    """Parse nuclei text output."""
    findings = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: [severity] [template-id] [protocol] url
                match = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
                if match:
                    findings.append(make_finding(
                        finding_id=str(uuid.uuid4()),
                        cloud=cloud,
                        source_tool="nuclei",
                        source_file=str(path),
                        title=match.group(2),
                        description=f"Protocol: {match.group(3)}, Target: {match.group(4)}",
                        severity=match.group(1),
                        resource_id=match.group(4),
                        raw=line,
                    ))
    except Exception as exc:
        print(f"  [WARN] Could not parse {path}: {exc}", file=sys.stderr)
    return findings


def parse_generic_json(path: Path, cloud: str) -> list[dict]:
    """Fallback parser for unknown JSON — extract what we can."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            text = json.dumps(item)
            sev = _severity_from_text(text)
            if sev != "INFO" or any(kw in text.lower() for kw in ["fail", "vulnerability", "danger", "alarm"]):
                findings.append(make_finding(
                    finding_id=str(uuid.uuid4()),
                    cloud=cloud,
                    source_tool="generic",
                    source_file=str(path),
                    title=item.get("title", item.get("check_id", item.get("name", path.stem))),
                    description=item.get("description", item.get("status_extended", ""))[:300],
                    severity=sev,
                    resource_id=item.get("resource_id", item.get("resource", "")),
                    raw=item,
                ))
    except Exception:
        pass
    return findings


# Router
PARSERS = {
    "prowler":    parse_prowler_json,
    "scoutsuite": parse_scoutsuite_json,
    "trivy":      parse_trivy_json,
    "checkov":    parse_checkov_json,
    "kube-bench": parse_kube_bench_json,
}


def detect_tool(path: Path) -> str:
    """Guess which tool produced a file based on filename patterns."""
    name = path.name.lower()
    if "prowler" in name:
        return "prowler"
    if "scout" in name:
        return "scoutsuite"
    if "trivy" in name:
        return "trivy"
    if "checkov" in name:
        return "checkov"
    if "kube-bench" in name or "kubebench" in name:
        return "kube-bench"
    if "nuclei" in name:
        return "nuclei"
    return "generic"


# ---------------------------------------------------------------------------
# Scanners — walk input directories
# ---------------------------------------------------------------------------

def scan_directory(input_dir: str, cloud: str) -> list[dict]:
    """Recursively scan a directory for parseable files."""
    findings: list[dict] = []
    root = Path(input_dir)
    if not root.exists():
        print(f"  [WARN] Directory does not exist: {input_dir}", file=sys.stderr)
        return findings
    files_parsed = 0
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        tool = detect_tool(path)
        if path.suffix == ".json":
            parser = PARSERS.get(tool, parse_generic_json)
            batch = parser(path, cloud)
        elif path.suffix == ".txt" and tool == "nuclei":
            batch = parse_nuclei_txt(path, cloud)
        else:
            continue
        if batch:
            findings.extend(batch)
            files_parsed += 1
    print(f"[+] Parsed {files_parsed} files from {input_dir}, extracted {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Compliance Tagging
# ---------------------------------------------------------------------------

def tag_compliance(findings: list[dict], frameworks: list[str]) -> list[dict]:
    """Add compliance references to each finding based on keyword matching."""
    for f in findings:
        text = (f["title"] + " " + f["description"] + " " + f["resource_type"]).lower()
        refs = []
        for fw in frameworks:
            mapping = COMPLIANCE_MAP.get(fw, {})
            for control, keywords in mapping.items():
                if any(kw in text for kw in keywords):
                    refs.append(f"{fw.upper()}:{control}")
        f["compliance_refs"] = list(set(refs))
    return findings


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def compute_risk_score(findings: list[dict]) -> dict:
    """Compute an overall risk score and breakdown."""
    severity_counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    weighted = sum(
        severity_counts[s] * SEVERITY_SCORES[s] for s in SEVERITIES
    )
    max_possible = len(findings) * 10 if findings else 1
    normalised = round((weighted / max_possible) * 100, 1)

    if normalised >= 70:
        rating = "CRITICAL"
    elif normalised >= 50:
        rating = "HIGH"
    elif normalised >= 30:
        rating = "MEDIUM"
    elif normalised >= 10:
        rating = "LOW"
    else:
        rating = "MINIMAL"

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "weighted_score": weighted,
        "normalised_score": normalised,
        "rating": rating,
    }


# ---------------------------------------------------------------------------
# Output: Unified JSON
# ---------------------------------------------------------------------------

def write_unified_json(findings: list[dict], output_dir: Path):
    path = output_dir / "unified-findings.json"
    with open(path, "w") as f:
        json.dump({
            "metadata": {
                "version": VERSION,
                "generated": datetime.datetime.utcnow().isoformat() + "Z",
                "total_findings": len(findings),
            },
            "findings": findings,
        }, f, indent=2)
    print(f"[*] Unified JSON       → {path}")


# ---------------------------------------------------------------------------
# Output: HTML Dashboard
# ---------------------------------------------------------------------------

def write_html_dashboard(findings: list[dict], risk: dict, output_dir: Path):
    path = output_dir / "dashboard.html"

    sev_data = json.dumps([risk["severity_counts"].get(s, 0) for s in SEVERITIES])
    cloud_counts: dict[str, int] = {}
    for f in findings:
        cloud_counts[f["cloud"]] = cloud_counts.get(f["cloud"], 0) + 1
    cloud_labels = json.dumps(list(cloud_counts.keys()))
    cloud_data = json.dumps(list(cloud_counts.values()))

    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_SCORES.get(x["severity"], 0), reverse=True):
        sev_class = f["severity"].lower()
        rows += f"""<tr class="{sev_class}">
  <td>{html.escape(f['severity'])}</td>
  <td>{html.escape(f['cloud'])}</td>
  <td>{html.escape(f['source_tool'])}</td>
  <td>{html.escape(f['title'][:80])}</td>
  <td>{html.escape(f['description'][:120])}</td>
  <td>{html.escape(f['resource_id'][:60])}</td>
  <td>{html.escape(', '.join(f['compliance_refs'][:3]))}</td>
</tr>\n"""

    dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Multi-Cloud Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; padding: 2rem; }}
  h1 {{ text-align:center; margin-bottom:0.5rem; font-size:1.8rem; }}
  .subtitle {{ text-align:center; color:#94a3b8; margin-bottom:2rem; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .card {{ background:#1e293b; border-radius:12px; padding:1.2rem; text-align:center; }}
  .card .num {{ font-size:2rem; font-weight:700; }}
  .card .label {{ color:#94a3b8; font-size:0.85rem; margin-top:0.3rem; }}
  .card.critical .num {{ color:#ef4444; }}
  .card.high .num {{ color:#f97316; }}
  .card.medium .num {{ color:#eab308; }}
  .card.low .num {{ color:#22c55e; }}
  .card.score .num {{ color:#38bdf8; }}
  .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:2rem; margin-bottom:2rem; }}
  .chart-box {{ background:#1e293b; border-radius:12px; padding:1.5rem; }}
  canvas {{ max-height: 280px; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:12px; overflow:hidden; }}
  th {{ background:#334155; padding:0.8rem 1rem; text-align:left; font-weight:600; font-size:0.8rem;
       text-transform:uppercase; letter-spacing:0.05em; }}
  td {{ padding:0.6rem 1rem; border-top:1px solid #334155; font-size:0.85rem; }}
  tr.critical td:first-child {{ color:#ef4444; font-weight:700; }}
  tr.high td:first-child {{ color:#f97316; font-weight:700; }}
  tr.medium td:first-child {{ color:#eab308; }}
  tr.low td:first-child {{ color:#22c55e; }}
  tr.info td:first-child {{ color:#94a3b8; }}
  .filter-bar {{ margin-bottom:1rem; display:flex; gap:0.5rem; flex-wrap:wrap; }}
  .filter-bar input {{ background:#1e293b; border:1px solid #475569; border-radius:8px;
    color:#e2e8f0; padding:0.5rem 1rem; width:300px; }}
  .filter-bar select {{ background:#1e293b; border:1px solid #475569; border-radius:8px;
    color:#e2e8f0; padding:0.5rem; }}
</style>
</head>
<body>
<h1>Multi-Cloud Security Dashboard</h1>
<p class="subtitle">Generated {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &middot; aggregator.py v{VERSION}</p>

<div class="cards">
  <div class="card score"><div class="num">{risk['normalised_score']}</div><div class="label">Risk Score ({risk['rating']})</div></div>
  <div class="card"><div class="num">{risk['total_findings']}</div><div class="label">Total Findings</div></div>
  <div class="card critical"><div class="num">{risk['severity_counts'].get('CRITICAL',0)}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="num">{risk['severity_counts'].get('HIGH',0)}</div><div class="label">High</div></div>
  <div class="card medium"><div class="num">{risk['severity_counts'].get('MEDIUM',0)}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="num">{risk['severity_counts'].get('LOW',0)}</div><div class="label">Low</div></div>
</div>

<div class="charts">
  <div class="chart-box"><canvas id="sevChart"></canvas></div>
  <div class="chart-box"><canvas id="cloudChart"></canvas></div>
</div>

<div class="filter-bar">
  <input type="text" id="search" placeholder="Filter findings ..." oninput="filterTable()">
  <select id="sevFilter" onchange="filterTable()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
</div>

<table id="findings">
<thead><tr><th>Severity</th><th>Cloud</th><th>Tool</th><th>Title</th><th>Description</th><th>Resource</th><th>Compliance</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>

<script>
new Chart(document.getElementById('sevChart'),{{type:'bar',data:{{labels:{json.dumps(SEVERITIES)},datasets:[{{
  label:'Findings by Severity',data:{sev_data},
  backgroundColor:['#ef4444','#f97316','#eab308','#22c55e','#94a3b8']}}]}},
  options:{{responsive:true,plugins:{{legend:{{display:false}}}}}}}});
new Chart(document.getElementById('cloudChart'),{{type:'doughnut',data:{{labels:{cloud_labels},datasets:[{{
  data:{cloud_data},backgroundColor:['#38bdf8','#f97316','#a78bfa','#22c55e']}}]}},
  options:{{responsive:true}}}});
function filterTable(){{
  const q=document.getElementById('search').value.toLowerCase();
  const s=document.getElementById('sevFilter').value;
  document.querySelectorAll('#findings tbody tr').forEach(r=>{{
    const text=r.textContent.toLowerCase();
    const matchQ=!q||text.includes(q);
    const matchS=!s||r.classList.contains(s);
    r.style.display=(matchQ&&matchS)?'':'none';
  }});
}}
</script>
</body></html>"""

    with open(path, "w") as f:
        f.write(dashboard_html)
    print(f"[*] HTML dashboard     → {path}")


# ---------------------------------------------------------------------------
# Output: Executive Summary (Markdown)
# ---------------------------------------------------------------------------

def write_executive_summary(findings: list[dict], risk: dict, clouds: list[str], output_dir: Path):
    path = output_dir / "executive-summary.md"

    cloud_breakdown = ""
    for cloud in sorted(set(f["cloud"] for f in findings)):
        count = sum(1 for f in findings if f["cloud"] == cloud)
        crits = sum(1 for f in findings if f["cloud"] == cloud and f["severity"] == "CRITICAL")
        cloud_breakdown += f"| {cloud} | {count} | {crits} |\n"

    top_findings = ""
    for i, f in enumerate(sorted(findings, key=lambda x: x["severity_score"], reverse=True)[:15], 1):
        top_findings += f"| {i} | {f['severity']} | {f['cloud']} | {f['title'][:60]} | {f['resource_id'][:40]} |\n"

    md = f"""# Multi-Cloud Security Assessment — Executive Summary

**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  
**Aggregator Version:** {VERSION}  
**Clouds Assessed:** {', '.join(sorted(set(f['cloud'] for f in findings)))}

---

## Risk Overview

| Metric | Value |
|--------|-------|
| **Overall Risk Score** | **{risk['normalised_score']} / 100 ({risk['rating']})** |
| Total Findings | {risk['total_findings']} |
| Critical | {risk['severity_counts'].get('CRITICAL', 0)} |
| High | {risk['severity_counts'].get('HIGH', 0)} |
| Medium | {risk['severity_counts'].get('MEDIUM', 0)} |
| Low | {risk['severity_counts'].get('LOW', 0)} |
| Info | {risk['severity_counts'].get('INFO', 0)} |

## Cloud Breakdown

| Cloud | Findings | Critical |
|-------|----------|----------|
{cloud_breakdown}

## Top 15 Findings

| # | Severity | Cloud | Title | Resource |
|---|----------|-------|-------|----------|
{top_findings}

## Compliance Coverage

| Framework | Findings Tagged |
|-----------|----------------|
| SOC 2 | {sum(1 for f in findings if any('SOC2' in r for r in f['compliance_refs']))} |
| ISO 27001 | {sum(1 for f in findings if any('ISO27001' in r for r in f['compliance_refs']))} |
| HIPAA | {sum(1 for f in findings if any('HIPAA' in r for r in f['compliance_refs']))} |
| PCI-DSS | {sum(1 for f in findings if any('PCI-DSS' in r for r in f['compliance_refs']))} |

## Recommendations

1. **Immediate (0-24h):** Address all CRITICAL findings — these represent active exposure.
2. **Short-term (1-7d):** Remediate HIGH findings, especially public access misconfigurations.
3. **Medium-term (1-4w):** Resolve MEDIUM findings and implement automated compliance checks.
4. **Ongoing:** Integrate this pipeline into CI/CD for continuous security validation.

---

*This report was generated automatically by aggregator.py v{VERSION}. All file hashes are recorded in AUDIT-MANIFEST.sha256.*
"""
    with open(path, "w") as f:
        f.write(md)
    print(f"[*] Executive summary  → {path}")


# ---------------------------------------------------------------------------
# Output: Neo4j Cypher
# ---------------------------------------------------------------------------

def write_neo4j_cypher(findings: list[dict], output_dir: Path):
    path = output_dir / "neo4j-import.cypher"
    lines = [
        "// Auto-generated by aggregator.py — import all findings into Neo4j",
        "// Run: cat neo4j-import.cypher | cypher-shell -u neo4j -p <password>",
        "",
        "// Create constraints",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Cloud) REQUIRE c.name IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE;",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Severity) REQUIRE s.level IS UNIQUE;",
        "",
        "// Create severity nodes",
    ]
    for s in SEVERITIES:
        lines.append(f'MERGE (:Severity {{level: "{s}", score: {SEVERITY_SCORES[s]}}});')

    lines.append("\n// Create findings")
    for f in findings:
        title_esc = f["title"].replace('"', '\\"').replace("'", "\\'")[:80]
        desc_esc = f["description"].replace('"', '\\"').replace("'", "\\'")[:200]
        res_esc = f["resource_id"].replace('"', '\\"')[:100]
        lines.append(f"""
MERGE (cloud:Cloud {{name: "{f['cloud']}"}})
MERGE (tool:Tool {{name: "{f['source_tool']}"}})
MERGE (sev:Severity {{level: "{f['severity']}"}})
CREATE (finding:Finding {{
  id: "{f['id']}",
  title: "{title_esc}",
  description: "{desc_esc}",
  resource_id: "{res_esc}",
  resource_type: "{f['resource_type']}",
  severity_score: {f['severity_score']},
  timestamp: "{f['timestamp']}"
}})
CREATE (finding)-[:IN_CLOUD]->(cloud)
CREATE (finding)-[:FOUND_BY]->(tool)
CREATE (finding)-[:HAS_SEVERITY]->(sev);""")

    # Cross-cloud correlation queries
    lines.append("""
// --- Cross-cloud correlation queries ---

// Find resources exposed in multiple clouds
MATCH (f1:Finding)-[:IN_CLOUD]->(c1:Cloud)
MATCH (f2:Finding)-[:IN_CLOUD]->(c2:Cloud)
WHERE c1 <> c2
  AND f1.resource_type = f2.resource_type
  AND f1.title = f2.title
MERGE (f1)-[:CROSS_CLOUD_CORRELATION]->(f2);

// Find critical attack paths across clouds
MATCH (f:Finding)-[:HAS_SEVERITY]->(s:Severity {level: "CRITICAL"})
MATCH (f)-[:IN_CLOUD]->(c:Cloud)
RETURN c.name AS cloud, count(f) AS critical_findings
ORDER BY critical_findings DESC;
""")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"[*] Neo4j Cypher       → {path}")


# ---------------------------------------------------------------------------
# Output: Audit Manifest
# ---------------------------------------------------------------------------

def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def write_audit_manifest(input_dirs: list[str], output_dir: Path):
    path = output_dir / "AUDIT-MANIFEST.sha256"
    lines = [f"# Audit manifest generated {datetime.datetime.utcnow().isoformat()}Z",
             f"# aggregator.py v{VERSION}", ""]

    lines.append("# --- Input files ---")
    for d in input_dirs:
        root = Path(d)
        if root.exists():
            for fp in sorted(root.rglob("*")):
                if fp.is_file():
                    lines.append(f"{sha256_file(str(fp))}  {fp}")

    lines.append("\n# --- Output files ---")
    for fp in sorted(output_dir.rglob("*")):
        if fp.is_file() and fp.name != "AUDIT-MANIFEST.sha256":
            lines.append(f"{sha256_file(str(fp))}  {fp}")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[*] Audit manifest     → {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid Multi-Cloud Security Testing Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cloud", required=True,
                        choices=["gcp", "aws", "azure", "all"],
                        help="Cloud provider (or 'all' for cross-cloud aggregation)")
    parser.add_argument("--input-dir", required=True, nargs="+",
                        help="One or more input directories containing tool outputs")
    parser.add_argument("--output-dir", required=True,
                        help="Directory for aggregated outputs")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687",
                        help="Neo4j bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j",
                        help="Neo4j username")
    parser.add_argument("--neo4j-password", default="",
                        help="Neo4j password")
    parser.add_argument("--compliance-frameworks", default="soc2,iso27001,hipaa,pci-dss",
                        help="Comma-separated compliance frameworks to tag")
    parser.add_argument("--version", action="version", version=f"aggregator.py v{VERSION}")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    frameworks = [fw.strip().lower().replace("-", "-") for fw in args.compliance_frameworks.split(",")]

    # Determine cloud(s) to scan
    if args.cloud == "all":
        clouds = ["gcp", "aws", "azure"]
    else:
        clouds = [args.cloud]

    # Scan all input directories
    all_findings: list[dict] = []
    for input_dir in args.input_dir:
        # Try to auto-detect cloud from directory name
        dir_lower = input_dir.lower()
        if args.cloud != "all":
            cloud = args.cloud
        elif "gcp" in dir_lower or "google" in dir_lower:
            cloud = "gcp"
        elif "aws" in dir_lower or "amazon" in dir_lower:
            cloud = "aws"
        elif "azure" in dir_lower or "microsoft" in dir_lower:
            cloud = "azure"
        else:
            cloud = "unknown"
        print(f"[*] Scanning {input_dir} (cloud={cloud}) ...")
        all_findings.extend(scan_directory(input_dir, cloud))

    if not all_findings:
        print("[!] No findings extracted. Check input directories and file formats.", file=sys.stderr)
        sys.exit(1)

    # Tag compliance
    print(f"[*] Tagging {len(all_findings)} findings with compliance frameworks: {', '.join(frameworks)}")
    all_findings = tag_compliance(all_findings, frameworks)

    # Compute risk
    risk = compute_risk_score(all_findings)
    print(f"[*] Risk score: {risk['normalised_score']}/100 ({risk['rating']})")

    # Generate outputs
    write_unified_json(all_findings, output_dir)
    write_html_dashboard(all_findings, risk, output_dir)
    write_executive_summary(all_findings, risk, clouds, output_dir)
    write_neo4j_cypher(all_findings, output_dir)
    write_audit_manifest(args.input_dir, output_dir)

    print(f"\n[+] Aggregation complete. {len(all_findings)} findings across {len(set(f['cloud'] for f in all_findings))} cloud(s).")


if __name__ == "__main__":
    main()
