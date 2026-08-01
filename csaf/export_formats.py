"""Interoperability exports for findings: SARIF 2.1.0 and an OSCAL-aligned subset.

These writers are additive and opt-in (``--export sarif oscal``). They never
replace the canonical ``findings.json``/``findings.csv``; they render the same
findings into formats that downstream tooling consumes:

* **SARIF 2.1.0** — ingested by GitHub code scanning and most SAST dashboards.
* **OSCAL assessment-results (subset)** — consumed by GRC tooling that speaks
  the NIST OSCAL model. This is a pragmatic, documented subset of the OSCAL
  ``assessment-results`` model, not a full OSCAL validation target.

Both readers are pure functions of the already-derived ``Finding`` list plus the
run context, so they add no cloud interaction and no new trust boundary.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from . import FRAMEWORK_VERSION
from .io_utils import atomic_text_writer
from .model import Finding, utcnow_iso

INFORMATION_URI = "https://github.com/rikterskale/Cloud-Security-Assessment-Framework"

# CSAF finding severity -> SARIF result level.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

# A deterministic namespace so OSCAL UUIDs are stable for the same run/finding.
_UUID_NAMESPACE = uuid.UUID("6f1a3c58-0d2e-4a1b-9c7e-abcd00000001")


def _stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(_UUID_NAMESPACE, "|".join(parts)))


def build_sarif(findings: list[Finding], context: dict) -> dict:
    """Return a SARIF 2.1.0 document for ``findings``."""
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        rule_id = finding.control_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity, "warning")},
                "properties": {
                    "security-severity": str(finding.risk_score),
                    "tags": list(finding.mappings),
                },
            }
        location = finding.resource_id or f"{finding.cloud}:{finding.account_id}"
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": finding.finding + (f" Remediation: {finding.remediation}" if finding.remediation else "")
                },
                "partialFingerprints": {"csafFindingId": finding.finding_id},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "cloud": finding.cloud,
                    "accountId": finding.account_id,
                    "region": finding.region,
                    "mappings": list(finding.mappings),
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {"fullyQualifiedName": location, "kind": finding.resource_type or "resource"}
                        ]
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CSAF",
                        "informationUri": INFORMATION_URI,
                        "version": FRAMEWORK_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": context.get("runId", "")},
                "results": results,
            }
        ],
    }


def build_oscal(findings: list[Finding], context: dict) -> dict:
    """Return an OSCAL-aligned ``assessment-results`` subset for ``findings``."""
    run_id = context.get("runId", utcnow_iso())
    oscal_findings = []
    for finding in findings:
        oscal_findings.append(
            {
                "uuid": _stable_uuid("finding", run_id, finding.finding_id),
                "title": finding.title,
                "description": finding.finding,
                "props": [
                    {"name": "severity", "value": finding.severity},
                    {"name": "risk-score", "value": str(finding.risk_score)},
                    {"name": "control-id", "value": finding.control_id},
                    {"name": "cloud", "value": finding.cloud},
                    {"name": "account", "value": finding.account_id},
                ]
                + [{"name": "mapping", "value": m} for m in finding.mappings],
                "target": {
                    "type": "objective-id",
                    "target-id": finding.control_id,
                    "status": {"state": "not-satisfied"},
                },
                "remediations": (
                    [
                        {
                            "uuid": _stable_uuid("remediation", run_id, finding.finding_id),
                            "title": "Remediation",
                            "description": finding.remediation,
                        }
                    ]
                    if finding.remediation
                    else []
                ),
            }
        )
    return {
        "assessment-results": {
            "uuid": _stable_uuid("assessment-results", run_id),
            "metadata": {
                "title": f"CSAF Assessment Results — {context.get('cloud', '')} {context.get('accountId', '')}",
                "last-modified": utcnow_iso(),
                "version": FRAMEWORK_VERSION,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "csaf-profile", "value": context.get("profile", "")},
                    {"name": "csaf-source-revision", "value": context.get("sourceRevision", "")},
                    {"name": "csaf-oscal-subset", "value": "true"},
                ],
            },
            "results": [
                {
                    "uuid": _stable_uuid("result", run_id),
                    "title": "CSAF read-only posture assessment",
                    "description": "Findings derived from failed or review control results.",
                    "start": utcnow_iso(),
                    "findings": oscal_findings,
                }
            ],
        }
    }


def write_sarif(findings: list[Finding], context: dict, out_dir: Path) -> Path:
    path = out_dir / "findings.sarif.json"
    with atomic_text_writer(path) as handle:
        json.dump(build_sarif(findings, context), handle, indent=2)
    return path


def write_oscal(findings: list[Finding], context: dict, out_dir: Path) -> Path:
    path = out_dir / "findings.oscal.json"
    with atomic_text_writer(path) as handle:
        json.dump(build_oscal(findings, context), handle, indent=2)
    return path


# Exposed so the runner can iterate a name -> writer mapping.
EXPORTERS = {"sarif": write_sarif, "oscal": write_oscal}


def _digest(text: str) -> str:  # small helper kept for symmetry with evidence hashing
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
