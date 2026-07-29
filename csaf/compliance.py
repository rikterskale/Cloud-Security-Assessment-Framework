"""Compliance framework rollup from control mappings.

Mappings are authored on each control in the catalog (e.g. ``CIS-AWS:1.5``,
``NIST-800-53:IA-2``). This module rolls failing controls up to a per-framework
summary rather than guessing from free text.
"""

from __future__ import annotations

from .model import ControlResult

FRAMEWORK_PREFIXES = {
    "CIS-AWS": "CIS AWS Foundations",
    "CIS-Azure": "CIS Microsoft Azure Foundations",
    "CIS-GCP": "CIS Google Cloud Platform Foundations",
    "CIS-Kubernetes": "CIS Kubernetes Benchmark",
    "NIST-800-53": "NIST SP 800-53",
    "MITRE": "MITRE ATT&CK",
    "RhinoSecurityLabs": "Rhino Security Labs Privesc Matrix",
}


def framework_of(mapping: str) -> str | None:
    prefix = mapping.split(":", 1)[0]
    return prefix if prefix in FRAMEWORK_PREFIXES else None


def rollup(results: list[ControlResult]) -> dict[str, dict]:
    """Return per-framework {evaluated, passed, failed, controls} summary."""
    summary: dict[str, dict] = {}
    for result in results:
        for mapping in result.mappings:
            framework = framework_of(mapping)
            if not framework:
                continue
            entry = summary.setdefault(
                framework,
                {"name": FRAMEWORK_PREFIXES[framework], "evaluated": 0, "passed": 0, "failed": 0, "controls": set()},
            )
            entry["controls"].add(mapping)
            if result.status in ("Pass", "Fail", "Review"):
                entry["evaluated"] += 1
                if result.status == "Pass":
                    entry["passed"] += 1
                else:
                    entry["failed"] += 1
    # Make JSON-serialisable.
    for entry in summary.values():
        entry["controls"] = sorted(entry["controls"])
    return summary
