#!/usr/bin/env python3
"""Preflight dependency and configuration check for CSAF.

Reports required and optional dependencies as PASS / WARN / FAIL without running
an assessment. Exit code 1 if any required dependency fails.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

REQUIRED_PYTHON = (3, 10)


def _find(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:  # parent package of a dotted name is absent
        return False


def _check(label: str, ok: bool, detail: str, required: bool) -> tuple[str, bool]:
    status = "PASS" if ok else ("FAIL" if required else "WARN")
    print(f"  [{status}] {label}: {detail}")
    return status, (ok or not required)


def main() -> int:
    print("CSAF dependency preflight\n")
    all_required_ok = True

    version = sys.version_info
    _, ok = _check(
        "Python >= 3.10", version >= REQUIRED_PYTHON, f"{version.major}.{version.minor}.{version.micro}", required=True
    )
    all_required_ok &= ok

    for module in ("boto3", "botocore"):
        found = _find(module)
        _, ok = _check(
            f"{module} installed",
            found,
            "available" if found else "missing (needed for live AWS assessment)",
            required=True,
        )
        all_required_ok &= ok

    optional = {
        "jsonschema": "schema validation tests skipped",
        "azure.identity": "needed for live Azure assessment (pip install -r requirements-azure.txt)",
        "google.auth": "needed for live GCP assessment (pip install -r requirements-gcp.txt)",
        "requests": "needed for live Azure/GCP assessment",
        "kubernetes": "needed for live Kubernetes assessment (pip install -r requirements-k8s.txt)",
    }
    for module, note in optional.items():
        found = _find(module)
        _check(
            f"{module} installed (optional)",
            found,
            "available" if found else f"missing ({note})",
            required=False,
        )

    root = Path(__file__).parent
    for name in (
        "control-catalog.json",
        "control-catalog-azure.json",
        "control-catalog-gcp.json",
        "control-catalog-k8s.json",
    ):
        catalog = root / "controls" / name
        ok_catalog = catalog.exists()
        _, ok = _check(f"{name} present", ok_catalog, str(catalog), required=True)
        all_required_ok &= ok
        if ok_catalog:
            try:
                data = json.loads(catalog.read_text(encoding="utf-8"))
                count = len(data.get("controls", []))
                _check(f"{name} parses", True, f"{count} controls", required=True)
            except Exception as exc:  # noqa: BLE001
                _, ok = _check(f"{name} parses", False, str(exc), required=True)
                all_required_ok &= ok

    for name in ("aws-cis-1.5.json", "azure-cis-2.0.json", "gcp-cis-1.3.json", "k8s-cis-1.8.json"):
        baseline = root / "baselines" / name
        _check(f"baseline {name} present (optional)", baseline.exists(), str(baseline), required=False)

    print()
    if all_required_ok:
        print("[OK] All required dependencies satisfied.")
        return 0
    print("[FAIL] One or more required dependencies are missing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
