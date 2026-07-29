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
        found = importlib.util.find_spec(module) is not None
        _, ok = _check(
            f"{module} installed",
            found,
            "available" if found else "missing (needed for live AWS assessment)",
            required=True,
        )
        all_required_ok &= ok

    for module in ("jsonschema",):
        found = importlib.util.find_spec(module) is not None
        _check(
            f"{module} installed (optional)",
            found,
            "available" if found else "missing (schema validation tests skipped)",
            required=False,
        )

    root = Path(__file__).parent
    catalog = root / "controls" / "control-catalog.json"
    ok_catalog = catalog.exists()
    _, ok = _check("control catalog present", ok_catalog, str(catalog), required=True)
    all_required_ok &= ok
    if ok_catalog:
        try:
            data = json.loads(catalog.read_text(encoding="utf-8"))
            count = len(data.get("controls", []))
            _check("control catalog parses", True, f"{count} controls", required=True)
        except Exception as exc:  # noqa: BLE001
            _, ok = _check("control catalog parses", False, str(exc), required=True)
            all_required_ok &= ok

    baseline = root / "baselines" / "aws-cis-1.5.json"
    _check("default baseline present (optional)", baseline.exists(), str(baseline), required=False)

    print()
    if all_required_ok:
        print("[OK] All required dependencies satisfied.")
        return 0
    print("[FAIL] One or more required dependencies are missing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
