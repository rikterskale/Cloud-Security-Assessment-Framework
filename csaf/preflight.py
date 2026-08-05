"""Dependency-aware local preflight and no-network assessment planning."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path

from .runner import CLOUDS


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str
    detail: str
    fix: str = ""
    required: bool = True


def _module_check(name: str, import_name: str, fix: str) -> PreflightCheck:
    present = importlib.util.find_spec(import_name) is not None
    return PreflightCheck(
        name, "PASS" if present else "FAIL", "installed" if present else "missing", "" if present else fix
    )


def run_preflight(
    cloud: str = "aws", output_dir: str = "csaf-output", *, include_optional: bool = True
) -> list[PreflightCheck]:
    """Return actionable checks without importing provider SDKs or contacting a cloud."""
    checks = [
        PreflightCheck(
            "Python version",
            "PASS" if sys.version_info >= (3, 10) else "FAIL",
            sys.version.split()[0],
            "Install Python 3.10 or newer.",
        ),
        _module_check(
            "boto3",
            "boto3",
            "Install locked dependencies: python -m pip install --require-hashes -r requirements-lock.txt",
        ),
        _module_check(
            "botocore",
            "botocore",
            "Install locked dependencies: python -m pip install --require-hashes -r requirements-lock.txt",
        ),
        _module_check(
            "jsonschema",
            "jsonschema",
            "Install locked dependencies: python -m pip install --require-hashes -r requirements-lock.txt",
        ),
    ]
    optional = {
        "azure": [
            (
                "azure.identity",
                "azure.identity",
                "Install the Azure extra: python -m pip install -r requirements-azure.txt",
            ),
            ("requests", "requests", "Install the Azure extra: python -m pip install -r requirements-azure.txt"),
        ],
        "gcp": [
            ("google-auth", "google.auth", "Install the GCP extra: python -m pip install -r requirements-gcp.txt"),
            ("requests", "requests", "Install the GCP extra: python -m pip install -r requirements-gcp.txt"),
        ],
        "k8s": [
            ("kubernetes", "kubernetes", "Install the Kubernetes extra: python -m pip install -r requirements-k8s.txt")
        ],
    }
    if include_optional:
        for name, module, fix in optional.get(cloud, []):
            checks.append(
                PreflightCheck(
                    name,
                    "PASS" if importlib.util.find_spec(module) else "WARN",
                    "installed" if importlib.util.find_spec(module) else "missing (needed for live provider runs)",
                    fix,
                    required=False,
                )
            )
    catalog = CLOUDS.get(cloud, {}).get("catalog")
    baseline = CLOUDS.get(cloud, {}).get("baseline")
    repo_root = Path(__file__).resolve().parents[1]
    for label, category, name in (("catalog", "controls", catalog), ("baseline", "baselines", baseline)):
        path = repo_root / category / (name or "")
        packaged = files("csaf").joinpath("resources", category, name or "")
        present = path.is_file() or packaged.is_file()
        detail = str(path) if path.is_file() else f"packaged resource {category}/{name}"
        checks.append(
            PreflightCheck(
                f"{label} resource",
                "PASS" if present else "FAIL",
                detail,
                "Restore the packaged repository resource." if not present else "",
            )
        )
    target = Path(output_dir)
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe = target / ".csaf-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append(PreflightCheck("output directory", "PASS", str(target.resolve())))
    except OSError as exc:
        checks.append(
            PreflightCheck("output directory", "FAIL", str(exc), "Choose a writable path with --output-dir.")
        )
    return checks


def format_preflight(checks: list[PreflightCheck]) -> str:
    lines = ["CSAF preflight (no cloud calls)", ""]
    for check in checks:
        line = f"[{check.status}] {check.name}: {check.detail}"
        if check.fix:
            line += f"\n    Fix: {check.fix}"
        lines.append(line)
    required_failures = [c for c in checks if c.required and c.status == "FAIL"]
    lines.extend(
        [
            "",
            "Result: "
            + ("PASS" if not required_failures else f"BLOCKED ({len(required_failures)} required check(s) failed)"),
        ]
    )
    return "\n".join(lines)


def plan_assessment(
    cloud: str, profile: str, catalog_path: str | None = None, baseline_path: str | None = None
) -> dict:
    """Build a deterministic operator preview from JSON only; never contacts a provider."""
    catalog = (
        Path(catalog_path)
        if catalog_path
        else Path(__file__).resolve().parents[1] / "controls" / CLOUDS[cloud]["catalog"]
    )
    baseline = (
        Path(baseline_path)
        if baseline_path
        else Path(__file__).resolve().parents[1] / "baselines" / CLOUDS[cloud]["baseline"]
    )
    if catalog.is_file():
        data = json.loads(catalog.read_text(encoding="utf-8"))
    else:
        data = json.loads(
            files("csaf").joinpath("resources", "controls", CLOUDS[cloud]["catalog"]).read_text(encoding="utf-8")
        )
    baseline_data = (
        json.loads(baseline.read_text(encoding="utf-8"))
        if baseline.is_file()
        else json.loads(
            files("csaf").joinpath("resources", "baselines", CLOUDS[cloud]["baseline"]).read_text(encoding="utf-8")
        )
    )
    controls = [c for c in data.get("controls", []) if profile in c.get("profiles", [])]
    excluded = set(baseline_data.get("notApplicableControls", baseline_data.get("not_applicable_controls", [])))
    selected = [c for c in controls if c.get("id") not in excluded]
    return {
        "schemaVersion": "1.0",
        "cloud": cloud,
        "profile": profile,
        "catalog": str(catalog),
        "baseline": str(baseline),
        "selectedControls": len(selected),
        "excludedControls": sorted(excluded),
        "controlIds": [c.get("id") for c in selected],
        "networkCalls": 0,
        "requiresCredentials": profile in {"Validation", "AdversarySimulation"},
        "nextStep": "Review this plan, then run the same command without --plan when the scope and prerequisites are ready.",
    }


def preflight_json(checks: list[PreflightCheck]) -> list[dict]:
    return [asdict(check) for check in checks]
