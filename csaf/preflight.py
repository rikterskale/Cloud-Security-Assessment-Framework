"""Dependency-aware local preflight, live credential probes, and no-network planning."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path

from .runner import CLOUDS

_CORE_MODULES = (("jsonschema", "jsonschema"),)
_CLOUD_MODULES = {
    "aws": [
        ("boto3", "boto3"),
        ("botocore", "botocore"),
    ],
    "azure": [
        ("azure.identity", "azure.identity"),
        ("requests", "requests"),
    ],
    "gcp": [
        ("google-auth", "google.auth"),
        ("requests", "requests"),
    ],
    "k8s": [
        ("kubernetes", "kubernetes"),
    ],
}
_EXTRA_FIX = {
    "aws": "python -m pip install 'cloud-saf[aws]'",
    "azure": "python -m pip install 'cloud-saf[azure]'",
    "gcp": "python -m pip install 'cloud-saf[gcp]'",
    "k8s": "python -m pip install 'cloud-saf[k8s]'",
}


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str
    detail: str
    fix: str = ""
    required: bool = True


def _module_check(name: str, import_name: str, fix: str, *, required: bool = True) -> PreflightCheck:
    present = importlib.util.find_spec(import_name) is not None
    if present:
        return PreflightCheck(name, "PASS", "installed", "", required)
    status = "FAIL" if required else "WARN"
    detail = "missing" if required else "missing (needed for live provider runs)"
    return PreflightCheck(name, status, detail, fix, required)


def run_preflight(
    cloud: str = "aws",
    output_dir: str = "csaf-output",
    *,
    include_optional: bool = True,
    live: bool = False,
    aws_profile: str | None = None,
    subscription: str | None = None,
    project: str | None = None,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
) -> list[PreflightCheck]:
    """Return actionable checks. Live probes contact the selected cloud read-only."""
    checks = [
        PreflightCheck(
            "Python version",
            "PASS" if sys.version_info >= (3, 10) else "FAIL",
            sys.version.split()[0],
            ""
            if sys.version_info >= (3, 10)
            else "Install Python 3.10 or newer from https://www.python.org/downloads/",
        ),
    ]
    for name, import_name in _CORE_MODULES:
        checks.append(
            _module_check(
                name,
                import_name,
                "python -m pip install --require-hashes -r requirements-lock.txt",
            )
        )
    cloud_fix = _EXTRA_FIX.get(cloud, "python -m pip install --require-hashes -r requirements-lock.txt")
    for name, import_name in _CLOUD_MODULES.get(cloud, []):
        checks.append(_module_check(name, import_name, cloud_fix, required=True))
    if include_optional:
        for other, modules in _CLOUD_MODULES.items():
            if other == cloud:
                continue
            for name, import_name in modules:
                checks.append(_module_check(name, import_name, _EXTRA_FIX[other], required=False))
    catalog = str(CLOUDS.get(cloud, {}).get("catalog") or "")
    baseline = str(CLOUDS.get(cloud, {}).get("baseline") or "")
    repo_root = Path(__file__).resolve().parents[1]
    for label, category, name in (("catalog", "controls", catalog), ("baseline", "baselines", baseline)):
        path = repo_root / category / (name or "")
        packaged = files("csaf").joinpath("resources").joinpath(category).joinpath(name or "")
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
    if live:
        from .errors import probe_cloud_access

        for err in probe_cloud_access(
            cloud,
            aws_profile=aws_profile,
            subscription=subscription,
            project=project,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
        ):
            checks.append(
                PreflightCheck(
                    err.resource or "cloud access",
                    "FAIL" if err.blocking else "PASS",
                    err.cause,
                    err.fix,
                    required=err.blocking,
                )
            )
    return checks


def format_preflight(
    checks: list[PreflightCheck],
    *,
    live: bool = False,
    cloud: str = "aws",
    aws_profile: str | None = None,
    subscription: str | None = None,
    project: str | None = None,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
    regions: list[str] | None = None,
    output_dir: str = "out",
) -> str:
    from .operator_guide import scan_command

    title = "CSAF preflight (live credential/API checks)" if live else "CSAF preflight (no cloud calls)"
    lines = [title, ""]
    for check in checks:
        line = f"[{check.status}] {check.name}: {check.detail}"
        if check.fix:
            line += f"\n    Resource: {check.name}\n    Fix: {check.fix}"
        lines.append(line)
    required_failures = [c for c in checks if c.required and c.status == "FAIL"]
    lines.append("")
    if required_failures:
        first_fix = next((check.fix for check in required_failures if check.fix), "Fix the required checks above.")
        lines.append(f"Result: BLOCKED ({len(required_failures)} required check(s) failed)")
        lines.append(f"Next: {first_fix}")
        lines.append(f"      Full playbook: csaf-assess --guide --cloud {cloud}")
    elif live:
        cmd = scan_command(
            cloud,
            aws_profile=aws_profile,
            subscription=subscription,
            project=project,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            regions=regions,
            output_dir=output_dir,
        )
        lines.append("Result: PASS — identity and APIs are ready. CSAF will only read.")
        lines.append(f"Next: {cmd}")
        lines.append("      Then open out/*/executive-summary.html")
    else:
        lines.append("Result: PASS")
        lines.append("Next: python3 invoke_assessment.py --self-check --output-dir out")
        lines.append(f"      For a real {cloud} account: csaf-assess --guide --cloud {cloud}")
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
            files("csaf")
            .joinpath("resources")
            .joinpath("controls")
            .joinpath(CLOUDS[cloud]["catalog"])
            .read_text(encoding="utf-8")
        )
    baseline_data = (
        json.loads(baseline.read_text(encoding="utf-8"))
        if baseline.is_file()
        else json.loads(
            files("csaf")
            .joinpath("resources")
            .joinpath("baselines")
            .joinpath(CLOUDS[cloud]["baseline"])
            .read_text(encoding="utf-8")
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
