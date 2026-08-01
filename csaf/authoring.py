"""Custom-control authoring toolkit (OFF-FEAT-008).

Two operator-facing helpers for people extending CSAF with their own controls:

* :func:`lint_catalog` / ``csaf-lint-catalog`` — validate a control catalog
  against the packaged JSON Schema **and** run semantic checks the schema
  cannot express, most importantly that every control's ``module``/``check``
  pair actually resolves to a real check method in the built-in (or installed
  plugin) module registry for its cloud. This catches the single most common
  authoring mistake: a catalog entry that references a check that does not
  exist, which otherwise only surfaces at runtime as an ``Error`` result.

* :func:`scaffold_module` / ``csaf-new-module`` — print a ready-to-edit
  assessment-module skeleton (an :class:`~csaf.clouds.base.AssessmentModule`
  subclass) plus a matching catalog-entry stub, so a new contributor starts
  from a correct, read-only-by-construction template.

Both helpers are read-only and offline: they touch no cloud and mutate no
tracked files unless the operator redirects output themselves.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .model import SEVERITIES

CLOUDS = ["aws", "azure", "gcp", "k8s"]
CLOUD_LABELS = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "k8s": "K8s"}
VALID_PROFILES = ["Inventory", "Assessment", "Validation", "AdversarySimulation"]
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# Virtual modules handled by every provider outside the check-method registry.
# "attestation" controls are answered from the engagement file (see
# csaf.clouds.base.attestation_results), not by a module check method.
VIRTUAL_MODULES = {"attestation"}


@dataclass(frozen=True)
class LintIssue:
    level: str  # "error" or "warning"
    location: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper()}] {self.location}: {self.message}"


def _module_registry(cloud: str) -> dict:
    """Return the built-in + plugin module registry for a cloud, or {} if unavailable."""
    import importlib

    module = importlib.import_module(f"csaf.clouds.{cloud}.modules")
    return dict(getattr(module, "MODULE_REGISTRY", {}))


def lint_catalog(path: str | Path, cloud: str | None = None, *, check_registry: bool = True) -> list[LintIssue]:
    """Lint a control catalog. Returns a list of issues (empty == clean).

    ``cloud`` overrides the cloud used to resolve modules; by default the
    catalog's own ``cloud`` field selects the registry. Set
    ``check_registry=False`` to skip module/check resolution (schema + semantic
    checks only), which is useful when the provider package is not importable.
    """
    path = Path(path)
    issues: list[LintIssue] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [LintIssue("error", path.name, f"cannot read/parse JSON: {exc}")]

    # 1. Schema validation (authoritative structural check).
    try:
        from .schema_validation import validate_instance

        validate_instance(data, "control-catalog.schema.json", path.name)
    except ValueError as exc:
        issues.append(LintIssue("error", path.name, str(exc)))
    except RuntimeError as exc:  # jsonschema missing
        issues.append(LintIssue("warning", path.name, f"schema validation skipped: {exc}"))

    controls = data.get("controls", [])
    catalog_cloud = data.get("cloud", "")
    resolved_cloud = (cloud or catalog_cloud or "").lower()
    if resolved_cloud in CLOUD_LABELS and CLOUD_LABELS[resolved_cloud] != catalog_cloud and not cloud:
        # cloud field label mismatch is covered by schema; nothing to do here.
        pass

    # 2. Semantic checks the schema cannot express.
    seen_ids: set[str] = set()
    for index, control in enumerate(controls):
        cid = control.get("id", f"<control#{index}>")
        loc = f"{path.name}::{cid}"

        if cid in seen_ids:
            issues.append(LintIssue("error", loc, "duplicate control id"))
        seen_ids.add(cid)

        if not _ID_RE.match(str(control.get("id", ""))):
            issues.append(LintIssue("error", loc, "control id must match [A-Za-z0-9][A-Za-z0-9._-]*"))

        severity = control.get("defaultSeverity", "")
        if severity not in SEVERITIES:
            issues.append(LintIssue("error", loc, f"defaultSeverity {severity!r} not in {SEVERITIES}"))

        profiles = control.get("profiles", [])
        for profile in profiles:
            if profile not in VALID_PROFILES:
                issues.append(LintIssue("error", loc, f"unknown profile {profile!r}"))
        if not profiles:
            issues.append(LintIssue("warning", loc, "control belongs to no profile; it will never be selected"))

        if control.get("validationOnly") and "Validation" not in profiles:
            issues.append(LintIssue("warning", loc, "validationOnly control is not in the Validation profile"))

        if "AdversarySimulation" in profiles and not any(
            str(m).startswith("MITRE:") for m in control.get("mappings", [])
        ):
            issues.append(
                LintIssue(
                    "warning",
                    loc,
                    "AdversarySimulation control has no MITRE: mapping; it will be filtered out of that profile",
                )
            )

    # 3. Module/check resolution against the real registry.
    if check_registry and resolved_cloud in CLOUDS:
        try:
            registry = _module_registry(resolved_cloud)
        except Exception as exc:  # noqa: BLE001 - provider package may not be installed
            issues.append(
                LintIssue("warning", path.name, f"module registry for {resolved_cloud!r} unavailable: {exc}")
            )
            registry = None
        if registry is not None:
            for control in controls:
                cid = control.get("id", "<control>")
                loc = f"{path.name}::{cid}"
                module_name = control.get("module", "")
                check_name = control.get("check", "")
                if module_name in VIRTUAL_MODULES:
                    # Answered from the engagement, not a check method; nothing to resolve.
                    continue
                module_cls = registry.get(module_name)
                if module_cls is None:
                    issues.append(
                        LintIssue(
                            "error",
                            loc,
                            f"module {module_name!r} not found in {resolved_cloud} registry "
                            f"(available: {sorted(registry)})",
                        )
                    )
                    continue
                if not callable(getattr(module_cls, check_name, None)):
                    issues.append(
                        LintIssue(
                            "error",
                            loc,
                            f"check {check_name!r} is not implemented on module {module_name!r} "
                            f"({module_cls.__name__})",
                        )
                    )

    return issues


MODULE_TEMPLATE = '''"""{label} {module} assessment module (scaffold).

Generated by ``csaf-new-module``. Every check method receives the control being
evaluated and a :class:`~csaf.clouds.base.CheckContext`, and must return a
``ControlResult`` (use ``self.result(...)``) or a list of them. Read only from
the cloud SDK on ``ctx.session``; never call a mutating operation.
"""

from __future__ import annotations

from csaf.clouds.base import AssessmentModule


class {classname}(AssessmentModule):
    name = "{module}"

    def {check}(self, control, ctx):
        # TODO: read configuration from ctx.session (read-only) and decide status.
        # Return Pass when the expected state holds, Fail when it does not.
        observed = "TODO: describe what was observed"
        passed = False  # TODO: compute from the observed configuration
        return self.result(
            control,
            ctx,
            status="Pass" if passed else "Fail",
            observed=observed,
        )
'''

CATALOG_ENTRY_TEMPLATE = {
    "id": "REPLACE-ME-1.1",
    "title": "Short human-readable control title",
    "category": "{module}",
    "module": "{module}",
    "check": "{check}",
    "defaultSeverity": "MEDIUM",
    "expectedState": "Describe the compliant state",
    "profiles": ["Assessment"],
    "mappings": [],
    "references": [],
}


def _classname(module: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^A-Za-z0-9]+", module) if part) + "Module"


def scaffold_module(cloud: str, module: str, check: str = "check_example") -> tuple[str, dict]:
    """Return (module_source, catalog_entry_stub) for a new check module."""
    cloud = cloud.lower()
    if cloud not in CLOUD_LABELS:
        raise ValueError(f"cloud must be one of {CLOUDS}")
    if not _ID_RE.match(module):
        raise ValueError("module name must match [A-Za-z0-9][A-Za-z0-9._-]*")
    source = MODULE_TEMPLATE.format(
        label=CLOUD_LABELS[cloud], module=module, check=check, classname=_classname(module)
    )
    entry = json.loads(json.dumps(CATALOG_ENTRY_TEMPLATE).replace("{module}", module).replace("{check}", check))
    return source, entry


# --- Console-script entry points -------------------------------------------


def lint_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lint a CSAF control catalog (schema + semantic + module resolution)."
    )
    parser.add_argument("catalog", nargs="+", help="Path(s) to control catalog JSON file(s).")
    parser.add_argument("--cloud", choices=CLOUDS, default=None, help="Override the cloud used to resolve modules.")
    parser.add_argument("--no-registry", action="store_true", help="Skip module/check resolution.")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures too.")
    args = parser.parse_args(argv)

    total_errors = 0
    total_warnings = 0
    for catalog in args.catalog:
        issues = lint_catalog(catalog, cloud=args.cloud, check_registry=not args.no_registry)
        errors = [i for i in issues if i.level == "error"]
        warnings = [i for i in issues if i.level == "warning"]
        total_errors += len(errors)
        total_warnings += len(warnings)
        if not issues:
            print(f"[OK] {catalog}: no issues")
        for issue in issues:
            print(issue)
    print(f"\n{total_errors} error(s), {total_warnings} warning(s).")
    if total_errors or (args.strict and total_warnings):
        return 1
    return 0


def scaffold_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print a new CSAF assessment-module scaffold + catalog stub.")
    parser.add_argument("--cloud", choices=CLOUDS, required=True)
    parser.add_argument("--module", required=True, help="Module key used in the catalog (e.g. 'eventbridge').")
    parser.add_argument("--check", default="check_example", help="First check method name (default: check_example).")
    args = parser.parse_args(argv)

    source, entry = scaffold_module(args.cloud, args.module, args.check)
    rel = f"csaf/clouds/{args.cloud}/modules/{args.module}.py"
    print(f"# ---- {rel} ----")
    print(source)
    print("# ---- catalog entry (add to the cloud's control-catalog and register the module) ----")
    print(json.dumps(entry, indent=2))
    print(
        f"\n# Register in csaf/clouds/{args.cloud}/modules/__init__.py:\n"
        f'#   _BUILTIN_MODULE_REGISTRY["{args.module}"] = {_classname(args.module)}'
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(lint_main())
