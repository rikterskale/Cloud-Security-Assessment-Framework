"""Offline ``--explain CONTROL_ID`` support (UX-ENH-007).

Lets an operator read what a control checks, its expected state, framework
mappings, and remediation without running an assessment or reading source. It
loads the packaged (or overridden) catalog for a cloud and formats one control.
"""

from __future__ import annotations

from pathlib import Path

from .catalog import Catalog
from .remediation import remediation_for
from .resource_paths import resolve_resource


def explain_control(cloud: str, control_id: str, catalog_path: str | Path | None = None) -> str | None:
    """Return a human-readable explanation of ``control_id`` for ``cloud``.

    Returns ``None`` when the control is not present in the catalog. Raises
    ``ValueError`` for an unknown cloud.
    """
    from .runner import CLOUDS  # local import avoids a module cycle

    if cloud not in CLOUDS:
        raise ValueError(f"Unknown cloud {cloud!r}; choose one of {sorted(CLOUDS)}.")

    with resolve_resource(catalog_path, "controls", CLOUDS[cloud]["catalog"]) as path:
        catalog = Catalog.load(path)

    match = next((control for control in catalog.controls if control.id == control_id), None)
    if match is None:
        return None

    lines = [
        f"Control {match.id}: {match.title}",
        f"Cloud:           {CLOUDS[cloud]['label']}",
        f"Category:        {match.category}",
        f"Implemented by:  {match.module}.{match.check}",
        f"Default severity: {match.default_severity}",
        f"Profiles:        {', '.join(match.profiles) or '(none)'}",
        f"Expected state:  {match.expected_state or '(not specified)'}",
    ]
    if match.mappings:
        lines.append(f"Mappings:        {', '.join(match.mappings)}")
    if match.references:
        lines.append(f"References:      {', '.join(match.references)}")
    lines.append(f"Remediation:     {remediation_for(match.id)}")
    return "\n".join(lines)
