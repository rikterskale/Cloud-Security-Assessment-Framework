"""Third-party module discovery via Python entry points.

Built-in modules are always the base registry for a cloud. Additional check
modules can be contributed by any installed distribution that declares an
entry point in the matching group (``csaf.modules.aws``, ``csaf.modules.azure``,
``csaf.modules.gcp``) — e.g. a ``pyproject.toml`` containing::

    [project.entry-points."csaf.modules.aws"]
    my_service = "my_csaf_extra.aws:MyServiceModule"

Installing that distribution makes ``MyServiceModule`` available under the
catalog ``module`` key ``my_service``, with no change to CSAF itself. Built-in
modules always win on a name collision: a third-party distribution cannot
silently shadow a core control's implementation.
"""

from __future__ import annotations

import os
import warnings
from importlib.metadata import entry_points

ALLOWLIST_ENV = "CSAF_PLUGIN_ALLOWLIST"


def _allowlist() -> set[str] | None:
    """Parse the optional plugin allowlist.

    Trust model: a third-party check module runs in-process with full trust once
    its distribution is installed, so installing a plugin is an explicit trust
    decision. For locked-down environments, set ``CSAF_PLUGIN_ALLOWLIST`` to a
    comma-separated list of entry-point names that may load; any other plugin is
    skipped (fail closed). Unset (the default) preserves prior behavior and loads
    every installed plugin. An empty value loads no plugins at all.
    """
    raw = os.environ.get(ALLOWLIST_ENV)
    if raw is None:
        return None
    return {name.strip() for name in raw.split(",") if name.strip()}


def discover_plugin_modules(group: str, builtin: dict) -> dict:
    """Merge externally-installed entry points into a built-in registry."""
    registry = dict(builtin)
    try:
        found = entry_points(group=group)
    except Exception as exc:  # noqa: BLE001 - a broken environment must not break CSAF's own modules
        warnings.warn(f"Plugin discovery for '{group}' failed: {exc}", stacklevel=2)
        return registry

    allowlist = _allowlist()

    for entry_point in found:
        if allowlist is not None and entry_point.name not in allowlist:
            warnings.warn(
                f"Skipping plugin module '{entry_point.name}' from '{entry_point.value}': not in {ALLOWLIST_ENV}.",
                stacklevel=2,
            )
            continue
        if entry_point.name in registry:
            warnings.warn(
                f"Ignoring plugin module '{entry_point.name}' from '{entry_point.value}': "
                "a built-in module already uses this name.",
                stacklevel=2,
            )
            continue
        try:
            registry[entry_point.name] = entry_point.load()
        except Exception as exc:  # noqa: BLE001 - one broken plugin must not break the others
            warnings.warn(f"Failed to load plugin module '{entry_point.name}': {exc}", stacklevel=2)

    return registry
