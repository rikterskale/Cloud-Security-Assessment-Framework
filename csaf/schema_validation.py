"""Runtime JSON Schema validation for operator-controlled configuration."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .resource_paths import read_resource_text


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    """Load and verify a packaged Draft 2020-12 schema."""
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - dependency preflight covers this
        raise RuntimeError(
            "Runtime configuration validation requires jsonschema. "
            "Install CSAF's declared dependencies before running an assessment."
        ) from exc

    schema = json.loads(read_resource_text("schemas", name))
    jsonschema.Draft202012Validator.check_schema(schema)
    return schema


def validate_instance(data: object, schema_name: str, source: str | Path) -> None:
    """Validate data and raise one actionable error containing all violations."""
    import jsonschema

    validator = jsonschema.Draft202012Validator(load_schema(schema_name), format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda error: [str(part) for part in error.absolute_path])
    if not errors:
        return

    details = []
    for error in errors[:10]:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        details.append(f"{location}: {error.message}")
    if len(errors) > 10:
        details.append(f"... and {len(errors) - 10} more validation error(s)")
    raise ValueError(f"{source} does not conform to {schema_name}: {'; '.join(details)}")
