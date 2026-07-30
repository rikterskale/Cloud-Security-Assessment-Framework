"""Resolve explicit configuration paths or packaged CSAF defaults."""

from __future__ import annotations

from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Iterator

RESOURCE_PACKAGE = "csaf.resources"


@contextmanager
def resolve_resource(
    explicit_path: str | Path | None,
    category: str,
    name: str,
) -> Iterator[Path]:
    """Yield an explicit path or a materialized packaged resource path."""
    if explicit_path is not None:
        yield Path(explicit_path)
        return

    resource = files(RESOURCE_PACKAGE).joinpath(category, name)
    if not resource.is_file():
        raise FileNotFoundError(f"Packaged CSAF {category} resource is missing: {name}")
    with as_file(resource) as path:
        yield Path(path)


def read_resource_text(category: str, name: str) -> str:
    """Read a UTF-8 packaged resource without depending on the current directory."""
    resource = files(RESOURCE_PACKAGE).joinpath(category, name)
    if not resource.is_file():
        raise FileNotFoundError(f"Packaged CSAF {category} resource is missing: {name}")
    return resource.read_text(encoding="utf-8")
