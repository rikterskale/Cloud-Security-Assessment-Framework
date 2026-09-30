"""Cleanup restricted to owned tutorial runs, preserving neighboring evidence."""

from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path

from .evidence import sha256_file
from .io_utils import atomic_text_writer

MARKER = ".csaf-tutorial.json"


def tutorial_base(output_dir: str) -> Path:
    base = Path(output_dir).resolve()
    if base.name not in {"csaf-output", "tutorial-output"}:
        raise ValueError("--output-dir must end in csaf-output or tutorial-output")
    return base


def mark_tutorial(output_dir: str, run_dir: str) -> None:
    base, run = Path(output_dir).resolve(), Path(run_dir).resolve()
    if run.parent != base:
        raise ValueError("tutorial run is outside its output directory")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    artifacts = manifest.get("Artifacts", [])
    if not artifacts:
        raise ValueError("tutorial manifest has no artifacts")
    for artifact in artifacts:
        path = (run / artifact["RelativePath"]).resolve()
        if not path.is_relative_to(run) or not path.is_file() or sha256_file(path) != artifact["SHA256"]:
            raise ValueError(f"tutorial artifact verification failed: {artifact['RelativePath']}")
    with atomic_text_writer(run / MARKER) as handle:
        json.dump({"runId": run.name}, handle)


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(
        getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def cleanup_tutorial(output_dir: str) -> int:
    """Remove marked synthetic tutorial children only; never remove the parent.

    Inspect all candidates before deletion. Reject links and Windows junctions
    so an owned directory cannot redirect cleanup outside the requested base.
    """
    base = tutorial_base(output_dir)
    if not base.exists():
        return 0
    owned = []
    for candidate in base.iterdir():
        if _is_link(candidate) or not candidate.is_dir() or not (candidate / MARKER).is_file():
            continue
        if candidate.resolve().parent != base:
            raise ValueError("tutorial run is outside its output directory")
        if any(_is_link(path) for path in candidate.rglob("*")):
            raise ValueError(f"tutorial run contains a link or junction: {candidate.name}")
        marker = json.loads((candidate / MARKER).read_text(encoding="utf-8"))
        context = json.loads((candidate / "technical-report.json").read_text(encoding="utf-8"))["Context"]
        if (
            marker.get("runId") != candidate.name
            or context.get("runId") != candidate.name
            or context.get("selfCheck") is not True
        ):
            raise ValueError(f"tutorial ownership could not be verified: {candidate.name}")
        owned.append(candidate)
    for run in owned:
        shutil.rmtree(run)
    return len(owned)
