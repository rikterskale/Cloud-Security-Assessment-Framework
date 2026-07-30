"""Setuptools build hooks for reproducible source-revision metadata."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def build_revision() -> str:
    configured = os.environ.get("CSAF_SOURCE_REVISION", "").strip()
    if REVISION_PATTERN.fullmatch(configured):
        return configured.lower()
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return "unknown"
    discovered = completed.stdout.strip()
    return discovered.lower() if REVISION_PATTERN.fullmatch(discovered) else "unknown"


class BuildPyWithRevision(build_py):
    def run(self) -> None:
        super().run()
        target = Path(self.build_lib) / "csaf" / "_source_revision"
        target.write_text(build_revision() + "\n", encoding="ascii", newline="\n")


setup(cmdclass={"build_py": BuildPyWithRevision})
