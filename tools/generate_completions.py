"""Print a CSAF shell completion file generated from the argparse parser."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from csaf.completion import render  # noqa: E402
from invoke_assessment import build_parser  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"bash", "zsh", "powershell"}:
        raise SystemExit("Usage: python tools/generate_completions.py {bash|zsh|powershell}")
    print(render(sys.argv[1], build_parser()), end="")


if __name__ == "__main__":
    main()
