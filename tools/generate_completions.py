"""Print or write a CSAF shell completion file generated from the argparse parser.

Always UTF-8 with LF line endings. Redirecting this script on Windows PowerShell
can produce UTF-16; use --write instead of shell redirection.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from csaf.completion import render  # noqa: E402
from invoke_assessment import build_parser  # noqa: E402

OUTPUT = {
    "bash": ROOT / "completions" / "csaf-assess.bash",
    "zsh": ROOT / "completions" / "_csaf-assess",
    "powershell": ROOT / "completions" / "csaf-assess.ps1",
}


def main() -> None:
    if len(sys.argv) not in {2, 3} or sys.argv[1] not in OUTPUT:
        raise SystemExit("Usage: python tools/generate_completions.py {bash|zsh|powershell} [--write]")
    text = render(sys.argv[1], build_parser()).replace("\r\n", "\n").replace("\r", "\n")
    if len(sys.argv) == 3:
        if sys.argv[2] != "--write":
            raise SystemExit("Usage: python tools/generate_completions.py {bash|zsh|powershell} [--write]")
        path = OUTPUT[sys.argv[1]]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
        return
    sys.stdout.buffer.write(text.encode("utf-8"))


if __name__ == "__main__":
    main()
