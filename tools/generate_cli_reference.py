"""Generate the user-facing CLI option table from argparse metadata."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from invoke_assessment import build_parser  # noqa: E402


def main() -> None:
    parser = build_parser()
    lines = [
        "# CSAF CLI Reference",
        "",
        "> Generated from `invoke_assessment.build_parser()`; run `python tools/generate_cli_reference.py` after changing CLI options.",
        "",
        "| Option | Default | Help |",
        "|---|---|---|",
    ]
    for action in parser._actions:
        if not action.option_strings or action.dest == "help":
            continue
        option = ", ".join(f"`{item}`" for item in action.option_strings)
        default = action.default if action.default is not None else "none"
        help_text = (action.help or "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {option} | `{default}` | {help_text} |")
    lines.extend(["", "## Safe first steps", "", "1. Run `python invoke_assessment.py --preflight`.", "2. Run `python invoke_assessment.py --plan --cloud aws --profile Assessment`.", "3. Run `python invoke_assessment.py --tutorial --output-dir tutorial-output`.", "4. Remove only tutorial output with `--cleanup-tutorial --output-dir tutorial-output`."])
    (ROOT / "docs" / "CLI_REFERENCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
