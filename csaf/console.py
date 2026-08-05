"""Small, dependency-free terminal presentation helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path


_ANSI = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "bold": "1"}


def use_color(no_color: bool = False) -> bool:
    """Honor explicit opt-out and the conventional NO_COLOR environment variable."""
    return not no_color and not os.environ.get("NO_COLOR") and sys.stdout.isatty()


def style(text: str, color: str, *, enabled: bool) -> str:
    return f"\x1b[{_ANSI[color]}m{text}\x1b[0m" if enabled else text


def progress_bar(completed: int, total: int, *, width: int = 20, color: bool = False) -> str:
    """Return a stable, line-oriented progress bar suitable for captured logs."""
    total = max(total, 1)
    completed = min(max(completed, 0), total)
    filled = round(width * completed / total)
    bar = "#" * filled + "-" * (width - filled)
    return style(f"[{bar}] {completed}/{total}", "blue", enabled=color)


def findings_table(result, *, color: bool = False) -> str:
    """Concise terminal table plus direct paths to the detailed artifacts."""
    risk, coverage = result.risk or {}, result.coverage or {}
    counts = risk.get("severity_counts")
    if not counts:
        return ""
    symbols = {"CRITICAL": "!", "HIGH": "!", "MEDIUM": "~", "LOW": "i"}
    shades = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "yellow", "LOW": "green"}
    rows = ["Findings summary:", "  Severity    Count"]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        label = f"{symbols[severity]} {severity:<9} {counts.get(severity, 0):>5}"
        rows.append("  " + style(label, shades[severity], enabled=color))
    out = Path(result.output_dir)
    rows.extend(
        [
            f"  Coverage    {coverage.get('Executed', '?')}/{coverage.get('SelectedControls', '?')} executed; "
            f"{coverage.get('NotTested', 0)} not tested; {coverage.get('Error', 0)} errored",
            "  Reports:",
            f"    HTML  {out / 'executive-summary.html'}",
            f"    CSV   {out / 'findings.csv'}",
            f"    JSON  {out / 'findings.json'}",
        ]
    )
    return "\n".join(rows)


def next_steps(command: str, detail: str) -> str:
    return f"\nWhat just happened: {detail}\nNext: {command}"
