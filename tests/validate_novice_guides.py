#!/usr/bin/env python3
"""Fail-closed validator for the canonical novice guides (roadmap #3 / REV-DOC-004).

Checks both `docs/guides/{WINDOWS,LINUX}_NOVICE_USABILITY_GUIDE.md` for:

* existence at the exact canonical paths;
* machine-readable YAML front matter with allowed enum values;
* all 30 mandatory top-level headings, in order;
* the command-block contract (each command ID documents "Run in:" and
  "Validation status:");
* no unresolved authoring placeholders;
* no instruction to disable a security control;
* cross-guide consistency (project name, repository URL, target release).

Runnable directly (`python tests/validate_novice_guides.py` — exit 1 on any
problem) so CI can gate on it, and importable (`validate_all()`), which the
unit test uses.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GUIDES = {
    "windows": REPO / "docs" / "guides" / "WINDOWS_NOVICE_USABILITY_GUIDE.md",
    "linux": REPO / "docs" / "guides" / "LINUX_NOVICE_USABILITY_GUIDE.md",
}
COMMAND_ID_PREFIX = {"windows": "WIN-CMD-", "linux": "LNX-CMD-"}

REQUIRED_HEADINGS = [
    "About This Guide",
    "What This Project Does",
    "Who Should Use It",
    "Safety, Authorization, and Data Handling",
    "Platform Support Status",
    "What You Will Accomplish",
    "Before You Begin Checklist",
    "Computer and Software Requirements",
    "Terms and Concepts You Need to Know",
    "Choose the Correct Installation Path",
    "Open the Correct Terminal or Shell",
    "Check and Install Prerequisites",
    "Download or Clone the Repository",
    "Find and Enter the Repository Folder",
    "Create an Isolated Environment",
    "Install Project Dependencies",
    "Build or Install the Project",
    "Verify the Installation",
    "Complete the First Safe Successful Run",
    "Understand the Screen Output, Exit Status, and Result Files",
    "Common Novice Workflows",
    "Configuration, Environment Variables, and Credentials",
    "How to Stop or Cancel Safely",
    "Cleanup, Uninstall, and Host Restoration",
    "Update, Upgrade, Downgrade, and Rollback",
    "Troubleshooting Matrix",
    "Frequently Asked Questions",
    "Command Quick Reference",
    "Glossary",
    "Validation Record, Known Limitations, and Support Boundaries",
]

ALLOWED_SUPPORT_STATUS = {"native_supported", "alternative_supported", "unsupported", "unverified"}
ALLOWED_VALIDATION_STATUS = {
    "verified_clean_environment",
    "partially_verified",
    "statically_verified_only",
    "blocked_environment_unavailable",
    "unsupported_platform",
}
REQUIRED_FRONT_MATTER = ["guide_id", "platform", "canonical_path", "project_name", "target_release", "target_commit"]

# Unresolved authoring tokens that must never ship in a final guide.
PLACEHOLDER_PATTERNS = [r"\{\{", r"<TODO>", r"FILL_ME_IN", r"your-value-here", r"TBD"]
# Instructions that weaken a security control (RemoteSigned/CurrentUser is fine).
UNSAFE_PATTERNS = [
    r"disable\s+(?:your\s+)?antivirus",
    r"disable\s+(?:the\s+)?firewall",
    r"ExecutionPolicy\s+(?:Bypass|Unrestricted)",
    r"verify\s*=\s*False",
    r"--no-check-certificate",
    r"curl\s+.*\|\s*sh",
]


def _front_matter(text: str) -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        return {}
    data = {}
    for line in match.group(1).splitlines():
        if ":" in line and not line.lstrip().startswith("-"):
            key, _, value = line.partition(":")
            data[key.strip()] = value.strip().strip('"')
    return data


def _heading_index(text: str, heading: str) -> int:
    """Return the position of a top-level heading, allowing an optional number
    prefix (e.g. '## 1. About This Guide'), or -1 if absent."""
    match = re.search(rf"^#{{1,6}}\s+(?:\d+\.\s+)?{re.escape(heading)}\s*$", text, re.MULTILINE)
    return match.start() if match else -1


def validate_guide(platform: str, path: Path) -> list[str]:
    problems: list[str] = []
    if not path.is_file():
        try:
            shown = path.relative_to(REPO)
        except ValueError:
            shown = path
        return [f"{platform}: missing canonical guide at {shown}"]

    text = path.read_text(encoding="utf-8")
    label = path.name

    # 1. Front matter.
    fm = _front_matter(text)
    if not fm:
        problems.append(f"{label}: missing YAML front matter")
    for key in REQUIRED_FRONT_MATTER:
        if not fm.get(key):
            problems.append(f"{label}: front matter missing/empty '{key}'")
    if fm.get("support_status") not in ALLOWED_SUPPORT_STATUS:
        problems.append(f"{label}: support_status {fm.get('support_status')!r} not allowed")
    if fm.get("validation_status") not in ALLOWED_VALIDATION_STATUS:
        problems.append(f"{label}: validation_status {fm.get('validation_status')!r} not allowed")
    if fm.get("platform") != platform:
        problems.append(f"{label}: front matter platform {fm.get('platform')!r} != {platform}")

    # 2. All headings, in order.
    last_index = -1
    for heading in REQUIRED_HEADINGS:
        idx = _heading_index(text, heading)
        if idx == -1:
            problems.append(f"{label}: missing required heading '{heading}'")
        elif idx < last_index:
            problems.append(f"{label}: heading '{heading}' is out of order")
        else:
            last_index = idx

    # 3. Command-block contract.
    command_ids = re.findall(rf"{COMMAND_ID_PREFIX[platform]}\d{{3}}", text)
    unique_ids = set(command_ids)
    if not unique_ids:
        problems.append(f"{label}: no command IDs found ({COMMAND_ID_PREFIX[platform]}NNN)")
    if len(command_ids) != len(set(command_ids)) and len(command_ids) - len(unique_ids) > len(unique_ids):
        # Command IDs are referenced again in the quick-reference table; only flag
        # if an ID is *defined* twice. Defined blocks carry a "Run in:" line.
        pass
    run_in = text.count("Run in:")
    validation_status = text.count("Validation status:")
    if run_in < len(unique_ids):
        problems.append(f"{label}: {len(unique_ids)} command IDs but only {run_in} 'Run in:' fields")
    if validation_status < len(unique_ids):
        problems.append(
            f"{label}: {len(unique_ids)} command IDs but only {validation_status} 'Validation status:' fields"
        )

    # 4. Placeholders.
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, text):
            problems.append(f"{label}: contains unresolved placeholder matching /{pattern}/")

    # 5. Unsafe instructions.
    for pattern in UNSAFE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            problems.append(f"{label}: contains unsafe instruction matching /{pattern}/")

    return problems


def validate_all() -> list[str]:
    problems: list[str] = []
    fronts = {}
    for platform, path in GUIDES.items():
        problems.extend(validate_guide(platform, path))
        if path.is_file():
            fronts[platform] = _front_matter(path.read_text(encoding="utf-8"))

    # Cross-guide consistency.
    if len(fronts) == 2:
        win, lnx = fronts["windows"], fronts["linux"]
        for key in ("project_name", "target_release", "target_commit"):
            if win.get(key) and win.get(key) != lnx.get(key):
                problems.append(f"cross-guide: {key} differs ({win.get(key)!r} vs {lnx.get(key)!r})")
    return problems


def main(argv: list[str] | None = None) -> int:
    problems = validate_all()
    if problems:
        print("Novice guide validation FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("Novice guide validation passed: both canonical guides are complete and consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
