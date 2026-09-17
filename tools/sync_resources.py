#!/usr/bin/env python3
"""Copy repository catalogs/baselines/schemas into the packaged resource tree.

Source of truth: controls/, baselines/, schemas/
Packaged copies: csaf/resources/{controls,baselines,schemas}/

  python tools/sync_resources.py          # copy source -> packaged
  python tools/sync_resources.py --check  # exit 1 on drift
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = (
    (ROOT / "controls", ROOT / "csaf" / "resources" / "controls"),
    (ROOT / "baselines", ROOT / "csaf" / "resources" / "baselines"),
    (ROOT / "schemas", ROOT / "csaf" / "resources" / "schemas"),
)


def _normalize(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def sync() -> None:
    for source, dest in PAIRS:
        dest.mkdir(parents=True, exist_ok=True)
        for path in dest.glob("*.json"):
            path.unlink()
        for path in sorted(source.glob("*.json")):
            shutil.copy2(path, dest / path.name)


def check() -> list[str]:
    problems: list[str] = []
    for source, dest in PAIRS:
        source_names = {p.name for p in source.glob("*.json")}
        dest_names = {p.name for p in dest.glob("*.json")}
        if source_names != dest_names:
            problems.append(f"{source.name}: names differ {sorted(source_names ^ dest_names)}")
            continue
        for name in sorted(source_names):
            if _normalize((source / name).read_bytes()) != _normalize((dest / name).read_bytes()):
                problems.append(f"{source.name}/{name} drifted from csaf/resources/{source.name}/{name}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync packaged CSAF resources.")
    parser.add_argument("--check", action="store_true", help="Fail if packaged copies drifted.")
    args = parser.parse_args(argv)
    if args.check:
        problems = check()
        if problems:
            print("Resource drift detected:")
            for problem in problems:
                print(f"  - {problem}")
            print("Fix: python tools/sync_resources.py")
            return 1
        print("Packaged resources match source directories.")
        return 0
    sync()
    print("Copied controls/, baselines/, and schemas/ into csaf/resources/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
