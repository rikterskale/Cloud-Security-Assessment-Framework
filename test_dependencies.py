#!/usr/bin/env python3
"""Preflight dependency and configuration check for CSAF.

Thin wrapper around :func:`csaf.preflight.run_preflight` so both a source
checkout and an installed wheel resolve packaged catalogs correctly.
"""

from __future__ import annotations

import sys

from csaf.preflight import format_preflight, run_preflight


def main(argv: list[str] | None = None) -> int:
    cloud = "aws"
    output_dir = "csaf-output"
    args = list(argv if argv is not None else sys.argv[1:])
    if "--cloud" in args:
        idx = args.index("--cloud")
        if idx + 1 < len(args):
            cloud = args[idx + 1]
    if "--output-dir" in args:
        idx = args.index("--output-dir")
        if idx + 1 < len(args):
            output_dir = args[idx + 1]
    checks = run_preflight(cloud, output_dir, include_optional=True)
    print(format_preflight(checks))
    return 0 if all(not check.required or check.status != "FAIL" for check in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
