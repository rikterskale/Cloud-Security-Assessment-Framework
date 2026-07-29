#!/usr/bin/env python3
"""CSAF — Cloud Security Assessment Framework runner (AWS).

Read-only AWS security posture assessment. Enumerates configuration, evaluates a
declarative control catalog, and produces coverage, findings, and reports. It
does not create, modify, or delete resources. The Validation profile enables
optional non-destructive validation and requires an approved engagement.

Examples
--------
Offline demo (no AWS needed):
    python3 invoke_assessment.py --self-check --output-dir out

Assess an account:
    python3 invoke_assessment.py --profile Assessment \
        --regions us-east-1 us-west-2 --aws-profile audit \
        --baseline baselines/aws-cis-1.5.json --output-dir out

Validation profile (requires an approving engagement file):
    python3 invoke_assessment.py --profile Validation \
        --engagement engagement.json --regions us-east-1 --output-dir out
"""

from __future__ import annotations

import argparse
import sys

from csaf import FRAMEWORK_VERSION
from csaf.runner import RunConfig, run_assessment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only AWS cloud security posture assessment (CSAF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--profile",
        default="Assessment",
        choices=["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        help="Authorization profile (default: Assessment).",
    )
    parser.add_argument(
        "--regions", nargs="+", default=["us-east-1"], help="Authorized regions for regional controls."
    )
    parser.add_argument("--catalog", default="controls/control-catalog.json", help="Path to the control catalog.")
    parser.add_argument(
        "--baseline", default="baselines/aws-cis-1.5.json", help="Path to the baseline thresholds file."
    )
    parser.add_argument(
        "--engagement", default=None, help="Path to the engagement authorization file (required for Validation)."
    )
    parser.add_argument("--aws-profile", default=None, help="Named AWS credentials profile to use (read-only).")
    parser.add_argument("--output-dir", default="csaf-output", help="Directory for reports and evidence.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR"])
    parser.add_argument("--self-check", action="store_true", help="Run offline with synthetic data (no cloud calls).")
    parser.add_argument("--version", action="version", version=f"CSAF v{FRAMEWORK_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = RunConfig(
        profile=args.profile,
        regions=args.regions,
        catalog_path=args.catalog,
        baseline_path=args.baseline,
        engagement_path=args.engagement,
        output_dir=args.output_dir,
        aws_profile=args.aws_profile,
        log_level=args.log_level,
        self_check=args.self_check,
    )
    result = run_assessment(config)
    print(
        f"\n[{'OK' if result.exit_code == 0 else 'INCOMPLETE' if result.exit_code == 2 else 'FATAL'}] {result.message}"
    )
    print(f"[*] Output written to {result.output_dir}")
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
