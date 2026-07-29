#!/usr/bin/env python3
"""CSAF — Cloud Security Assessment Framework runner (AWS / Azure / GCP).

Read-only cloud security posture assessment. Enumerates configuration,
evaluates a declarative control catalog, and produces coverage, findings, and
reports. It does not create, modify, or delete resources. The Validation
profile enables optional non-destructive validation and requires an approved
engagement.

Examples
--------
Offline demo (no cloud needed):
    python3 invoke_assessment.py --self-check --output-dir out
    python3 invoke_assessment.py --self-check --cloud azure --output-dir out
    python3 invoke_assessment.py --self-check --cloud gcp --output-dir out

Assess an AWS account:
    python3 invoke_assessment.py --profile Assessment \
        --regions us-east-1 us-west-2 --aws-profile audit \
        --baseline baselines/aws-cis-1.5.json --output-dir out

Assess an Azure subscription (uses DefaultAzureCredential):
    python3 invoke_assessment.py --cloud azure \
        --subscription 00000000-0000-0000-0000-000000000000 --output-dir out

Assess a GCP project (uses Application Default Credentials):
    python3 invoke_assessment.py --cloud gcp --project my-project --output-dir out

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
        description="Read-only multi-cloud security posture assessment (CSAF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cloud",
        default="aws",
        choices=["aws", "azure", "gcp"],
        help="Cloud provider to assess (default: aws).",
    )
    parser.add_argument(
        "--profile",
        default="Assessment",
        choices=["Inventory", "Assessment", "Validation", "AdversarySimulation"],
        help="Authorization profile (default: Assessment).",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=["us-east-1"],
        help="Authorized regions for regional AWS controls (Azure/GCP controls are subscription/project scoped).",
    )
    parser.add_argument(
        "--catalog", default=None, help="Path to the control catalog (default: the selected cloud's catalog)."
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Path to the baseline thresholds file (default: the selected cloud's CIS baseline).",
    )
    parser.add_argument(
        "--engagement", default=None, help="Path to the engagement authorization file (required for Validation)."
    )
    parser.add_argument(
        "--engagement-key-file",
        default=None,
        help="Path to a shared-secret key file; when set, the engagement file's signature must verify "
        "(see sign_engagement.py) or Validation/AdversarySimulation is refused.",
    )
    parser.add_argument(
        "--previous-findings",
        default=None,
        help="Path to a prior run's findings.json to diff against (adds DeltaStatus and findings-resolved.json).",
    )
    parser.add_argument("--aws-profile", default=None, help="Named AWS credentials profile to use (read-only).")
    parser.add_argument(
        "--subscription", default=None, help="Azure subscription ID to assess (default: discovered if unambiguous)."
    )
    parser.add_argument("--project", default=None, help="GCP project ID to assess (default: the ADC default project).")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="AWS only: evaluate this many regions concurrently (default: 1, sequential).",
    )
    parser.add_argument("--output-dir", default="csaf-output", help="Directory for reports and evidence.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR"])
    parser.add_argument("--self-check", action="store_true", help="Run offline with synthetic data (no cloud calls).")
    parser.add_argument("--version", action="version", version=f"CSAF v{FRAMEWORK_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = RunConfig(
        profile=args.profile,
        cloud=args.cloud,
        regions=args.regions,
        catalog_path=args.catalog,
        baseline_path=args.baseline,
        engagement_path=args.engagement,
        engagement_key_path=args.engagement_key_file,
        previous_findings_path=args.previous_findings,
        output_dir=args.output_dir,
        aws_profile=args.aws_profile,
        subscription_id=args.subscription,
        project_id=args.project,
        max_workers=args.max_workers,
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
