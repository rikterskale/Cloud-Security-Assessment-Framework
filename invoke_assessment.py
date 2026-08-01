#!/usr/bin/env python3
"""CSAF — Cloud Security Assessment Framework runner (AWS / Azure / GCP / K8s).

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
    python3 invoke_assessment.py --self-check --cloud k8s --output-dir out

Assess an AWS account:
    python3 invoke_assessment.py --profile Assessment \
        --regions us-east-1 us-west-2 --aws-profile audit \
        --baseline baselines/aws-cis-1.5.json --output-dir out

Assess an Azure subscription (uses DefaultAzureCredential):
    python3 invoke_assessment.py --cloud azure \
        --subscription 00000000-0000-0000-0000-000000000000 --output-dir out

Assess a GCP project (uses Application Default Credentials):
    python3 invoke_assessment.py --cloud gcp --project my-project --output-dir out

Assess a Kubernetes cluster (uses the current or named kubeconfig context):
    python3 invoke_assessment.py --cloud k8s --kube-context my-cluster --output-dir out

Validation profile (requires an approving engagement file):
    python3 invoke_assessment.py --profile Validation \
        --engagement engagement.json --engagement-key-file engagement.key \
        --regions us-east-1 --output-dir out
"""

from __future__ import annotations

import argparse
import sys

from csaf import FRAMEWORK_VERSION
from csaf.runner import RunConfig, run_assessment

EXIT_CODE_MEANING = {
    0: "all selected controls executed, no errors",
    2: "completed, but some controls were NotTested or errored (e.g. a missing attestation)",
    1: "fatal error (unauthorized profile/scope, bad input, or a failed prerequisite)",
}

_EXIT_CODE_HELP = "Exit codes:\n" + "".join(
    f"  {code}  {meaning}\n" for code, meaning in sorted(EXIT_CODE_MEANING.items())
)


def exit_code_note(code: int) -> str:
    """One-line explanation of a non-zero exit code (empty for success)."""
    if code == 0:
        return ""
    return f"(exit {code}: {EXIT_CODE_MEANING.get(code, 'unknown')})"


def format_run_summary(result) -> str:
    """Human-readable severity/coverage summary for a completed run (empty if unavailable)."""
    risk = result.risk or {}
    coverage = result.coverage or {}
    counts = risk.get("severity_counts")
    if not counts:
        return ""
    return "\n".join(
        [
            f"Risk: {risk.get('normalised_score', '?')}/100 ({risk.get('rating', '?')})",
            "Findings by severity: "
            f"CRITICAL {counts.get('CRITICAL', 0)}, HIGH {counts.get('HIGH', 0)}, "
            f"MEDIUM {counts.get('MEDIUM', 0)}, LOW {counts.get('LOW', 0)}",
            f"Coverage: {coverage.get('Executed', '?')}/{coverage.get('SelectedControls', '?')} executed, "
            f"{coverage.get('NotTested', 0)} not tested, {coverage.get('Error', 0)} errored",
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only multi-cloud security posture assessment (CSAF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EXIT_CODE_HELP,
    )
    parser.add_argument(
        "--cloud",
        default="aws",
        choices=["aws", "azure", "gcp", "k8s"],
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
        "--engagement",
        default=None,
        help="Path to the signed engagement authorization file (required for active profiles).",
    )
    parser.add_argument(
        "--engagement-key-file",
        default=None,
        help="Path to the shared-secret key used to verify the signed engagement; required for "
        "Validation/AdversarySimulation (see sign_engagement.py).",
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
        "--kube-context",
        default=None,
        help="Kubeconfig context to assess (default: the kubeconfig's current-context).",
    )
    parser.add_argument(
        "--kubeconfig",
        default=None,
        help="Path to a kubeconfig file (default: the standard kubeconfig locations/KUBECONFIG env var).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="AWS only: evaluate this many regions concurrently (default: 1, sequential).",
    )
    parser.add_argument(
        "--output-dir",
        default="csaf-output",
        help="Parent directory; each assessment is written to a unique run subdirectory.",
    )
    parser.add_argument(
        "--export",
        nargs="+",
        default=[],
        choices=["sarif", "oscal"],
        help="Additionally write findings in interoperability formats (SARIF 2.1.0 and/or an OSCAL "
        "assessment-results subset). Additive; does not replace findings.json/csv.",
    )
    parser.add_argument(
        "--attest-key-file",
        default=None,
        help="Path to a shared-secret key; when given, write attestation.json signing the run manifest "
        "(verify later with csaf-attest verify).",
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR"])
    parser.add_argument(
        "--explain",
        metavar="CONTROL_ID",
        default=None,
        help="Print a control's intent, expected state, mappings, and remediation, then exit (offline; "
        "uses --cloud to pick the catalog).",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Preflight: validate the profile, engagement, scope, and catalog selection, then exit "
        "without contacting the cloud or writing reports (exit 0 if a run would be authorized, 1 otherwise).",
    )
    parser.add_argument("--self-check", action="store_true", help="Run offline with synthetic data (no cloud calls).")
    parser.add_argument("--version", action="version", version=f"CSAF v{FRAMEWORK_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.explain:
        from csaf.explain import explain_control

        text = explain_control(args.cloud, args.explain)
        if text is None:
            print(f"Control {args.explain!r} was not found in the {args.cloud} catalog.")
            return 1
        print(text)
        return 0

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
        kube_context=args.kube_context,
        kubeconfig_path=args.kubeconfig,
        max_workers=args.max_workers,
        log_level=args.log_level,
        self_check=args.self_check,
        export=args.export,
        attest_key_path=args.attest_key_file,
        check_only=args.check_only,
    )
    result = run_assessment(config)
    status = "OK" if result.exit_code == 0 else "INCOMPLETE" if result.exit_code == 2 else "FATAL"
    print(f"\n[{status}] {result.message}")
    note = exit_code_note(result.exit_code)
    if note:
        print(f"    {note}")
    summary = format_run_summary(result)
    if summary and args.log_level != "ERROR":
        print(summary)
    print(f"[*] Output written to {result.output_dir}")
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
