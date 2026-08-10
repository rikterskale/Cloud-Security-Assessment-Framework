"""Assessment orchestration and exit-code policy.

Exit codes (mirroring the AD assessment framework):

* ``0`` — all selected controls executed and no execution errors.
* ``2`` — completed, but one or more selected controls were NotTested or errored.
* ``1`` — fatal runner or prerequisite failure (e.g. unauthorized profile).
"""

from __future__ import annotations

import datetime
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from . import FRAMEWORK_VERSION
from .baseline import Baseline
from .catalog import Catalog
from .compliance import rollup
from .coverage import compute_coverage, compute_risk_score
from .delta import compute_delta
from .detection_coverage import compute_detection_coverage
from .engagement import Engagement
from .evidence import EvidenceStore, write_manifest
from .logging_ import AssessmentLogger
from .model import finding_from_result
from .remediation import remediation_for
from .reporting import (
    write_control_results,
    write_coverage,
    write_detection_coverage,
    write_executive_html,
    write_findings,
    write_remediation_roadmap,
    write_technical_report,
)
from .resource_paths import resolve_resource

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_INCOMPLETE = 2
REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")

# Per-cloud packaged defaults: display label, control catalog, and baseline.
CLOUDS = {
    "aws": {
        "label": "AWS",
        "catalog": "control-catalog.json",
        "baseline": "aws-cis-1.5.json",
    },
    "azure": {
        "label": "Azure",
        "catalog": "control-catalog-azure.json",
        "baseline": "azure-cis-2.0.json",
    },
    "gcp": {
        "label": "GCP",
        "catalog": "control-catalog-gcp.json",
        "baseline": "gcp-cis-1.3.json",
    },
    "k8s": {
        "label": "K8s",
        "catalog": "control-catalog-k8s.json",
        "baseline": "k8s-cis-1.8.json",
    },
}


@dataclass
class RunConfig:
    profile: str = "Assessment"
    cloud: str = "aws"
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    catalog_path: str | None = None
    baseline_path: str | None = None
    engagement_path: str | None = None
    engagement_key_path: str | None = None
    allow_secret_discovery: bool = False
    previous_findings_path: str | None = None
    output_dir: str = "csaf-output"
    aws_profile: str | None = None
    subscription_id: str | None = None
    project_id: str | None = None
    kube_context: str | None = None
    kubeconfig_path: str | None = None
    max_workers: int = 1
    log_level: str = "INFO"
    self_check: bool = False
    export: list[str] = field(default_factory=list)
    attest_key_path: str | None = None
    check_only: bool = False
    no_color: bool = False
    color: bool = False


@dataclass
class RunResult:
    exit_code: int
    output_dir: str
    coverage: dict
    risk: dict
    finding_count: int
    all_executed: bool
    message: str


def source_revision() -> str:
    """Return the immutable source revision when supplied or locally discoverable."""
    configured = os.environ.get("CSAF_SOURCE_REVISION", "").strip()
    if REVISION_PATTERN.fullmatch(configured):
        return configured.lower()

    try:
        revision_resource = files("csaf").joinpath("_source_revision")
        packaged = revision_resource.read_text(encoding="ascii").strip() if revision_resource.is_file() else ""
    except (FileNotFoundError, ModuleNotFoundError):
        packaged = ""
    if REVISION_PATTERN.fullmatch(packaged):
        return packaged.lower()

    repository_root = Path(__file__).resolve().parent.parent
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return "unknown"
    discovered = completed.stdout.strip()
    return discovered.lower() if REVISION_PATTERN.fullmatch(discovered) else "unknown"


def run_assessment(config: RunConfig) -> RunResult:
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{secrets.token_hex(4)}"
    output_base = Path(config.output_dir)
    out_dir = output_base / run_id
    try:
        output_base.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(exist_ok=False)
    except Exception as exc:  # noqa: BLE001 - preserve fatal-result contract before logging exists
        return RunResult(EXIT_FATAL, str(output_base), {}, {}, 0, False, f"Fatal: cannot create run directory: {exc}")

    logger = AssessmentLogger(
        run_id=run_id,
        log_path=out_dir / f"assessment-{run_id}.log",
        jsonl_path=out_dir / f"assessment-{run_id}.jsonl",
        level=config.log_level,
    )

    try:
        if config.cloud not in CLOUDS:
            logger.error("runner", f"Unknown cloud '{config.cloud}'. Choose one of: {sorted(CLOUDS)}.")
            logger.close()
            return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Unknown cloud: {config.cloud}")
        cloud = CLOUDS[config.cloud]
        cloud_label = cloud["label"]

        with (
            resolve_resource(config.catalog_path, "controls", cloud["catalog"]) as catalog_path,
            resolve_resource(config.baseline_path, "baselines", cloud["baseline"]) as baseline_path,
        ):
            catalog = Catalog.load(catalog_path)
            baseline = Baseline.load(baseline_path)
        engagement = Engagement.load(config.engagement_path)

        signing_key = None
        if config.engagement_key_path:
            with open(config.engagement_key_path, "rb") as handle:
                signing_key = handle.read().strip()
            if not signing_key:
                raise ValueError("Engagement key file is empty.")

        allowed, reason = engagement.authorize_profile(config.profile, signing_key=signing_key)
        logger.info("engagement", f"Profile '{config.profile}' authorization: {reason}")
        if not allowed:
            logger.error("engagement", f"Profile '{config.profile}' is not authorized: {reason}")
            logger.close()
            return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Unauthorized profile: {reason}")

        if config.allow_secret_discovery:
            if config.cloud != "azure" or config.profile != "Validation":
                message = "--allow-secret-discovery is supported only for the Azure Validation profile."
                logger.error("secret-discovery", message)
                logger.close()
                return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, message)
            discovery_allowed, discovery_reason = engagement.authorize_secret_discovery(signing_key)
            logger.info("secret-discovery", f"Authorization: {discovery_reason}")
            if not discovery_allowed:
                logger.error("secret-discovery", f"Not authorized: {discovery_reason}")
                logger.close()
                return RunResult(
                    EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Unauthorized secret discovery: {discovery_reason}"
                )

        active_profile = config.profile in ("Validation", "AdversarySimulation")
        requested_account = {
            "azure": config.subscription_id,
            "gcp": config.project_id,
            "k8s": config.kube_context,
        }.get(config.cloud)
        if active_profile and config.cloud != "aws" and requested_account is None:
            if len(engagement.authorized_accounts) == 1:
                requested_account = engagement.authorized_accounts[0]
            else:
                message = (
                    f"Active {cloud_label} profiles require an explicit target identifier or exactly one "
                    "authorizedAccounts entry."
                )
                logger.error("engagement", message)
                logger.close()
                return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, message)
        scope_allowed, scope_reason = engagement.authorize_scope(
            cloud_label,
            config.regions,
            requested_account,
            active=active_profile,
        )
        logger.info("engagement", f"Requested scope authorization: {scope_reason}")
        if not scope_allowed:
            logger.error("engagement", f"Requested scope is not authorized: {scope_reason}")
            logger.close()
            return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Unauthorized scope: {scope_reason}")

        controls = catalog.for_profile(config.profile)
        # Honour baseline not-applicable exclusions.
        controls = [c for c in controls if c.id not in baseline.not_applicable_controls]
        if not controls:
            message = (
                f"Profile '{config.profile}' selected no controls for cloud '{config.cloud}'. "
                "Choose a supported profile or provide a catalog with controls for that profile."
            )
            logger.error("catalog", message)
            logger.close()
            return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, message)
        selected_ids = {c.id for c in controls}
        logger.info("catalog", f"Selected {len(controls)} controls for profile '{config.profile}'.")

        if config.check_only:
            # Preflight: profile, engagement, scope, and catalog selection are all
            # valid. Stop before any cloud contact or report writing.
            message = (
                f"Preflight passed: profile '{config.profile}', scope, and {len(controls)} "
                "selected controls are valid. No cloud calls or reports were made."
            )
            logger.info("runner", message)
            logger.close()
            return RunResult(EXIT_OK, str(out_dir), {}, {}, 0, True, message)

        evidence = EvidenceStore(out_dir)

        if config.self_check:
            from .selfcheck import SelfCheckProvider

            provider = SelfCheckProvider(cloud_label)
            account_id = provider.account_id
            logger.info("runner", "Running in offline self-check mode (no cloud calls).")
        else:
            provider_kwargs: dict = {}
            if config.cloud == "aws":
                from .clouds.aws.provider import AwsProvider as Provider
                from .clouds.aws.session import AwsSession

                session = AwsSession(profile=config.aws_profile, region=config.regions[0])
                account_id = session.account_id
                scope_note = f"account {account_id} in regions {config.regions}"
                provider_kwargs["max_workers"] = config.max_workers
                if len(config.regions) > 1:
                    from threading import Lock

                    from .console import progress_bar, use_color

                    completed_regions = 0
                    color = config.color or use_color(config.no_color)
                    progress_lock = Lock()

                    def show_region_progress(region: str) -> None:
                        nonlocal completed_regions
                        with progress_lock:
                            completed_regions += 1
                            print(
                                f"Progress {progress_bar(completed_regions, len(config.regions), color=color)} region complete: {region}"
                            )

                    provider_kwargs["progress_callback"] = show_region_progress
            elif config.cloud == "azure":
                from .clouds.azure.provider import AzureProvider as Provider
                from .clouds.azure.session import ArmSession

                session = ArmSession(subscription_id=requested_account)
                account_id = session.subscription_id
                scope_note = f"subscription {account_id}"
                provider_kwargs["secret_discovery_enabled"] = config.allow_secret_discovery
            elif config.cloud == "gcp":
                from .clouds.gcp.provider import GcpProvider as Provider
                from .clouds.gcp.session import GcpSession

                session = GcpSession(project_id=requested_account)
                account_id = session.project_id
                scope_note = f"project {account_id}"
            else:
                from .clouds.k8s.provider import K8sProvider as Provider
                from .clouds.k8s.session import K8sSession

                session = K8sSession(kubeconfig_path=config.kubeconfig_path, context=requested_account)
                account_id = session.cluster_context
                scope_note = f"cluster context {account_id}"

            provider = Provider(session, baseline, evidence, logger, engagement, config.profile, **provider_kwargs)
            logger.info("runner", f"Assessing {cloud_label} {scope_note}.")

        if not engagement.account_authorized(account_id):
            logger.error("engagement", f"Account or context {account_id} is not in the authorized scope.")
            logger.close()
            return RunResult(
                EXIT_FATAL,
                str(out_dir),
                {},
                {},
                0,
                False,
                f"Account or context {account_id} not authorized by engagement.",
            )

        results = provider.evaluate(controls, config.regions)

        # Derive findings from Fail/Review results only.
        findings = [finding_from_result(r, remediation_for(r.control_id)) for r in results if r.is_finding]
        delta = compute_delta(findings, config.previous_findings_path)

        coverage = compute_coverage(selected_ids, results)
        evaluated_by_control = {r.control_id for r in results if r.is_executed or r.status == "Error"}
        not_tested_ids = sorted(selected_ids - evaluated_by_control)
        risk = compute_risk_score(results)
        compliance = rollup(results)
        detection_coverage = compute_detection_coverage(results)

        revision = source_revision()
        context = {
            "runId": run_id,
            "cloud": cloud_label,
            "accountId": account_id,
            "profile": config.profile,
            "regions": config.regions,
            "frameworkVersion": FRAMEWORK_VERSION,
            "sourceRevision": revision,
            "engagementId": engagement.engagement_id,
            "selfCheck": config.self_check,
            "secretDiscovery": config.allow_secret_discovery,
        }

        if delta is not None:
            context["findingsDelta"] = delta.to_summary()

        write_control_results(results, out_dir)
        write_findings(findings, out_dir, delta=delta)
        write_coverage(coverage, not_tested_ids, out_dir)
        write_remediation_roadmap(findings, out_dir)
        write_detection_coverage(detection_coverage, out_dir)
        write_technical_report(
            results, findings, coverage, risk, compliance, context, out_dir, detection_coverage=detection_coverage
        )
        write_executive_html(
            findings, coverage, risk, compliance, context, out_dir, delta=delta, detection_coverage=detection_coverage
        )

        # Optional interoperability exports (additive; never replace findings.json).
        if config.export:
            from .export_formats import EXPORTERS

            for fmt in config.export:
                writer = EXPORTERS.get(fmt)
                if writer is None:
                    logger.warn("export", f"Unknown export format '{fmt}'; skipping.")
                    continue
                path = writer(findings, context, out_dir)
                logger.info("export", f"Wrote {fmt} export: {path.name}")

        # Report any selected control that did not complete.
        for control_id in not_tested_ids:
            logger.warn("coverage", f"SELECTED CHECK NOT COMPLETED: {control_id}")
        for result in results:
            if result.status == "Error":
                logger.warn("coverage", f"SELECTED CHECK NOT COMPLETED: {result.control_id} ({result.error_reason})")

        all_executed = coverage.all_selected_executed
        exit_code = EXIT_OK if all_executed else EXIT_INCOMPLETE
        message = (
            f"Completed. {len(findings)} findings, risk {risk['normalised_score']}/100 ({risk['rating']}). "
            f"Coverage {coverage.executed}/{coverage.selected} executed."
        )
        logger.info("runner", message)
        if not all_executed:
            logger.warn("runner", "CompletedWithErrors: not every selected control executed.")
        # The logger is flushed after every record. Write the manifest only
        # after the final log event so its hashes describe the completed run.
        write_manifest(out_dir, cloud_label, account_id, config.profile, source_revision=revision)
        # Optional attested evidence bundle: sign the manifest after it is
        # final. Created after the manifest and thus intentionally outside it.
        if config.attest_key_path:
            from .attestation import write_attestation

            with open(config.attest_key_path, "rb") as handle:
                attest_key = handle.read().strip()
            if attest_key:
                write_attestation(out_dir, attest_key)
        logger.close()
        return RunResult(exit_code, str(out_dir), coverage.to_dict(), risk, len(findings), all_executed, message)

    except Exception as exc:  # noqa: BLE001 - top-level guard produces a fatal exit
        from .diagnostics import format_fatal

        logger.error("runner", f"Fatal error: {type(exc).__name__}: {exc}")
        logger.close()
        return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Fatal: {format_fatal(exc)}")
