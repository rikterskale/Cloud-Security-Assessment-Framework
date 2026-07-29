"""Assessment orchestration and exit-code policy.

Exit codes (mirroring the AD assessment framework):

* ``0`` — all selected controls executed and no execution errors.
* ``2`` — completed, but one or more selected controls were NotTested or errored.
* ``1`` — fatal runner or prerequisite failure (e.g. unauthorized profile).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path

from . import FRAMEWORK_VERSION
from .baseline import Baseline
from .catalog import Catalog
from .compliance import rollup
from .coverage import compute_coverage, compute_risk_score
from .engagement import Engagement
from .evidence import EvidenceStore, write_manifest
from .logging_ import AssessmentLogger
from .model import finding_from_result
from .remediation import remediation_for
from .reporting import (
    write_control_results,
    write_coverage,
    write_executive_html,
    write_findings,
    write_remediation_roadmap,
    write_technical_report,
)

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_INCOMPLETE = 2


@dataclass
class RunConfig:
    profile: str = "Assessment"
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    catalog_path: str = "controls/control-catalog.json"
    baseline_path: str | None = None
    engagement_path: str | None = None
    output_dir: str = "csaf-output"
    aws_profile: str | None = None
    log_level: str = "INFO"
    self_check: bool = False


@dataclass
class RunResult:
    exit_code: int
    output_dir: str
    coverage: dict
    risk: dict
    finding_count: int
    all_executed: bool
    message: str


def run_assessment(config: RunConfig) -> RunResult:
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger = AssessmentLogger(
        run_id=run_id,
        log_path=out_dir / f"assessment-{run_id}.log",
        jsonl_path=out_dir / f"assessment-{run_id}.jsonl",
        level=config.log_level,
    )

    try:
        catalog = Catalog.load(config.catalog_path)
        baseline = Baseline.load(config.baseline_path)
        engagement = Engagement.load(config.engagement_path)

        allowed, reason = engagement.authorize_profile(config.profile)
        logger.info("engagement", f"Profile '{config.profile}' authorization: {reason}")
        if not allowed:
            logger.error("engagement", f"Profile '{config.profile}' is not authorized: {reason}")
            logger.close()
            return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Unauthorized profile: {reason}")

        controls = catalog.for_profile(config.profile)
        # Honour baseline not-applicable exclusions.
        controls = [c for c in controls if c.id not in baseline.not_applicable_controls]
        selected_ids = {c.id for c in controls}
        logger.info("catalog", f"Selected {len(controls)} controls for profile '{config.profile}'.")

        evidence = EvidenceStore(out_dir)

        if config.self_check:
            from .selfcheck import SelfCheckProvider

            provider = SelfCheckProvider()
            account_id = provider.account_id
            logger.info("runner", "Running in offline self-check mode (no cloud calls).")
        else:
            from .clouds.aws.provider import AwsProvider
            from .clouds.aws.session import AwsSession

            session = AwsSession(profile=config.aws_profile, region=config.regions[0])
            account_id = session.account_id
            if not engagement.account_authorized(account_id):
                logger.error("engagement", f"Account {account_id} is not in the authorized scope.")
                logger.close()
                return RunResult(
                    EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Account {account_id} not authorized by engagement."
                )
            provider = AwsProvider(session, baseline, evidence, logger, engagement, config.profile)
            logger.info("runner", f"Assessing AWS account {account_id} in regions {config.regions}.")

        results = provider.evaluate(controls, config.regions)

        # Derive findings from Fail/Review results only.
        findings = [finding_from_result(r, remediation_for(r.control_id)) for r in results if r.is_finding]

        coverage = compute_coverage(selected_ids, results)
        evaluated_by_control = {r.control_id for r in results if r.is_executed or r.status == "Error"}
        not_tested_ids = sorted(selected_ids - evaluated_by_control)
        risk = compute_risk_score(results)
        compliance = rollup(results)

        context = {
            "runId": run_id,
            "cloud": "AWS",
            "accountId": account_id,
            "profile": config.profile,
            "regions": config.regions,
            "frameworkVersion": FRAMEWORK_VERSION,
            "engagementId": engagement.engagement_id,
            "selfCheck": config.self_check,
        }

        write_control_results(results, out_dir)
        write_findings(findings, out_dir)
        write_coverage(coverage, not_tested_ids, out_dir)
        write_remediation_roadmap(findings, out_dir)
        write_technical_report(results, findings, coverage, risk, compliance, context, out_dir)
        write_executive_html(findings, coverage, risk, compliance, context, out_dir)
        write_manifest(out_dir, "AWS", account_id, config.profile)

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
        logger.close()
        return RunResult(exit_code, str(out_dir), coverage.to_dict(), risk, len(findings), all_executed, message)

    except Exception as exc:  # noqa: BLE001 - top-level guard produces a fatal exit
        logger.error("runner", f"Fatal error: {type(exc).__name__}: {exc}")
        logger.close()
        return RunResult(EXIT_FATAL, str(out_dir), {}, {}, 0, False, f"Fatal: {exc}")
