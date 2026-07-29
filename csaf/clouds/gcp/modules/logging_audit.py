"""Cloud Logging and audit-configuration controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext
from .identity import project_iam_policy

LOGGING_V2 = "https://logging.googleapis.com/v2"
REQUIRED_LOG_TYPES = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}


class LoggingModule(AssessmentModule):
    name = "logging"

    def audit_logging(self, control, ctx: CheckContext):
        policy = project_iam_policy(ctx)
        for config in policy.get("auditConfigs", []) or []:
            if config.get("service") != "allServices":
                continue
            enabled = {c.get("logType") for c in config.get("auditLogConfigs", [])}
            exempted = [c for c in config.get("auditLogConfigs", []) if c.get("exemptedMembers")]
            if enabled >= REQUIRED_LOG_TYPES and not exempted:
                return self.result(
                    control,
                    ctx,
                    "Pass",
                    "Audit logging covers allServices for admin and data access without exemptions.",
                )
            missing = sorted(REQUIRED_LOG_TYPES - enabled)
            detail = f"missing log types {missing}" if missing else "exempted members present"
            return self.result(control, ctx, "Fail", f"allServices audit config incomplete: {detail}.")
        return self.result(control, ctx, "Fail", "No allServices audit configuration on the project IAM policy.")

    def log_sinks(self, control, ctx: CheckContext):
        sinks = ctx.session.get_list(f"{LOGGING_V2}/projects/{ctx.account_id}/sinks", "sinks")
        catch_all = [s for s in sinks if not s.get("filter") and not s.get("disabled")]
        if catch_all:
            names = [s.get("name", "unknown") for s in catch_all]
            return self.result(control, ctx, "Pass", f"Catch-all log sink(s) export all entries: {names}.")
        if sinks:
            return self.result(
                control,
                ctx,
                "Fail",
                f"{len(sinks)} sink(s) exist but none exports all log entries (every sink is filtered or disabled).",
            )
        return self.result(control, ctx, "Fail", "No log sinks are configured for the project.")
