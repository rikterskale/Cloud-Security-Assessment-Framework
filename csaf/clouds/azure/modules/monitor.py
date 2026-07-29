"""Azure Monitor / activity-log controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_DIAGNOSTIC = "2021-05-01-preview"
REQUIRED_CATEGORIES = {"Administrative", "Security", "Policy", "Alert"}


class MonitorModule(AssessmentModule):
    name = "monitor"

    def activity_log_export(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        settings = arm.get_value(f"{sub}/providers/Microsoft.Insights/diagnosticSettings", API_DIAGNOSTIC)
        if not settings:
            return self.result(control, ctx, "Fail", "No diagnostic setting exports the subscription activity log.")
        best: set[str] = set()
        for setting in settings:
            enabled = set()
            for log in setting.get("properties", {}).get("logs", []):
                if not log.get("enabled"):
                    continue
                if log.get("categoryGroup") == "allLogs":
                    enabled |= REQUIRED_CATEGORIES
                elif log.get("category"):
                    enabled.add(log["category"])
            if enabled >= REQUIRED_CATEGORIES:
                return self.result(
                    control,
                    ctx,
                    "Pass",
                    f"Diagnostic setting '{setting.get('name', 'unknown')}' exports all required activity-log categories.",
                )
            if len(enabled) > len(best):
                best = enabled
        missing = sorted(REQUIRED_CATEGORIES - best)
        return self.result(
            control, ctx, "Fail", f"No diagnostic setting covers required categories; best match misses {missing}."
        )
