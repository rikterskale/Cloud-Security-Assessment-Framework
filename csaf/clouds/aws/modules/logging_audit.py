"""CloudTrail, Config, and GuardDuty logging/detection controls."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext


class LoggingModule(AssessmentModule):
    name = "logging"

    def _trails(self, ctx: CheckContext) -> list[dict]:
        if "cloudtrail_trails" in ctx.cache:
            return ctx.cache["cloudtrail_trails"]
        ct = ctx.session.client("cloudtrail", ctx.region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        detailed = []
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            detailed.append({**trail, "_IsLogging": status.get("IsLogging", False)})
        ctx.cache["cloudtrail_trails"] = detailed
        return detailed

    def cloudtrail_multiregion(self, control, ctx: CheckContext):
        active = [t for t in self._trails(ctx) if t.get("IsMultiRegionTrail") and t.get("_IsLogging")]
        status = "Pass" if active else "Fail"
        return self.result(
            control, ctx, status, f"active multi-region trails={len(active)}", resource_type="cloudtrail"
        )

    def cloudtrail_log_validation(self, control, ctx: CheckContext):
        trails = self._trails(ctx)
        if not trails:
            return self.result(control, ctx, "Fail", "No CloudTrail trails to validate.")
        offenders = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
        if not offenders:
            return self.result(control, ctx, "Pass", "All trails enable log file validation.")
        return [
            self.result(
                control, ctx, "Fail", f"no log file validation: {name}", resource_type="cloudtrail", resource_id=name
            )
            for name in offenders
        ]

    def cloudtrail_kms(self, control, ctx: CheckContext):
        trails = self._trails(ctx)
        if not trails:
            return self.result(control, ctx, "Fail", "No CloudTrail trails to evaluate.")
        offenders = [t["Name"] for t in trails if not t.get("KmsKeyId")]
        if not offenders:
            return self.result(control, ctx, "Pass", "All trails encrypt logs with KMS.")
        return [
            self.result(
                control, ctx, "Fail", f"trail not KMS-encrypted: {name}", resource_type="cloudtrail", resource_id=name
            )
            for name in offenders
        ]

    def config_enabled(self, control, ctx: CheckContext):
        cfg = ctx.session.client("config", ctx.region)
        recorders = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        recording = [r for r in recorders if r.get("recording")]
        status = "Pass" if recording else "Fail"
        return self.result(
            control,
            ctx,
            status,
            f"active Config recorders={len(recording)}",
            resource_type="config-recorder",
            resource_id=ctx.region,
        )

    def guardduty_enabled(self, control, ctx: CheckContext):
        gd = ctx.session.client("guardduty", ctx.region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        active = []
        for det in detectors:
            if gd.get_detector(DetectorId=det).get("Status") == "ENABLED":
                active.append(det)
        status = "Pass" if active else "Fail"
        return self.result(
            control,
            ctx,
            status,
            f"enabled GuardDuty detectors={len(active)}",
            resource_type="guardduty",
            resource_id=ctx.region,
        )
