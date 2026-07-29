"""RDS data-protection controls (per-region scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext


class RdsModule(AssessmentModule):
    name = "rds"

    def _instances(self, ctx: CheckContext) -> list[dict]:
        key = f"rds_instances_{ctx.region}"
        if key in ctx.cache:
            return ctx.cache[key]
        rds = ctx.session.client("rds", ctx.region)
        instances = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            instances.extend(page.get("DBInstances", []))
        ctx.cache[key] = instances
        return instances

    def rds_encryption(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No RDS instances in region.")
        offenders = [i["DBInstanceIdentifier"] for i in instances if not i.get("StorageEncrypted")]
        if not offenders:
            return self.result(control, ctx, "Pass", "All RDS instances encrypt storage.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"unencrypted RDS storage: {name}",
                resource_type="rds-instance",
                resource_id=name,
            )
            for name in offenders
        ]

    def rds_public_access(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No RDS instances in region.")
        offenders = [i["DBInstanceIdentifier"] for i in instances if i.get("PubliclyAccessible")]
        if not offenders:
            return self.result(control, ctx, "Pass", "No publicly accessible RDS instances.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"publicly accessible RDS: {name}",
                resource_type="rds-instance",
                resource_id=name,
            )
            for name in offenders
        ]
