"""Cloud SQL instance controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

SQLADMIN_V1 = "https://sqladmin.googleapis.com/v1"
SSL_ENFORCING_MODES = {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}


class SqlModule(AssessmentModule):
    name = "sql"

    def _instances(self, ctx: CheckContext) -> list[dict]:
        if "cloudsql_instances" not in ctx.cache:
            ctx.cache["cloudsql_instances"] = ctx.session.get_list(
                f"{SQLADMIN_V1}/instances", "items", params={"project": ctx.account_id}
            )
        return ctx.cache["cloudsql_instances"]

    def sql_open_to_world(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No Cloud SQL instances in project.")
        offenders = []
        for instance in instances:
            ip_config = instance.get("settings", {}).get("ipConfiguration", {})
            open_networks = [
                n.get("value") for n in ip_config.get("authorizedNetworks", []) if n.get("value") == "0.0.0.0/0"
            ]
            if open_networks:
                offenders.append(instance.get("name", "unknown"))
        if not offenders:
            return self.result(control, ctx, "Pass", "No Cloud SQL instance authorizes 0.0.0.0/0.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"instance authorizes 0.0.0.0/0: {name}",
                resource_type="cloudsql-instance",
                resource_id=name,
            )
            for name in offenders
        ]

    def sql_require_ssl(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No Cloud SQL instances in project.")
        offenders = []
        for instance in instances:
            ip_config = instance.get("settings", {}).get("ipConfiguration", {})
            if not ip_config.get("ipv4Enabled", False):
                continue  # private-IP-only instances are out of scope for TLS-on-public-IP
            enforced = bool(ip_config.get("requireSsl")) or ip_config.get("sslMode") in SSL_ENFORCING_MODES
            if not enforced:
                offenders.append(instance.get("name", "unknown"))
        if not offenders:
            return self.result(control, ctx, "Pass", "All public-IP Cloud SQL instances require TLS.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"TLS not required for connections: {name}",
                resource_type="cloudsql-instance",
                resource_id=name,
            )
            for name in offenders
        ]
