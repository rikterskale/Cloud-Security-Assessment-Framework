"""Azure SQL server controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_SQL = "2021-11-01"


class SqlModule(AssessmentModule):
    name = "sql"

    def _servers(self, ctx: CheckContext) -> list[dict]:
        if "sql_servers" not in ctx.cache:
            sub = f"/subscriptions/{ctx.account_id}"
            ctx.cache["sql_servers"] = ctx.session.get_value(f"{sub}/providers/Microsoft.Sql/servers", API_SQL)
        return ctx.cache["sql_servers"]

    def sql_auditing(self, control, ctx: CheckContext):
        servers = self._servers(ctx)
        if not servers:
            return self.result(control, ctx, "NotApplicable", "No Azure SQL servers in subscription.")
        offenders = []
        for server in servers:
            auditing = ctx.session.get(f"{server['id']}/auditingSettings/default", API_SQL)
            if auditing.get("properties", {}).get("state") != "Enabled":
                offenders.append(server.get("name", "unknown"))
        if not offenders:
            return self.result(control, ctx, "Pass", f"Auditing enabled on all {len(servers)} SQL server(s).")
        return [
            self.result(
                control, ctx, "Fail", f"auditing disabled: {name}", resource_type="sql-server", resource_id=name
            )
            for name in offenders
        ]

    def sql_public_network_access(self, control, ctx: CheckContext):
        servers = self._servers(ctx)
        if not servers:
            return self.result(control, ctx, "NotApplicable", "No Azure SQL servers in subscription.")
        offenders = [
            s.get("name", "unknown")
            for s in servers
            if s.get("properties", {}).get("publicNetworkAccess", "Enabled") != "Disabled"
        ]
        if not offenders:
            return self.result(control, ctx, "Pass", "Public network access disabled on all SQL servers.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"public network access enabled: {name}",
                resource_type="sql-server",
                resource_id=name,
            )
            for name in offenders
        ]
