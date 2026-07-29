"""Compute Engine instance controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

GCE_V1 = "https://compute.googleapis.com/compute/v1"
DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"


def _metadata_value(metadata: dict, key: str) -> str | None:
    for item in metadata.get("items", []) or []:
        if item.get("key") == key:
            return str(item.get("value", ""))
    return None


class ComputeModule(AssessmentModule):
    name = "compute"

    def _instances(self, ctx: CheckContext) -> list[dict]:
        if "gce_instances" not in ctx.cache:
            ctx.cache["gce_instances"] = ctx.session.get_aggregated(
                f"{GCE_V1}/projects/{ctx.account_id}/aggregated/instances", "instances"
            )
        return ctx.cache["gce_instances"]

    def _project(self, ctx: CheckContext) -> dict:
        if "gce_project" not in ctx.cache:
            ctx.cache["gce_project"] = ctx.session.get(f"{GCE_V1}/projects/{ctx.account_id}")
        return ctx.cache["gce_project"]

    def default_service_account(self, control, ctx: CheckContext):
        # GKE nodes legitimately run on managed instance templates and are exempt per CIS.
        instances = [i for i in self._instances(ctx) if not i.get("name", "").startswith("gke-")]
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No non-GKE compute instances in project.")
        offenders = [
            i.get("name", "unknown")
            for i in instances
            if any(sa.get("email", "").endswith(DEFAULT_COMPUTE_SA_SUFFIX) for sa in i.get("serviceAccounts", []))
        ]
        if not offenders:
            return self.result(control, ctx, "Pass", "No instance runs as the default Compute Engine service account.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"instance uses the default compute service account: {name}",
                resource_type="gce-instance",
                resource_id=name,
            )
            for name in offenders
        ]

    def public_ip_instances(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No compute instances in project.")
        offenders = []
        for instance in instances:
            for nic in instance.get("networkInterfaces", []):
                if any(cfg.get("natIP") for cfg in nic.get("accessConfigs", []) or []):
                    offenders.append(instance.get("name", "unknown"))
                    break
        if not offenders:
            return self.result(control, ctx, "Pass", "No compute instance has an external IP address.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"instance has an external IP: {name}",
                resource_type="gce-instance",
                resource_id=name,
            )
            for name in offenders
        ]

    def os_login(self, control, ctx: CheckContext):
        project = self._project(ctx)
        project_enabled = str(
            _metadata_value(project.get("commonInstanceMetadata", {}), "enable-oslogin") or ""
        ).lower() in ("true", "1", "y", "yes")
        if not project_enabled:
            return self.result(
                control, ctx, "Fail", "Project metadata does not set enable-oslogin=TRUE.", resource_type="project"
            )
        overrides = [
            i.get("name", "unknown")
            for i in self._instances(ctx)
            if str(_metadata_value(i.get("metadata", {}), "enable-oslogin") or "").lower() in ("false", "0", "n", "no")
        ]
        if not overrides:
            return self.result(control, ctx, "Pass", "OS Login enabled at project level with no instance overrides.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"instance overrides OS Login to disabled: {name}",
                resource_type="gce-instance",
                resource_id=name,
            )
            for name in overrides
        ]

    def serial_ports_disabled(self, control, ctx: CheckContext):
        instances = self._instances(ctx)
        if not instances:
            return self.result(control, ctx, "NotApplicable", "No compute instances in project.")
        offenders = [
            i.get("name", "unknown")
            for i in instances
            if str(_metadata_value(i.get("metadata", {}), "serial-port-enable") or "").lower() in ("true", "1")
        ]
        if not offenders:
            return self.result(control, ctx, "Pass", "No instance enables interactive serial-port access.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"serial port access enabled: {name}",
                resource_type="gce-instance",
                resource_id=name,
            )
            for name in offenders
        ]
