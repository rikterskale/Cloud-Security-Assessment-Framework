"""VPC / security-group network controls (per-region scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext
from .compute import _covered_ports, _has_public_cidr


class NetworkModule(AssessmentModule):
    name = "network"

    def sg_admin_ingress(self, control, ctx: CheckContext):
        ec2 = ctx.session.client("ec2", ctx.region)
        ports = set(ctx.baseline.get("sensitiveIngressPorts", [22, 3389]))
        offenders = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                open_ports = set()
                for perm in sg.get("IpPermissions", []):
                    if _has_public_cidr(perm):
                        open_ports |= _covered_ports(perm, ports)
                if open_ports:
                    offenders.append((sg["GroupId"], sorted(open_ports)))
        if not offenders:
            return self.result(control, ctx, "Pass", "No security group opens admin ports to the internet.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{gid} opens ports {p} to 0.0.0.0/0",
                resource_type="security-group",
                resource_id=gid,
            )
            for gid, p in offenders
        ]

    def default_sg_restricted(self, control, ctx: CheckContext):
        ec2 = ctx.session.client("ec2", ctx.region)
        offenders = []
        for page in ec2.get_paginator("describe_security_groups").paginate(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        ):
            for sg in page.get("SecurityGroups", []):
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    offenders.append(sg["GroupId"])
        if not offenders:
            return self.result(control, ctx, "Pass", "Default security groups have no rules.")
        return [
            self.result(
                control, ctx, "Fail", f"default SG has rules: {gid}", resource_type="security-group", resource_id=gid
            )
            for gid in offenders
        ]

    def vpc_flow_logs(self, control, ctx: CheckContext):
        ec2 = ctx.session.client("ec2", ctx.region)
        vpcs = [v["VpcId"] for page in ec2.get_paginator("describe_vpcs").paginate() for v in page.get("Vpcs", [])]
        if not vpcs:
            return self.result(control, ctx, "NotApplicable", "No VPCs in region.")
        logged = set()
        for page in ec2.get_paginator("describe_flow_logs").paginate():
            for fl in page.get("FlowLogs", []):
                if fl.get("FlowLogStatus") == "ACTIVE":
                    logged.add(fl.get("ResourceId"))
        offenders = [v for v in vpcs if v not in logged]
        if not offenders:
            return self.result(control, ctx, "Pass", f"All {len(vpcs)} VPCs have active flow logs.")
        return [
            self.result(control, ctx, "Fail", f"no active flow log: {vid}", resource_type="vpc", resource_id=vid)
            for vid in offenders
        ]
