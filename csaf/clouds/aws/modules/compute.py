"""EC2 / compute controls (per-region scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext


class ComputeModule(AssessmentModule):
    name = "compute"

    def _instances(self, ctx: CheckContext) -> list[dict]:
        key = f"ec2_instances_{ctx.region}"
        if key in ctx.cache:
            return ctx.cache[key]
        ec2 = ctx.session.client("ec2", ctx.region)
        instances = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        ctx.cache[key] = instances
        return instances

    def imdsv2_required(self, control, ctx: CheckContext):
        offenders = []
        running = 0
        for inst in self._instances(ctx):
            if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                continue
            running += 1
            options = inst.get("MetadataOptions", {})
            if options.get("HttpTokens") != "required":
                offenders.append(inst.get("InstanceId"))
        if running == 0:
            return self.result(control, ctx, "NotApplicable", "No running instances in region.")
        if not offenders:
            return self.result(control, ctx, "Pass", "All running instances require IMDSv2.")
        return [
            self.result(
                control, ctx, "Fail", f"IMDSv2 not required: {iid}", resource_type="ec2-instance", resource_id=iid
            )
            for iid in offenders
        ]

    def ebs_default_encryption(self, control, ctx: CheckContext):
        ec2 = ctx.session.client("ec2", ctx.region)
        enabled = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
        status = "Pass" if enabled else "Fail"
        return self.result(
            control,
            ctx,
            status,
            f"EBS encryption-by-default={enabled}",
            resource_type="ec2-region",
            resource_id=ctx.region,
        )

    def public_instance_exposure(self, control, ctx: CheckContext):
        ec2 = ctx.session.client("ec2", ctx.region)
        ports = set(ctx.baseline.get("sensitiveIngressPorts", [22, 3389]))
        # Build map of security-group id -> open sensitive ports from 0.0.0.0/0.
        sg_open: dict[str, set[int]] = {}
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page.get("SecurityGroups", []):
                open_ports = set()
                for perm in sg.get("IpPermissions", []):
                    if not _has_public_cidr(perm):
                        continue
                    for port in _covered_ports(perm, ports):
                        open_ports.add(port)
                if open_ports:
                    sg_open[sg["GroupId"]] = open_ports
        offenders = []
        for inst in self._instances(ctx):
            if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                continue
            if not inst.get("PublicIpAddress"):
                continue
            exposed = set()
            for sg in inst.get("SecurityGroups", []):
                exposed |= sg_open.get(sg.get("GroupId"), set())
            if exposed:
                offenders.append((inst.get("InstanceId"), sorted(exposed)))
        if not offenders:
            return self.result(control, ctx, "Pass", "No public instances exposed on sensitive ports.")
        return [
            self.result(
                control, ctx, "Fail", f"{iid} public on ports {p}", resource_type="ec2-instance", resource_id=iid
            )
            for iid, p in offenders
        ]


def _has_public_cidr(perm: dict) -> bool:
    for rng in perm.get("IpRanges", []):
        if rng.get("CidrIp") == "0.0.0.0/0":
            return True
    for rng in perm.get("Ipv6Ranges", []):
        if rng.get("CidrIpv6") == "::/0":
            return True
    return False


def _covered_ports(perm: dict, ports: set[int]) -> set[int]:
    if perm.get("IpProtocol") == "-1":
        return set(ports)
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return set()
    return {p for p in ports if from_port <= p <= to_port}
