"""VPC network controls (project scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

GCE_V1 = "https://compute.googleapis.com/compute/v1"
ANYWHERE = {"0.0.0.0/0", "::/0"}


def _covers_port(allowed: list[dict], port: int) -> bool:
    for entry in allowed:
        protocol = entry.get("IPProtocol", "").lower()
        if protocol not in ("tcp", "all"):
            continue
        ports = entry.get("ports")
        if not ports:  # no ports field means every port for the protocol
            return True
        for value in ports:
            value = str(value)
            if "-" in value:
                low, _, high = value.partition("-")
                if low.isdigit() and high.isdigit() and int(low) <= port <= int(high):
                    return True
            elif value.isdigit() and int(value) == port:
                return True
    return False


class NetworkModule(AssessmentModule):
    name = "network"

    def open_admin_ports(self, control, ctx: CheckContext):
        firewalls = ctx.session.get_list(f"{GCE_V1}/projects/{ctx.account_id}/global/firewalls", "items")
        sensitive = [int(p) for p in ctx.baseline.get("sensitiveIngressPorts", [22, 3389])]
        offenders = []
        for rule in firewalls:
            if rule.get("direction", "INGRESS") != "INGRESS" or rule.get("disabled"):
                continue
            if not (set(rule.get("sourceRanges", [])) & ANYWHERE):
                continue
            exposed = sorted(p for p in sensitive if _covers_port(rule.get("allowed", []), p))
            if exposed:
                offenders.append((rule.get("name", "unknown"), exposed))
        if not offenders:
            return self.result(control, ctx, "Pass", "No firewall rule allows 0.0.0.0/0 ingress to admin ports.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{name} allows 0.0.0.0/0 ingress to ports {ports}",
                resource_type="firewall-rule",
                resource_id=name,
            )
            for name, ports in offenders
        ]

    def default_network(self, control, ctx: CheckContext):
        networks = ctx.session.get_list(f"{GCE_V1}/projects/{ctx.account_id}/global/networks", "items")
        default = [n for n in networks if n.get("name") == "default"]
        if not default:
            return self.result(control, ctx, "Pass", "No auto-created 'default' network exists in the project.")
        return self.result(
            control,
            ctx,
            "Fail",
            "The auto-created 'default' network exists with permissive default firewall rules.",
            resource_type="vpc-network",
            resource_id="default",
        )

    def subnet_flow_logs(self, control, ctx: CheckContext):
        subnets = ctx.session.get_aggregated(
            f"{GCE_V1}/projects/{ctx.account_id}/aggregated/subnetworks", "subnetworks"
        )
        evaluated = [s for s in subnets if s.get("purpose", "PRIVATE") == "PRIVATE"]
        if not evaluated:
            return self.result(control, ctx, "NotApplicable", "No standard VPC subnetworks in project.")
        offenders = [s.get("name", "unknown") for s in evaluated if not s.get("enableFlowLogs")]
        if not offenders:
            return self.result(control, ctx, "Pass", f"Flow logs enabled on all {len(evaluated)} subnetwork(s).")
        return [
            self.result(
                control, ctx, "Fail", f"flow logs disabled: {name}", resource_type="subnetwork", resource_id=name
            )
            for name in offenders
        ]
