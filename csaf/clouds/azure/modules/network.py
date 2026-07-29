"""Network security group and Network Watcher controls (subscription scope)."""

from __future__ import annotations

from ...base import AssessmentModule, CheckContext

API_NETWORK = "2023-09-01"
INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any", "::/0"}


def _sources(props: dict) -> list[str]:
    values = list(props.get("sourceAddressPrefixes") or [])
    if props.get("sourceAddressPrefix"):
        values.append(props["sourceAddressPrefix"])
    return [str(v).lower() for v in values]


def _port_ranges(props: dict) -> list[str]:
    values = list(props.get("destinationPortRanges") or [])
    if props.get("destinationPortRange"):
        values.append(props["destinationPortRange"])
    return [str(v) for v in values]


def _covers_port(ranges: list[str], port: int) -> bool:
    for value in ranges:
        if value == "*":
            return True
        if "-" in value:
            low, _, high = value.partition("-")
            if low.strip().isdigit() and high.strip().isdigit() and int(low) <= port <= int(high):
                return True
        elif value.strip().isdigit() and int(value) == port:
            return True
    return False


class NetworkModule(AssessmentModule):
    name = "network"

    def nsg_admin_ingress(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        nsgs = arm.get_value(f"{sub}/providers/Microsoft.Network/networkSecurityGroups", API_NETWORK)
        sensitive = [int(p) for p in ctx.baseline.get("sensitiveIngressPorts", [22, 3389])]
        offenders = []
        for nsg in nsgs:
            for rule in nsg.get("properties", {}).get("securityRules", []):
                props = rule.get("properties", {})
                if props.get("direction") != "Inbound" or props.get("access") != "Allow":
                    continue
                if not (set(_sources(props)) & INTERNET_SOURCES):
                    continue
                ranges = _port_ranges(props)
                exposed = sorted(p for p in sensitive if _covers_port(ranges, p))
                if exposed:
                    offenders.append((nsg.get("name", "unknown"), rule.get("name", "unknown"), exposed))
        if not offenders:
            return self.result(control, ctx, "Pass", "No NSG allows internet ingress to sensitive admin ports.")
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"{nsg}/{rule} allows internet ingress to ports {ports}",
                resource_type="network-security-group",
                resource_id=nsg,
            )
            for nsg, rule, ports in offenders
        ]

    def network_watcher(self, control, ctx: CheckContext):
        arm = ctx.session
        sub = f"/subscriptions/{ctx.account_id}"
        vnets = arm.get_value(f"{sub}/providers/Microsoft.Network/virtualNetworks", API_NETWORK)
        if not vnets:
            return self.result(control, ctx, "NotApplicable", "No virtual networks in subscription.")
        used_locations = {v.get("location", "").lower() for v in vnets if v.get("location")}
        watchers = arm.get_value(f"{sub}/providers/Microsoft.Network/networkWatchers", API_NETWORK)
        enabled_locations = {
            w.get("location", "").lower()
            for w in watchers
            if w.get("properties", {}).get("provisioningState") == "Succeeded"
        }
        missing = sorted(used_locations - enabled_locations)
        if not missing:
            return self.result(
                control, ctx, "Pass", f"Network Watcher enabled in all VNet locations: {sorted(used_locations)}."
            )
        return [
            self.result(
                control,
                ctx,
                "Fail",
                f"no Network Watcher in location with VNets: {location}",
                resource_type="location",
                resource_id=location,
            )
            for location in missing
        ]
