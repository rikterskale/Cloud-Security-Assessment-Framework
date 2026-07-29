"""NSG / Network Watcher module checks against faked ARM responses."""

import tempfile
import unittest

from csaf.clouds.azure.modules.network import NetworkModule
from tests.fakes import make_azure_ctx, make_control

NSGS = "/subscriptions/sub-1/providers/Microsoft.Network/networkSecurityGroups"
VNETS = "/subscriptions/sub-1/providers/Microsoft.Network/virtualNetworks"
WATCHERS = "/subscriptions/sub-1/providers/Microsoft.Network/networkWatchers"


def _rule(name, direction="Inbound", access="Allow", source_prefix="0.0.0.0/0", port_range="22"):
    return {
        "name": name,
        "properties": {
            "direction": direction,
            "access": access,
            "sourceAddressPrefix": source_prefix,
            "destinationPortRange": port_range,
        },
    }


class NetworkTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = NetworkModule()


class TestNsgAdminIngress(NetworkTestCase):
    def test_no_nsgs_passes(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: []})
        self.assertEqual(self.module.nsg_admin_ingress(make_control(), ctx).status, "Pass")

    def test_internet_ingress_to_admin_port_fails(self):
        nsgs = [{"name": "nsg-web", "properties": {"securityRules": [_rule("allow-ssh")]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        results = self.module.nsg_admin_ingress(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"nsg-web"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_outbound_rule_ignored(self):
        nsgs = [{"name": "nsg1", "properties": {"securityRules": [_rule("out", direction="Outbound")]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        self.assertEqual(self.module.nsg_admin_ingress(make_control(), ctx).status, "Pass")

    def test_deny_rule_ignored(self):
        nsgs = [{"name": "nsg1", "properties": {"securityRules": [_rule("deny", access="Deny")]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        self.assertEqual(self.module.nsg_admin_ingress(make_control(), ctx).status, "Pass")

    def test_non_internet_source_ignored(self):
        nsgs = [{"name": "nsg1", "properties": {"securityRules": [_rule("corp", source_prefix="10.0.0.0/8")]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        self.assertEqual(self.module.nsg_admin_ingress(make_control(), ctx).status, "Pass")

    def test_port_range_and_multiple_prefixes_covered(self):
        rule = {
            "name": "wide",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefixes": ["0.0.0.0/0"],
                "destinationPortRanges": ["20-25"],
            },
        }
        nsgs = [{"name": "nsg-wide", "properties": {"securityRules": [rule]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        results = self.module.nsg_admin_ingress(make_control(), ctx)
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_wildcard_port_star_covers_everything(self):
        rule = {
            "name": "wide-star",
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        }
        nsgs = [{"name": "nsg-star", "properties": {"securityRules": [rule]}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={NSGS: nsgs})
        results = self.module.nsg_admin_ingress(make_control(), ctx)
        self.assertTrue(all(r.status == "Fail" for r in results))


class TestNetworkWatcher(NetworkTestCase):
    def test_no_vnets_not_applicable(self):
        ctx = make_azure_ctx(self.tmp.name, get_value={VNETS: [], WATCHERS: []})
        self.assertEqual(self.module.network_watcher(make_control(), ctx).status, "NotApplicable")

    def test_watcher_covers_all_vnet_locations_passes(self):
        vnets = [{"location": "eastus"}]
        watchers = [{"location": "eastus", "properties": {"provisioningState": "Succeeded"}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={VNETS: vnets, WATCHERS: watchers})
        self.assertEqual(self.module.network_watcher(make_control(), ctx).status, "Pass")

    def test_missing_watcher_location_fails(self):
        vnets = [{"location": "eastus"}, {"location": "westus"}]
        watchers = [{"location": "eastus", "properties": {"provisioningState": "Succeeded"}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={VNETS: vnets, WATCHERS: watchers})
        results = self.module.network_watcher(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"westus"})
        self.assertTrue(all(r.status == "Fail" for r in results))

    def test_watcher_not_succeeded_state_ignored(self):
        vnets = [{"location": "eastus"}]
        watchers = [{"location": "eastus", "properties": {"provisioningState": "Disabled"}}]
        ctx = make_azure_ctx(self.tmp.name, get_value={VNETS: vnets, WATCHERS: watchers})
        results = self.module.network_watcher(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"eastus"})


if __name__ == "__main__":
    unittest.main()
