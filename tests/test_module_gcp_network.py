"""VPC network module checks against faked GCP REST responses."""

import tempfile
import unittest

from csaf.clouds.gcp.modules.network import GCE_V1, NetworkModule
from tests.fakes import make_control, make_gcp_ctx

FIREWALLS_URL = f"{GCE_V1}/projects/proj-1/global/firewalls"
NETWORKS_URL = f"{GCE_V1}/projects/proj-1/global/networks"
SUBNETS_URL = f"{GCE_V1}/projects/proj-1/aggregated/subnetworks"


def firewall(name, allowed, source_ranges=("0.0.0.0/0",), direction="INGRESS", disabled=False):
    return {
        "name": name,
        "direction": direction,
        "disabled": disabled,
        "sourceRanges": list(source_ranges),
        "allowed": allowed,
    }


class NetworkTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = NetworkModule()


class TestOpenAdminPorts(NetworkTestCase):
    def test_no_offenders_passes(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: []})
        self.assertEqual(self.module.open_admin_ports(make_control(), ctx).status, "Pass")

    def test_open_ssh_port_flagged(self):
        rule = firewall("allow-ssh", allowed=[{"IPProtocol": "tcp", "ports": ["22"]}])
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        results = self.module.open_admin_ports(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"allow-ssh"})

    def test_no_ports_field_means_all_ports_open(self):
        rule = firewall("allow-all-tcp", allowed=[{"IPProtocol": "tcp"}])
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        results = self.module.open_admin_ports(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"allow-all-tcp"})

    def test_port_range_covers_target(self):
        rule = firewall("allow-range", allowed=[{"IPProtocol": "tcp", "ports": ["20-25"]}])
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        results = self.module.open_admin_ports(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"allow-range"})

    def test_disabled_rule_ignored(self):
        rule = firewall("disabled-rule", allowed=[{"IPProtocol": "tcp", "ports": ["22"]}], disabled=True)
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        self.assertEqual(self.module.open_admin_ports(make_control(), ctx).status, "Pass")

    def test_egress_rule_ignored(self):
        rule = firewall("egress-rule", allowed=[{"IPProtocol": "tcp", "ports": ["22"]}], direction="EGRESS")
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        self.assertEqual(self.module.open_admin_ports(make_control(), ctx).status, "Pass")

    def test_non_internet_source_ignored(self):
        rule = firewall("internal", allowed=[{"IPProtocol": "tcp", "ports": ["22"]}], source_ranges=["10.0.0.0/8"])
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        self.assertEqual(self.module.open_admin_ports(make_control(), ctx).status, "Pass")

    def test_udp_protocol_not_matched_to_admin_ports(self):
        rule = firewall("udp-rule", allowed=[{"IPProtocol": "udp", "ports": ["22"]}])
        ctx = make_gcp_ctx(self.tmp.name, get_list={FIREWALLS_URL: [rule]})
        self.assertEqual(self.module.open_admin_ports(make_control(), ctx).status, "Pass")


class TestDefaultNetwork(NetworkTestCase):
    def test_no_default_network_passes(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={NETWORKS_URL: [{"name": "custom-vpc"}]})
        self.assertEqual(self.module.default_network(make_control(), ctx).status, "Pass")

    def test_default_network_exists_fails(self):
        ctx = make_gcp_ctx(self.tmp.name, get_list={NETWORKS_URL: [{"name": "default"}]})
        result = self.module.default_network(make_control(), ctx)
        self.assertEqual(result.status, "Fail")
        self.assertEqual(result.resource_id, "default")


class TestSubnetFlowLogs(NetworkTestCase):
    def test_no_private_subnets_not_applicable(self):
        ctx = make_gcp_ctx(self.tmp.name, get_aggregated={SUBNETS_URL: []})
        self.assertEqual(self.module.subnet_flow_logs(make_control(), ctx).status, "NotApplicable")

    def test_flow_logs_enabled_passes(self):
        subnet = {"name": "subnet1", "purpose": "PRIVATE", "enableFlowLogs": True}
        ctx = make_gcp_ctx(self.tmp.name, get_aggregated={SUBNETS_URL: [subnet]})
        self.assertEqual(self.module.subnet_flow_logs(make_control(), ctx).status, "Pass")

    def test_flow_logs_disabled_fails(self):
        subnet = {"name": "subnet1", "purpose": "PRIVATE", "enableFlowLogs": False}
        ctx = make_gcp_ctx(self.tmp.name, get_aggregated={SUBNETS_URL: [subnet]})
        results = self.module.subnet_flow_logs(make_control(), ctx)
        self.assertEqual({r.resource_id for r in results}, {"subnet1"})

    def test_non_private_purpose_subnet_excluded(self):
        subnet = {"name": "proxy-only", "purpose": "REGIONAL_MANAGED_PROXY", "enableFlowLogs": False}
        ctx = make_gcp_ctx(self.tmp.name, get_aggregated={SUBNETS_URL: [subnet]})
        self.assertEqual(self.module.subnet_flow_logs(make_control(), ctx).status, "NotApplicable")


if __name__ == "__main__":
    unittest.main()
