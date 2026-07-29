"""VPC/security-group network module checks."""

import tempfile
import unittest

from csaf.clouds.aws.modules.network import NetworkModule
from tests.fakes import FakeClient, make_control, make_ctx


class NetworkTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = NetworkModule()

    def ctx(self, pages):
        return make_ctx(self.tmp.name, clients={"ec2": FakeClient(pages=pages)}, region="us-east-1")


class TestSgAdminIngress(NetworkTestCase):
    def test_open_admin_port_flagged(self):
        groups = [
            {
                "GroupId": "sg-open",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            },
            {
                "GroupId": "sg-internal",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
                ],
            },
        ]
        results = self.module.sg_admin_ingress(
            make_control(), self.ctx({"describe_security_groups": [{"SecurityGroups": groups}]})
        )
        self.assertEqual([r.resource_id for r in results], ["sg-open"])
        self.assertEqual(results[0].status, "Fail")
        self.assertIn("3389", results[0].observed_value)

    def test_custom_baseline_ports_respected(self):
        groups = [
            {
                "GroupId": "sg-db",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ]
        ctx = make_ctx(
            self.tmp.name,
            clients={"ec2": FakeClient(pages={"describe_security_groups": [{"SecurityGroups": groups}]})},
            thresholds={"sensitiveIngressPorts": [5432]},
            region="us-east-1",
        )
        results = self.module.sg_admin_ingress(make_control(), ctx)
        self.assertEqual([r.resource_id for r in results], ["sg-db"])

    def test_clean_groups_pass(self):
        result = self.module.sg_admin_ingress(
            make_control(), self.ctx({"describe_security_groups": [{"SecurityGroups": []}]})
        )
        self.assertEqual(result.status, "Pass")


class TestDefaultSgRestricted(NetworkTestCase):
    def test_default_sg_with_rules_fails(self):
        def pages(kwargs):
            # The check filters on group-name=default; honour that filter.
            assert kwargs["Filters"] == [{"Name": "group-name", "Values": ["default"]}]
            return [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-def-rules",
                            "IpPermissions": [{"IpProtocol": "-1"}],
                            "IpPermissionsEgress": [],
                        },
                        {"GroupId": "sg-def-clean", "IpPermissions": [], "IpPermissionsEgress": []},
                    ]
                }
            ]

        results = self.module.default_sg_restricted(make_control(), self.ctx({"describe_security_groups": pages}))
        self.assertEqual([r.resource_id for r in results], ["sg-def-rules"])
        self.assertEqual(results[0].status, "Fail")

    def test_egress_rules_alone_also_fail(self):
        groups = [{"GroupId": "sg-def", "IpPermissions": [], "IpPermissionsEgress": [{"IpProtocol": "-1"}]}]
        results = self.module.default_sg_restricted(
            make_control(), self.ctx({"describe_security_groups": [{"SecurityGroups": groups}]})
        )
        self.assertEqual([r.status for r in results], ["Fail"])

    def test_empty_default_sgs_pass(self):
        groups = [{"GroupId": "sg-def", "IpPermissions": [], "IpPermissionsEgress": []}]
        result = self.module.default_sg_restricted(
            make_control(), self.ctx({"describe_security_groups": [{"SecurityGroups": groups}]})
        )
        self.assertEqual(result.status, "Pass")


class TestVpcFlowLogs(NetworkTestCase):
    def test_no_vpcs_is_not_applicable(self):
        ctx = self.ctx({"describe_vpcs": [{"Vpcs": []}], "describe_flow_logs": [{"FlowLogs": []}]})
        self.assertEqual(self.module.vpc_flow_logs(make_control(), ctx).status, "NotApplicable")

    def test_unlogged_vpc_flagged_inactive_flow_log_ignored(self):
        ctx = self.ctx(
            {
                "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-logged"}, {"VpcId": "vpc-dark"}]}],
                "describe_flow_logs": [
                    {
                        "FlowLogs": [
                            {"ResourceId": "vpc-logged", "FlowLogStatus": "ACTIVE"},
                            {"ResourceId": "vpc-dark", "FlowLogStatus": "INACTIVE"},
                        ]
                    }
                ],
            }
        )
        results = self.module.vpc_flow_logs(make_control(), ctx)
        self.assertEqual([r.resource_id for r in results], ["vpc-dark"])
        self.assertEqual(results[0].status, "Fail")

    def test_all_logged_passes(self):
        ctx = self.ctx(
            {
                "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-1"}]}],
                "describe_flow_logs": [{"FlowLogs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}]}],
            }
        )
        self.assertEqual(self.module.vpc_flow_logs(make_control(), ctx).status, "Pass")


if __name__ == "__main__":
    unittest.main()
