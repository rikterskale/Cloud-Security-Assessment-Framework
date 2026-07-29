"""EC2/compute module checks and the shared security-group helpers."""

import tempfile
import unittest

from csaf.clouds.aws.modules.compute import ComputeModule, _covered_ports, _has_public_cidr
from tests.fakes import FakeClient, make_control, make_ctx


class TestSecurityGroupHelpers(unittest.TestCase):
    def test_has_public_cidr(self):
        cases = [
            ({"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, True),
            ({"Ipv6Ranges": [{"CidrIpv6": "::/0"}]}, True),
            ({"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}, False),
            ({"IpRanges": [], "Ipv6Ranges": []}, False),
            ({}, False),
        ]
        for perm, expected in cases:
            self.assertEqual(_has_public_cidr(perm), expected, perm)

    def test_covered_ports(self):
        sensitive = {22, 3389}
        cases = [
            ({"IpProtocol": "-1"}, {22, 3389}),  # all-traffic rule covers everything
            ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}, {22}),
            ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}, {22, 3389}),
            ({"IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000}, {3389}),
            ({"IpProtocol": "tcp", "FromPort": 80, "ToPort": 443}, set()),
            ({"IpProtocol": "tcp"}, set()),  # missing port bounds -> nothing covered
        ]
        for perm, expected in cases:
            self.assertEqual(_covered_ports(perm, sensitive), expected, perm)


def instance(instance_id, state="running", tokens="required", public_ip=None, groups=()):
    inst = {
        "InstanceId": instance_id,
        "State": {"Name": state},
        "MetadataOptions": {"HttpTokens": tokens},
        "SecurityGroups": [{"GroupId": g} for g in groups],
    }
    if public_ip:
        inst["PublicIpAddress"] = public_ip
    return inst


def ec2_client(instances=(), security_groups=(), ebs_default=None):
    responses = {}
    if ebs_default is not None:
        responses["get_ebs_encryption_by_default"] = {"EbsEncryptionByDefault": ebs_default}
    return FakeClient(
        responses=responses,
        pages={
            "describe_instances": [{"Reservations": [{"Instances": list(instances)}]}],
            "describe_security_groups": [{"SecurityGroups": list(security_groups)}],
        },
    )


class ComputeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = ComputeModule()

    def ctx(self, client):
        return make_ctx(self.tmp.name, clients={"ec2": client}, region="us-east-1")


class TestImdsV2(ComputeTestCase):
    def test_no_running_instances_is_not_applicable(self):
        ctx = self.ctx(ec2_client(instances=[instance("i-1", state="terminated", tokens="optional")]))
        self.assertEqual(self.module.imdsv2_required(make_control(), ctx).status, "NotApplicable")

    def test_offender_flagged_terminated_skipped(self):
        ctx = self.ctx(
            ec2_client(
                instances=[
                    instance("i-good"),
                    instance("i-bad", tokens="optional"),
                    instance("i-gone", state="shutting-down", tokens="optional"),
                ]
            )
        )
        results = self.module.imdsv2_required(make_control(), ctx)
        self.assertEqual([r.resource_id for r in results], ["i-bad"])
        self.assertEqual(results[0].status, "Fail")

    def test_all_enforced_passes(self):
        ctx = self.ctx(ec2_client(instances=[instance("i-1"), instance("i-2")]))
        self.assertEqual(self.module.imdsv2_required(make_control(), ctx).status, "Pass")


class TestEbsDefaultEncryption(ComputeTestCase):
    def test_enabled_passes_disabled_fails(self):
        self.assertEqual(
            self.module.ebs_default_encryption(make_control(), self.ctx(ec2_client(ebs_default=True))).status, "Pass"
        )
        self.assertEqual(
            self.module.ebs_default_encryption(make_control(), self.ctx(ec2_client(ebs_default=False))).status, "Fail"
        )


class TestPublicInstanceExposure(ComputeTestCase):
    OPEN_SG = {
        "GroupId": "sg-open",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }
    CLOSED_SG = {
        "GroupId": "sg-closed",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
    }

    def test_public_instance_with_open_sg_fails(self):
        ctx = self.ctx(
            ec2_client(
                instances=[instance("i-exposed", public_ip="203.0.113.5", groups=["sg-open"])],
                security_groups=[self.OPEN_SG, self.CLOSED_SG],
            )
        )
        results = self.module.public_instance_exposure(make_control(), ctx)
        self.assertEqual([r.resource_id for r in results], ["i-exposed"])
        self.assertIn("22", results[0].observed_value)

    def test_private_instance_and_closed_sg_pass(self):
        ctx = self.ctx(
            ec2_client(
                instances=[
                    instance("i-private", groups=["sg-open"]),  # open SG but no public IP
                    instance("i-guarded", public_ip="203.0.113.9", groups=["sg-closed"]),
                ],
                security_groups=[self.OPEN_SG, self.CLOSED_SG],
            )
        )
        self.assertEqual(self.module.public_instance_exposure(make_control(), ctx).status, "Pass")

    def test_instance_inventory_cached_per_region(self):
        client = ec2_client(instances=[instance("i-1")], ebs_default=True)
        ctx = self.ctx(client)
        self.module.imdsv2_required(make_control(), ctx)
        self.module.public_instance_exposure(make_control(), ctx)
        describe_calls = [name for name, _ in client.calls if name == "describe_instances"]
        self.assertEqual(len(describe_calls), 1, "instance inventory should be collected once per region context")
        self.assertIn("ec2_instances_us-east-1", ctx.cache)


if __name__ == "__main__":
    unittest.main()
